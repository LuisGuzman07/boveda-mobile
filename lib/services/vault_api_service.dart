import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'vault_crypto_service.dart';

class VaultApiException implements Exception {
  final String message;
  VaultApiException(this.message);
  @override
  String toString() => message;
}

class VaultApiService {
  static const configuredUrl = String.fromEnvironment('BOVEDA_API_URL');
  final FlutterSecureStorage storage;
  final String baseUrl;
  String? _token;
  String? _deviceId;
  String? _userId;
  SimpleKeyPair? _signingKey;

  VaultApiService({FlutterSecureStorage? storage, String? baseUrl})
      : storage = storage ??
            const FlutterSecureStorage(
                aOptions: AndroidOptions(encryptedSharedPreferences: true)),
        baseUrl = baseUrl ??
            (configuredUrl.isNotEmpty
                ? configuredUrl
                : (!kIsWeb && Platform.isAndroid
                    ? 'http://localhost:8000/api/v1'
                    : 'http://localhost:8000/api/v1'));

  bool get authenticated => _token != null;
  String get deviceId => _deviceId!;

  Future<Map<String, dynamic>> _request(String method, String path,
      {Map<String, dynamic>? body,
      String? token,
      String? retryKey,
      bool signed = false,
      String? deviceHeader}) async {
    final uri = Uri.parse('$baseUrl$path');
    final text = body == null ? '' : jsonEncode(body);
    final headers = <String, String>{'Content-Type': 'application/json'};
    if (token != null) headers['Authorization'] = 'Bearer $token';
    if (deviceHeader != null) headers['X-Device-Id'] = deviceHeader;
    if (retryKey != null) headers['Idempotency-Key'] = retryKey;
    if (signed) {
      if (_token == null || _signingKey == null) {
        throw VaultApiException('Inicia sesión nuevamente.');
      }
      headers['Authorization'] = 'Bearer $_token';
      final payload = jsonDecode(utf8.decode(
          base64Url.decode(base64Url.normalize(_token!.split('.')[1])))) as Map;
      final timestamp =
          (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
      final digest = hashes.sha256.convert(utf8.encode(text)).toString();
      final message = [
        payload['jti'],
        timestamp,
        method,
        uri.path,
        retryKey ?? '',
        digest
      ].join('\n');
      final signature =
          await Ed25519().sign(utf8.encode(message), keyPair: _signingKey!);
      headers['X-Vault-Timestamp'] = timestamp;
      headers['X-Vault-Signature'] = base64Encode(signature.bytes);
    }
    final client = http.Client();
    try {
      final request = http.Request(method, uri)
        ..headers.addAll(headers)
        ..body = text;
      final response = await http.Response.fromStream(
              await client.send(request).timeout(const Duration(seconds: 20)))
          .timeout(const Duration(seconds: 20));
      final data = jsonDecode(response.body);
      if (response.statusCode >= 400) {
        if (signed && response.statusCode == 401) logout();
        final detail = data is Map ? data['detail'] : null;
        throw VaultApiException(detail is String
            ? detail
            : 'Solicitud rechazada (${response.statusCode}).');
      }
      return Map<String, dynamic>.from(data as Map);
    } on SocketException {
      throw VaultApiException(
          'No se pudo conectar con el backend. Verifica Docker y la URL.');
    } finally {
      client.close();
    }
  }

  Future<void> login(String email, String password, String code) async {
    if (kIsWeb) {
      throw VaultApiException(
          'CU-06 requiere Android o escritorio con almacenamiento seguro; usa la web React para administrar.');
    }
    logout();
    final account = email.trim().toLowerCase();
    final scope = hashes.sha256.convert(utf8.encode(account)).toString();
    var identifier = await storage.read(key: 'cu06_device_id');
    if (identifier == null) {
      identifier = VaultCryptoService.newId();
      await storage.write(key: 'cu06_device_id', value: identifier);
    }
    var seed = await storage.read(key: 'cu06_signing_$scope');
    if (seed == null) {
      seed = base64Encode(VaultCryptoService.randomBytes(32));
      await storage.write(key: 'cu06_signing_$scope', value: seed);
    }
    final signingKey = await Ed25519().newKeyPairFromSeed(base64Decode(seed));
    final publicKey = base64Encode((await signingKey.extractPublicKey()).bytes);
    final device = {
      'nombre': 'Bóveda móvil',
      'tipo': 'MOVIL',
      'sistema_operativo': Platform.operatingSystem,
      'identificador_seguro': identifier,
      'public_key': publicKey,
      'confiar_dispositivo': true
    };
    var auth = await _request('POST', '/auth/login', body: {
      'correo': account,
      'password': password,
      'dispositivo': device,
      'confiar_dispositivo': true
    });
    if (auth['mfa_required'] != true) {
      throw VaultApiException(
          'Activa MFA TOTP desde la web antes de crear bóvedas.');
    }
    auth = await _request('POST', '/auth/mfa/verify-login', body: {
      'mfa_token': auth['mfa_token'],
      'code': code.trim(),
      'dispositivo': device,
      'confiar_dispositivo': true
    });
    final authToken = auth['access_token'] as String;
    final devices = await _request('GET', '/devices',
        token: authToken, deviceHeader: identifier);
    final currentDevice = (devices['dispositivos'] as List)
        .map((item) => Map<String, dynamic>.from(item as Map))
        .firstWhere((item) => item['es_dispositivo_actual'] == true);

    Future<Map<String, dynamic>> signChallenge(String purpose) async {
      final issued = await _request('POST', '/devices/challenge',
          token: authToken,
          deviceHeader: identifier,
          body: {'proposito': purpose});
      final expires = DateTime.parse(issued['fecha_expiracion'] as String)
              .toUtc()
              .millisecondsSinceEpoch ~/
          1000;
      final transcript = [
        'boveda-device-challenge-v1',
        issued['id_desafio'],
        purpose,
        currentDevice['id_usuario'],
        currentDevice['id_dispositivo'],
        issued['nonce'],
        expires.toString(),
      ].join('\n');
      final signature =
          await Ed25519().sign(utf8.encode(transcript), keyPair: signingKey);
      return {...issued, 'firma': base64Encode(signature.bytes)};
    }

    final enrollment = await signChallenge('DEVICE_ENROLLMENT');
    await _request('POST', '/devices/challenge/prove',
        token: authToken,
        deviceHeader: identifier,
        body: {
          'id_desafio': enrollment['id_desafio'],
          'nonce': enrollment['nonce'],
          'firma': enrollment['firma'],
        });
    final challenge = await signChallenge('VAULT_SESSION');
    final session = await _request('POST', '/vaults/session',
        token: authToken,
        deviceHeader: identifier,
        body: {
          'id_desafio': challenge['id_desafio'],
          'nonce': challenge['nonce'],
          'firma': challenge['firma'],
        });
    _token = session['access_token'] as String;
    _deviceId = session['id_dispositivo'] as String;
    _userId = session['id_usuario'] as String;
    _signingKey = signingKey;
  }

  Future<Uint8List> deviceKey() async {
    final storageKey = 'cu06_wrapping_$_userId';
    var encoded = await storage.read(key: storageKey);
    if (encoded == null) {
      encoded = base64Encode(VaultCryptoService.randomBytes(32));
      await storage.write(key: storageKey, value: encoded);
    }
    return base64Decode(encoded);
  }

  Future<List<Map<String, dynamic>>> listVaults() async {
    final data = await _request('GET', '/vaults', signed: true);
    return (data['items'] as List)
        .map((item) => Map<String, dynamic>.from(item as Map))
        .toList();
  }

  Future<Map<String, dynamic>> getVault(String id) =>
      _request('GET', '/vaults/$id', signed: true);

  Future<Map<String, dynamic>> createEmergencyKit(
          String vaultId, Map<String, dynamic> body) =>
      _request('POST', '/vaults/$vaultId/emergency-kit', body: body, signed: true);

  Future<Map<String, dynamic>> recoverEmergencyKit(
          String vaultId, Map<String, dynamic> body) =>
      _request('POST', '/vaults/$vaultId/emergency-kit/recover', body: body, signed: true);

  Future<Map<String, dynamic>> revokeEmergencyKit(String vaultId) =>
      _request('POST', '/vaults/$vaultId/emergency-kit/revoke', signed: true);

  Future<Map<String, dynamic>> listVaultFiles(String id,
          {int page = 1, int pageSize = 25}) =>
      _request('GET', '/vaults/$id/files?page=$page&page_size=$pageSize',
          signed: true);

  Future<Map<String, dynamic>> downloadFile(String vaultId, String versionId) =>
      _request('GET', '/vaults/$vaultId/files/$versionId/download', signed: true);

  Future<Map<String, dynamic>> deleteFile(
          String vaultId, String fileId, String retryKey) =>
      _request('DELETE', '/vaults/$vaultId/files/$fileId',
          body: const {}, retryKey: retryKey, signed: true);
  Future<Map<String, dynamic>> createVault(
          Map<String, dynamic> body, String retryKey) =>
      _request('POST', '/vaults', body: body, retryKey: retryKey, signed: true);

  Future<Map<String, dynamic>> uploadEncryptedFile(
      String vaultId, Map<String, dynamic> body, String retryKey) =>
      _request('POST', '/vaults/$vaultId/files',
          body: body, retryKey: retryKey, signed: true);

  Future<Map<String, dynamic>?> pendingCreation() async {
    final encoded = await storage.read(key: 'cu06_pending_$_userId');
    return encoded == null
        ? null
        : Map<String, dynamic>.from(jsonDecode(encoded) as Map);
  }

  Future<void> savePending(Map<String, dynamic> body, String retryKey) =>
      storage.write(
          key: 'cu06_pending_$_userId',
          value: jsonEncode({'body': body, 'retry_key': retryKey}));
  Future<void> clearPending() => storage.delete(key: 'cu06_pending_$_userId');

  void logout() {
    _token = null;
    _deviceId = null;
    _userId = null;
    _signingKey?.destroy();
    _signingKey = null;
  }
}
