import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';
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
        baseUrl = AppConfig.resolveApiUrl(
          configuredUrl:
              baseUrl ?? (configuredUrl.isNotEmpty ? configuredUrl : null),
          port: 8001,
        );

  bool get authenticated => _token != null;
  String get deviceId => _deviceId!;

  Future<Map<String, dynamic>> _request(String method, String path,
      {Map<String, dynamic>? body,
      String? token,
      String? retryKey,
      bool signed = false}) async {
    final uri = Uri.parse('$baseUrl$path');
    final text = body == null ? '' : jsonEncode(body);
    final headers = <String, String>{'Content-Type': 'application/json'};
    if (token != null) headers['Authorization'] = 'Bearer $token';
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
    final session = await _request('POST', '/vaults/session',
        token: auth['access_token'] as String,
        body: {
          'refresh_token': auth['refresh_token'],
          'code': code.trim(),
          'public_key': publicKey
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
  Future<Map<String, dynamic>> createVault(
          Map<String, dynamic> body, String retryKey) =>
      _request('POST', '/vaults', body: body, retryKey: retryKey, signed: true);

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
