import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';
import 'app_lock_service.dart';
import 'device_identity_api_service.dart';
import 'installation_identity_service.dart';
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
  AppLockService? _lockService;
  final http.Client? _client;
  final DeviceIdentityApiService _deviceIdentity;

  VaultApiService({
    FlutterSecureStorage? storage,
    String? baseUrl,
    AppLockService? lockService,
    DeviceIdentityApiService? deviceIdentityApi,
    InstallationIdentityProvider? installationIdentity,
    http.Client? client,
  })  : storage = storage ??
            const FlutterSecureStorage(
                aOptions: AndroidOptions(encryptedSharedPreferences: true)),
        _lockService = lockService,
        _client = client,
        baseUrl = _resolveBaseUrl(baseUrl),
        _deviceIdentity = deviceIdentityApi ??
            DeviceIdentityApiService(
              identity: installationIdentity,
              lockService: lockService,
              client: client,
              baseUrl: _resolveBaseUrl(baseUrl),
            ) {
    if (lockService != null) {
      _deviceIdentity.attachLockService(lockService);
    }
  }

  static String _resolveBaseUrl(String? baseUrl) => AppConfig.resolveApiUrl(
        configuredUrl:
            baseUrl ?? (configuredUrl.isNotEmpty ? configuredUrl : null),
        port: 8000,
      );

  bool get authenticated => _token != null && _allowsSensitiveActions;
  String get deviceId {
    _ensureUnlocked();
    final identifier = _deviceId;
    if (identifier == null) {
      throw VaultApiException('Inicia sesión nuevamente.');
    }
    return identifier;
  }

  void attachLockService(AppLockService lockService) {
    _lockService = lockService;
    _deviceIdentity.attachLockService(lockService);
  }

  Future<Map<String, dynamic>> _request(String method, String path,
      {Map<String, dynamic>? body,
      String? token,
      String? retryKey,
      bool signed = false,
      Map<String, String>? extraHeaders}) async {
    _ensureUnlocked();
    final uri = Uri.parse('$baseUrl$path');
    final text = body == null ? '' : jsonEncode(body);
    final headers = <String, String>{'Content-Type': 'application/json'};
    if (token != null) headers['Authorization'] = 'Bearer $token';
    if (retryKey != null) headers['Idempotency-Key'] = retryKey;
    if (extraHeaders != null) headers.addAll(extraHeaders);
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
    final client = _client ?? http.Client();
    try {
      final request = http.Request(method, uri)
        ..headers.addAll(headers)
        ..body = text;
      final response = await http.Response.fromStream(
              await client.send(request).timeout(const Duration(seconds: 20)))
          .timeout(const Duration(seconds: 20));
      _ensureUnlocked();
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
      if (_client == null) {
        client.close();
      }
    }
  }

  Future<void> login(String email, String password, String code) async {
    _ensureUnlocked();
    if (kIsWeb) {
      throw VaultApiException(
          'CU-06 requiere Android o escritorio con almacenamiento seguro; usa la web React para administrar.');
    }
    logout();
    final account = email.trim().toLowerCase();
    final scope = hashes.sha256.convert(utf8.encode(account)).toString();
    var seed = await storage.read(key: 'cu06_signing_$scope');
    _ensureUnlocked();
    if (seed == null) {
      seed = base64Encode(VaultCryptoService.randomBytes(32));
      await storage.write(key: 'cu06_signing_$scope', value: seed);
      _ensureUnlocked();
    }
    final signingKey = await Ed25519().newKeyPairFromSeed(base64Decode(seed));
    var adoptedSigningKey = false;
    try {
      _ensureUnlocked();
      final vaultPublicKey =
          base64Encode((await signingKey.extractPublicKey()).bytes);
      _ensureUnlocked();
      final device = await _deviceIdentity.loginDevicePayload(
        vaultPublicKey: vaultPublicKey,
      );
      _ensureUnlocked();
      var auth = await _request('POST', '/auth/login', body: {
        'correo': account,
        'password': password,
        'dispositivo': device,
      });
      if (auth['mfa_required'] == true) {
        final mfaToken = auth['mfa_token'];
        if (mfaToken is! String) {
          throw VaultApiException('El backend no entregó el token MFA.');
        }
        auth = await _request('POST', '/auth/mfa/verify-login', body: {
          'mfa_token': mfaToken,
          'code': code.trim(),
        });
      }
      final nativeAccessToken = auth['access_token'];
      if (nativeAccessToken is! String) {
        throw VaultApiException(
            'El backend no entregó una sesión nativa válida.');
      }
      await _deviceIdentity.enrollAndProve(accessToken: nativeAccessToken);
      _ensureUnlocked();
      final vaultChallenge = await _deviceIdentity.vaultSessionProof(
        accessToken: nativeAccessToken,
      );
      _ensureUnlocked();
      final session = await _request('POST', '/vaults/session',
          token: nativeAccessToken,
          extraHeaders: {'X-Device-Id': vaultChallenge.installationId},
          body: vaultChallenge.requestBody);
      _ensureUnlocked();
      _token = session['access_token'] as String;
      _deviceId = session['id_dispositivo'] as String;
      _userId = session['id_usuario'] as String;
      _signingKey = signingKey;
      adoptedSigningKey = true;
    } on DeviceIdentityApiException catch (error) {
      throw VaultApiException(error.message);
    } on InstallationIdentityException catch (error) {
      throw VaultApiException(error.message);
    } finally {
      if (!adoptedSigningKey) {
        signingKey.destroy();
      }
    }
  }

  Future<Uint8List> deviceKey() async {
    _ensureUnlocked();
    final storageKey = 'cu06_wrapping_$_userId';
    var encoded = await storage.read(key: storageKey);
    _ensureUnlocked();
    if (encoded == null) {
      encoded = base64Encode(VaultCryptoService.randomBytes(32));
      await storage.write(key: storageKey, value: encoded);
      _ensureUnlocked();
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
    _ensureUnlocked();
    final encoded = await storage.read(key: 'cu06_pending_$_userId');
    _ensureUnlocked();
    return encoded == null
        ? null
        : Map<String, dynamic>.from(jsonDecode(encoded) as Map);
  }

  Future<void> savePending(Map<String, dynamic> body, String retryKey) async {
    _ensureUnlocked();
    await storage.write(
      key: 'cu06_pending_$_userId',
      value: jsonEncode({'body': body, 'retry_key': retryKey}),
    );
    _ensureUnlocked();
  }

  Future<void> clearPending() async {
    _ensureUnlocked();
    await storage.delete(key: 'cu06_pending_$_userId');
    _ensureUnlocked();
  }

  void logout() {
    _token = null;
    _deviceId = null;
    _userId = null;
    _signingKey?.destroy();
    _signingKey = null;
  }

  bool get _allowsSensitiveActions =>
      _lockService == null || _lockService!.allowsSensitiveActions;

  void _ensureUnlocked() {
    if (!_allowsSensitiveActions) {
      throw VaultApiException(
        'Desbloquea la aplicación antes de usar las bóvedas cifradas.',
      );
    }
  }
}
