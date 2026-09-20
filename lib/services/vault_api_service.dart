import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';
import '../features/file_upload/domain/vault_file_upload_api.dart';
import 'app_lock_service.dart';
import 'device_identity_api_service.dart';
import 'installation_identity_service.dart';
import 'vault_crypto_service.dart';

class VaultApiException implements Exception {
  VaultApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => message;
}

class VaultApiService implements VaultFileUploadApi {
  static const configuredUrl = String.fromEnvironment('BOVEDA_API_URL');
  static const vaultSessionPath = '/vaults/session';
  final FlutterSecureStorage storage;
  final String baseUrl;
  String? _token;
  String? _deviceId;
  String? _userId;
  String? _accountScope;
  SimpleKeyPair? _signingKey;
  AppLockService? _lockService;
  final http.Client? _client;
  final DeviceIdentityApiService _deviceIdentity;
  final _sessionInvalidationListeners = <VoidCallback>{};
  int _sessionGeneration = 0;

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

  void addSessionInvalidationListener(VoidCallback listener) {
    _sessionInvalidationListeners.add(listener);
  }

  void removeSessionInvalidationListener(VoidCallback listener) {
    _sessionInvalidationListeners.remove(listener);
  }

  Future<Map<String, dynamic>> _request(String method, String path,
      {Map<String, dynamic>? body,
      String? token,
      String? retryKey,
      bool signed = false,
      bool expectJson = true,
      Map<String, String>? extraHeaders}) async {
    _ensureUnlocked();
    final requestSession = _sessionGeneration;
    final uri = Uri.parse('$baseUrl$path');
    final text = body == null ? '' : jsonEncode(body);
    final headers = <String, String>{'Content-Type': 'application/json'};
    if (token != null) headers['Authorization'] = 'Bearer $token';
    if (retryKey != null) headers['Idempotency-Key'] = retryKey;
    if (extraHeaders != null) headers.addAll(extraHeaders);
    if (signed) {
      final vaultToken = _token;
      final signingKey = _signingKey;
      if (vaultToken == null || signingKey == null) {
        throw VaultApiException('Inicia sesión nuevamente.');
      }
      headers['Authorization'] = 'Bearer $vaultToken';
      final payload = jsonDecode(utf8.decode(
              base64Url.decode(base64Url.normalize(vaultToken.split('.')[1]))))
          as Map;
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
          await Ed25519().sign(utf8.encode(message), keyPair: signingKey);
      _ensureCurrentSession(requestSession);
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
      final detail = _responseDetail(response.body);
      if (response.statusCode == 401 || response.statusCode == 403) {
        await _invalidateRemoteSession(requestSession);
        throw VaultApiException(
          detail ?? 'Solicitud rechazada (${response.statusCode}).',
          statusCode: response.statusCode,
        );
      }
      _ensureCurrentSession(requestSession);
      if (response.statusCode >= 400) {
        throw VaultApiException(
          detail ?? 'Solicitud rechazada (${response.statusCode}).',
          statusCode: response.statusCode,
        );
      }
      if (!expectJson) {
        return const <String, dynamic>{};
      }
      return _decodeResponse(response);
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
    final loginSession = _sessionGeneration;
    final account = email.trim().toLowerCase();
    final scope = hashes.sha256.convert(utf8.encode(account)).toString();
    _accountScope = scope;
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
      final session = await _request('POST', vaultSessionPath,
          token: nativeAccessToken,
          extraHeaders: {'X-Device-Id': vaultChallenge.installationId},
          body: vaultChallenge.requestBody);
      _ensureUnlocked();
      final vaultToken = session['access_token'];
      final deviceId = session['id_dispositivo'];
      final userId = session['id_usuario'];
      if (vaultToken is! String || deviceId is! String || userId is! String) {
        throw VaultApiException(
            'El backend no entregó una sesión de bóveda válida.');
      }
      _token = vaultToken;
      _deviceId = deviceId;
      _userId = userId;
      _signingKey = signingKey;
      adoptedSigningKey = true;
    } on DeviceIdentityApiException catch (error) {
      if ((error.statusCode == 401 || error.statusCode == 403) &&
          loginSession == _sessionGeneration) {
        await _invalidateRemoteSession(loginSession);
      }
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
    final requestSession = _sessionGeneration;
    final storageKey = 'cu06_wrapping_${_requireUserId()}';
    var encoded = await storage.read(key: storageKey);
    _ensureCurrentSession(requestSession);
    if (encoded == null) {
      encoded = base64Encode(VaultCryptoService.randomBytes(32));
      await storage.write(key: storageKey, value: encoded);
      _ensureCurrentSession(requestSession);
    }
    return base64Decode(encoded);
  }

  Future<List<Map<String, dynamic>>> revalidateSession() async {
    final data = await _request('GET', '/vaults', signed: true);
    return (data['items'] as List)
        .map((item) => Map<String, dynamic>.from(item as Map))
        .toList();
  }

  Future<void> validateVaultSession() async {
    final data = await _request('GET', vaultSessionPath, signed: true);
    if (data['status'] != 'active') {
      throw VaultApiException('La sesión de bóveda no está activa.');
    }
  }

  Future<List<Map<String, dynamic>>> listVaults() => revalidateSession();

  Future<void> revokeSession() async {
    if (_token == null) {
      logout();
      return;
    }
    try {
      await _request(
        'DELETE',
        vaultSessionPath,
        signed: true,
        expectJson: false,
      );
    } finally {
      logout();
    }
  }

  Future<Map<String, dynamic>> getVault(String id) =>
      _request('GET', '/vaults/$id', signed: true);
  Future<Map<String, dynamic>> createVault(
          Map<String, dynamic> body, String retryKey) =>
      _request('POST', '/vaults', body: body, retryKey: retryKey, signed: true);

  @override
  Future<Map<String, dynamic>> createFileUploadIntent(
    String vaultId,
    int ciphertextLength,
    String retryKey,
  ) =>
      _request(
        'POST',
        '/vaults/$vaultId/files/upload-intents',
        body: <String, dynamic>{
          'tamano_ciphertext_esperado': ciphertextLength,
          'version_criptografica': 1,
        },
        retryKey: retryKey,
        signed: true,
      );

  @override
  Future<Map<String, dynamic>> completeFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    Map<String, dynamic> body,
    String retryKey,
  ) =>
      _request(
        'POST',
        '/vaults/$vaultId/files/$fileId/versions/$versionId/complete',
        body: body,
        retryKey: retryKey,
        signed: true,
      );

  @override
  Future<Map<String, dynamic>> abortFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    String retryKey,
  ) =>
      _request(
        'POST',
        '/vaults/$vaultId/files/$fileId/versions/$versionId/abort',
        retryKey: retryKey,
        signed: true,
      );

  Future<Map<String, dynamic>?> pendingCreation() async {
    _ensureUnlocked();
    final requestSession = _sessionGeneration;
    final encoded = await storage.read(key: 'cu06_pending_${_requireUserId()}');
    _ensureCurrentSession(requestSession);
    return encoded == null
        ? null
        : Map<String, dynamic>.from(jsonDecode(encoded) as Map);
  }

  Future<void> savePending(Map<String, dynamic> body, String retryKey) async {
    _ensureUnlocked();
    final requestSession = _sessionGeneration;
    await storage.write(
      key: 'cu06_pending_${_requireUserId()}',
      value: jsonEncode({'body': body, 'retry_key': retryKey}),
    );
    _ensureCurrentSession(requestSession);
  }

  Future<void> clearPending() async {
    _ensureUnlocked();
    final requestSession = _sessionGeneration;
    await storage.delete(key: 'cu06_pending_${_requireUserId()}');
    _ensureCurrentSession(requestSession);
  }

  void logout() {
    _clearSession();
  }

  String _requireUserId() {
    final userId = _userId;
    if (userId == null) {
      throw VaultApiException('Inicia sesión nuevamente.');
    }
    return userId;
  }

  void _ensureCurrentSession(int requestSession) {
    _ensureUnlocked();
    if (requestSession != _sessionGeneration) {
      throw VaultApiException(
        'La sesión de bóveda cambió antes de completar la operación.',
      );
    }
  }

  Future<void> _invalidateRemoteSession(int requestSession) async {
    if (requestSession != _sessionGeneration) {
      return;
    }
    final data = _VaultSessionData(
      accountScope: _accountScope,
      userId: _userId,
    );
    _clearSession();
    _lockService?.lock();
    await _deleteVaultData(data);
  }

  Future<void> _deleteVaultData(_VaultSessionData data) async {
    final deletions = <Future<void>>[];
    if (data.accountScope != null) {
      deletions.add(storage.delete(key: 'cu06_signing_${data.accountScope}'));
    }
    if (data.userId != null) {
      deletions.add(storage.delete(key: 'cu06_wrapping_${data.userId}'));
      deletions.add(storage.delete(key: 'cu06_pending_${data.userId}'));
    }
    try {
      await Future.wait(deletions);
    } catch (_) {
      // The application remains locked even if secure storage cannot be cleared.
    }
  }

  void _clearSession() {
    _sessionGeneration++;
    _token = null;
    _deviceId = null;
    _userId = null;
    _accountScope = null;
    _signingKey?.destroy();
    _signingKey = null;
    for (final listener
        in List<VoidCallback>.from(_sessionInvalidationListeners)) {
      listener();
    }
  }

  String? _responseDetail(String body) {
    try {
      final data = jsonDecode(body);
      return data is Map && data['detail'] is String
          ? data['detail'] as String
          : null;
    } catch (_) {
      return null;
    }
  }

  Map<String, dynamic> _decodeResponse(http.Response response) {
    try {
      final data = jsonDecode(response.body);
      if (data is! Map) {
        throw const FormatException();
      }
      return Map<String, dynamic>.from(data);
    } catch (_) {
      throw VaultApiException('El backend devolvió una respuesta inválida.');
    }
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

class _VaultSessionData {
  const _VaultSessionData({
    required this.accountScope,
    required this.userId,
  });

  final String? accountScope;
  final String? userId;
}
