import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/app_config.dart';
import 'app_lock_service.dart';
import 'installation_identity_service.dart';

class DeviceIdentityApiException implements Exception {
  DeviceIdentityApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

class DeviceChallenge {
  DeviceChallenge({
    required this.id,
    required this.nonce,
    required this.purpose,
    required this.expiresAt,
  });

  final String id;
  final String nonce;
  final String purpose;
  final DateTime expiresAt;

  factory DeviceChallenge.fromJson(Map<String, dynamic> json) {
    final id = json['id_desafio'];
    final nonce = json['nonce'];
    final purpose = json['proposito'];
    final expiresAt = json['fecha_expiracion'];
    if (id is! String ||
        nonce is! String ||
        purpose is! String ||
        expiresAt is! String) {
      throw DeviceIdentityApiException('Respuesta de desafío inválida.');
    }
    final parsedExpiration = DateTime.tryParse(expiresAt);
    if (parsedExpiration == null) {
      throw DeviceIdentityApiException('Expiración de desafío inválida.');
    }
    return DeviceChallenge(
      id: id,
      nonce: nonce,
      purpose: purpose,
      expiresAt: parsedExpiration.toUtc(),
    );
  }
}

class SignedDeviceChallenge {
  const SignedDeviceChallenge({
    required this.installationId,
    required this.challengeId,
    required this.nonce,
    required this.signature,
  });

  final String installationId;
  final String challengeId;
  final String nonce;
  final String signature;

  Map<String, dynamic> get requestBody => <String, dynamic>{
        'id_desafio': challengeId,
        'nonce': nonce,
        'firma': signature,
      };
}

class DeviceIdentityApiService {
  DeviceIdentityApiService({
    InstallationIdentityProvider? identity,
    AppLockService? lockService,
    http.Client? client,
    String? baseUrl,
  })  : _identity = identity ?? InstallationIdentityService(),
        _lockService = lockService,
        _client = client,
        _baseUrl = baseUrl ?? AppConfig.baseUrl;

  static const challengePath = '/devices/challenge';
  static const challengeProofPath = '/devices/challenge/prove';
  static const enrollmentPurpose = 'DEVICE_ENROLLMENT';
  static const vaultSessionPurpose = 'VAULT_SESSION';

  final InstallationIdentityProvider _identity;
  AppLockService? _lockService;
  final http.Client? _client;
  final String _baseUrl;

  Future<Map<String, dynamic>> deviceRegistrationPayload({
    String name = 'Bóveda móvil',
  }) async {
    _ensureUnlocked();
    final identity = await _identity.loadOrCreate();
    _ensureUnlocked();
    return identity.deviceRegistrationPayload(
      name: name,
      operatingSystem: kIsWeb ? 'web' : defaultTargetPlatform.name,
    );
  }

  Future<Map<String, dynamic>> loginDevicePayload({
    required String vaultPublicKey,
    String name = 'Bóveda móvil',
  }) async {
    final payload = await deviceRegistrationPayload(name: name);
    if (vaultPublicKey.isEmpty || vaultPublicKey == payload['public_key']) {
      throw DeviceIdentityApiException(
        'La clave de firma de bóveda debe ser distinta de la identidad de instalación.',
      );
    }
    return <String, dynamic>{
      ...payload,
      'vault_public_key': vaultPublicKey,
    };
  }

  void attachLockService(AppLockService lockService) {
    _lockService = lockService;
  }

  Future<void> enrollAndProve({
    required String accessToken,
  }) async {
    final proof = await _signedChallenge(
      accessToken: accessToken,
      purpose: enrollmentPurpose,
    );
    await _post(
      challengeProofPath,
      accessToken: accessToken,
      installationId: proof.installationId,
      body: proof.requestBody,
    );
  }

  Future<SignedDeviceChallenge> vaultSessionProof({
    required String accessToken,
  }) =>
      _signedChallenge(
        accessToken: accessToken,
        purpose: vaultSessionPurpose,
      );

  Future<SignedDeviceChallenge> _signedChallenge({
    required String accessToken,
    required String purpose,
  }) async {
    _ensureUnlocked();
    final identity = await _identity.loadOrCreate();
    _ensureUnlocked();
    final claims = _nativeSessionClaims(accessToken);
    final challengeResponse = await _post(
      challengePath,
      accessToken: accessToken,
      installationId: identity.installationId,
      body: <String, dynamic>{'proposito': purpose},
    );
    final challenge = DeviceChallenge.fromJson(challengeResponse);
    if (challenge.purpose != purpose) {
      throw DeviceIdentityApiException(
        'El desafío recibido no corresponde a la operación solicitada.',
      );
    }
    final signature = await _identity.signChallenge(
      challengeId: challenge.id,
      purpose: challenge.purpose,
      userId: claims.userId,
      deviceId: claims.deviceId,
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
    );
    _ensureUnlocked();
    return SignedDeviceChallenge(
      installationId: identity.installationId,
      challengeId: challenge.id,
      nonce: challenge.nonce,
      signature: signature,
    );
  }

  Future<Map<String, dynamic>> _post(
    String path, {
    required String accessToken,
    required String installationId,
    required Map<String, dynamic> body,
  }) async {
    _ensureUnlocked();
    final client = _client ?? http.Client();
    try {
      final response = await client
          .post(
            Uri.parse('$_baseUrl$path'),
            headers: <String, String>{
              'Authorization': 'Bearer $accessToken',
              'Content-Type': 'application/json',
              'X-Device-Id': installationId,
            },
            body: jsonEncode(body),
          )
          .timeout(const Duration(seconds: 20));
      _ensureUnlocked();
      final decoded = _decode(response);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final detail = decoded['detail'];
        throw DeviceIdentityApiException(
          detail is String
              ? detail
              : 'El backend rechazó el enrolamiento (${response.statusCode}).',
        );
      }
      return decoded;
    } on DeviceIdentityApiException {
      rethrow;
    } catch (_) {
      throw DeviceIdentityApiException(
        'No se pudo completar el enrolamiento del dispositivo.',
      );
    } finally {
      if (_client == null) {
        client.close();
      }
    }
  }

  Map<String, dynamic> _decode(http.Response response) {
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is! Map) {
        throw const FormatException();
      }
      return Map<String, dynamic>.from(decoded);
    } catch (_) {
      throw DeviceIdentityApiException(
          'El backend devolvió una respuesta inválida.');
    }
  }

  _NativeSessionClaims _nativeSessionClaims(String accessToken) {
    try {
      final parts = accessToken.split('.');
      if (parts.length != 3) {
        throw const FormatException();
      }
      final payload = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
      );
      if (payload is! Map) {
        throw const FormatException();
      }
      final userId = payload['sub'];
      final deviceId = payload['did'];
      if (userId is! String || deviceId is! String) {
        throw const FormatException();
      }
      return _NativeSessionClaims(userId: userId, deviceId: deviceId);
    } catch (_) {
      throw DeviceIdentityApiException(
        'La sesión nativa no contiene la identidad necesaria para el desafío.',
      );
    }
  }

  void _ensureUnlocked() {
    if (_lockService?.allowsSensitiveActions == false) {
      throw DeviceIdentityApiException(
        'Desbloquea la aplicación antes de usar la identidad del dispositivo.',
      );
    }
  }
}

class _NativeSessionClaims {
  const _NativeSessionClaims({
    required this.userId,
    required this.deviceId,
  });

  final String userId;
  final String deviceId;
}
