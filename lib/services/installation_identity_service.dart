import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

class InstallationIdentityException implements Exception {
  InstallationIdentityException(this.message, {this.recoveryRequired = true});

  final String message;
  final bool recoveryRequired;

  @override
  String toString() => message;
}

abstract class SecureInstallationIdentityStore {
  Future<String?> read(String key);

  Future<void> write(String key, String value);

  Future<void> delete(String key);
}

class FlutterSecureInstallationIdentityStore
    implements SecureInstallationIdentityStore {
  FlutterSecureInstallationIdentityStore({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                encryptedSharedPreferences: true,
                resetOnError: false,
              ),
              iOptions: IOSOptions(
                accessibility: KeychainAccessibility.unlocked_this_device,
              ),
            );

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

abstract class InstallationIdentityStateStore {
  Future<bool?> isInitialized();

  Future<void> markInitialized();
}

class SharedPreferencesInstallationIdentityStateStore
    implements InstallationIdentityStateStore {
  static const initializationKey =
      'boveda_installation_identity_initialized_v1';

  @override
  Future<bool?> isInitialized() async {
    final preferences = await SharedPreferences.getInstance();
    return preferences.getBool(initializationKey);
  }

  @override
  Future<void> markInitialized() async {
    final preferences = await SharedPreferences.getInstance();
    if (!await preferences.setBool(initializationKey, true)) {
      throw InstallationIdentityException(
        'No se pudo registrar el estado de la identidad local.',
      );
    }
  }
}

class InstallationIdentity {
  const InstallationIdentity({
    required this.installationId,
    required this.publicKey,
  });

  final String installationId;
  final String publicKey;

  Map<String, dynamic> deviceRegistrationPayload({
    required String name,
    required String operatingSystem,
  }) =>
      <String, dynamic>{
        'nombre': name,
        'tipo': 'MOVIL',
        'sistema_operativo': operatingSystem,
        'identificador_seguro': installationId,
        'public_key': publicKey,
      };
}

abstract class InstallationIdentityProvider {
  Future<InstallationIdentity> loadOrCreate();

  Future<InstallationIdentity> recover();

  Future<String> signChallenge({
    required String challengeId,
    required String purpose,
    required String userId,
    required String deviceId,
    required String nonce,
    required DateTime expiresAt,
  });
}

class InstallationIdentityService implements InstallationIdentityProvider {
  InstallationIdentityService({
    SecureInstallationIdentityStore? secureStore,
    InstallationIdentityStateStore? stateStore,
    Ed25519? algorithm,
  })  : _secureStore = secureStore ?? FlutterSecureInstallationIdentityStore(),
        _stateStore =
            stateStore ?? SharedPreferencesInstallationIdentityStateStore(),
        _algorithm = algorithm ?? Ed25519();

  static const secureInstallationIdKey = 'boveda_installation_id_v1';
  static const privateSeedKey = 'boveda_installation_ed25519_seed_v1';
  static const identityVersionKey = 'boveda_installation_identity_version_v1';
  static const _identityVersion = '1';

  final SecureInstallationIdentityStore _secureStore;
  final InstallationIdentityStateStore _stateStore;
  final Ed25519 _algorithm;
  Future<void> _operationTail = Future<void>.value();

  @override
  Future<InstallationIdentity> loadOrCreate() =>
      _runSerialized(_loadOrCreateIdentity);

  @override
  Future<InstallationIdentity> recover() => _runSerialized(() async {
        await Future.wait(<Future<void>>[
          _secureStore.delete(secureInstallationIdKey),
          _secureStore.delete(privateSeedKey),
          _secureStore.delete(identityVersionKey),
        ]);
        final values = await _readValues();
        if (values.any((value) => value != null)) {
          throw InstallationIdentityException(
            'No se pudo limpiar la identidad local para recuperarla. Intenta nuevamente.',
          );
        }
        return _createIdentity();
      });

  @override
  Future<String> signChallenge({
    required String challengeId,
    required String purpose,
    required String userId,
    required String deviceId,
    required String nonce,
    required DateTime expiresAt,
  }) {
    return _runSerialized(() async {
      final material = await _loadMaterial();
      try {
        final keyPair = await _algorithm.newKeyPairFromSeed(material.seed);
        try {
          final signature = await _algorithm.sign(
            _challengeTranscript(
              challengeId: challengeId,
              purpose: purpose,
              userId: userId,
              deviceId: deviceId,
              nonce: nonce,
              expiresAt: expiresAt,
            ),
            keyPair: keyPair,
          );
          return base64Encode(signature.bytes);
        } finally {
          keyPair.destroy();
        }
      } finally {
        material.seed.fillRange(0, material.seed.length, 0);
      }
    });
  }

  Future<InstallationIdentity> _loadOrCreateIdentity() async {
    final material = await _loadMaterial();
    try {
      return await _toPublicIdentity(material);
    } finally {
      material.seed.fillRange(0, material.seed.length, 0);
    }
  }

  Future<_IdentityMaterial> _loadMaterial() async {
    final initialized = await _readInitialized();
    final values = await _readValues();
    final allMissing = values.every((value) => value == null);
    if (allMissing && initialized != true) {
      return _createMaterial();
    }
    if (values.any((value) => value == null)) {
      throw InstallationIdentityException(
        'La identidad criptográfica local está incompleta. Restablécela explícitamente para volver a enrolar este dispositivo.',
      );
    }

    final installationId = values[0]!;
    final seedValue = values[1]!;
    final version = values[2]!;
    if (!_isInstallationId(installationId) || version != _identityVersion) {
      throw InstallationIdentityException(
        'La identidad criptográfica local no es válida. Restablécela explícitamente para volver a enrolar este dispositivo.',
      );
    }
    final seed = _decodeSeed(seedValue);

    if (initialized != true) {
      try {
        await _stateStore.markInitialized();
      } catch (_) {
        seed.fillRange(0, seed.length, 0);
        throw InstallationIdentityException(
          'No se pudo verificar el estado de la identidad local. Intenta nuevamente sin restablecerla.',
          recoveryRequired: false,
        );
      }
    }
    return _IdentityMaterial(installationId, seed);
  }

  Future<InstallationIdentity> _createIdentity() async {
    final material = await _createMaterial();
    try {
      return await _toPublicIdentity(material);
    } finally {
      material.seed.fillRange(0, material.seed.length, 0);
    }
  }

  Future<_IdentityMaterial> _createMaterial() async {
    final seed = _randomBytes(32);
    final installationId = _newInstallationId();
    try {
      final encodedSeed = base64Encode(seed);
      await _secureStore.write(secureInstallationIdKey, installationId);
      await _secureStore.write(privateSeedKey, encodedSeed);
      await _secureStore.write(identityVersionKey, _identityVersion);

      final values = await _readValues();
      if (values[0] != installationId ||
          values[1] != encodedSeed ||
          values[2] != _identityVersion) {
        throw InstallationIdentityException(
          'No se pudo verificar la identidad criptográfica local.',
        );
      }
      await _stateStore.markInitialized();
      return _IdentityMaterial(installationId, Uint8List.fromList(seed));
    } on InstallationIdentityException {
      rethrow;
    } catch (_) {
      throw InstallationIdentityException(
        'No se pudo crear la identidad criptográfica local. No se generará otra identidad automáticamente.',
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  Future<InstallationIdentity> _toPublicIdentity(
      _IdentityMaterial material) async {
    final keyPair = await _algorithm.newKeyPairFromSeed(material.seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return InstallationIdentity(
        installationId: material.installationId,
        publicKey: base64Encode(publicKey.bytes),
      );
    } finally {
      keyPair.destroy();
    }
  }

  Future<List<String?>> _readValues() {
    return Future.wait<String?>(<Future<String?>>[
      _secureStore.read(secureInstallationIdKey),
      _secureStore.read(privateSeedKey),
      _secureStore.read(identityVersionKey),
    ]);
  }

  Future<bool?> _readInitialized() async {
    try {
      return await _stateStore.isInitialized();
    } on InstallationIdentityException {
      rethrow;
    } catch (_) {
      throw InstallationIdentityException(
        'No se pudo acceder al estado de la identidad local.',
        recoveryRequired: false,
      );
    }
  }

  Uint8List _decodeSeed(String value) {
    try {
      final seed = Uint8List.fromList(base64Decode(value));
      if (seed.length != 32 || base64Encode(seed) != value) {
        seed.fillRange(0, seed.length, 0);
        throw const FormatException();
      }
      return seed;
    } catch (_) {
      throw InstallationIdentityException(
        'La clave privada de instalación falta o está dañada. Restablécela explícitamente para volver a enrolar este dispositivo.',
      );
    }
  }

  Future<T> _runSerialized<T>(Future<T> Function() action) {
    final next = _operationTail.then<T>((_) => action());
    _operationTail = next.then<void>(
      (_) {},
      onError: (Object _, StackTrace __) {},
    );
    return next;
  }

  static List<int> _challengeTranscript({
    required String challengeId,
    required String purpose,
    required String userId,
    required String deviceId,
    required String nonce,
    required DateTime expiresAt,
  }) {
    final expiresAtSeconds = expiresAt.toUtc().millisecondsSinceEpoch ~/ 1000;
    return utf8.encode(<String>[
      'boveda-device-challenge-v1',
      challengeId,
      purpose,
      userId,
      deviceId,
      nonce,
      '$expiresAtSeconds',
    ].join('\n'));
  }

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  static String _newInstallationId() {
    final bytes = _randomBytes(16);
    try {
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      final hex =
          bytes.map((value) => value.toRadixString(16).padLeft(2, '0')).join();
      return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  static bool _isInstallationId(String value) => RegExp(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
      ).hasMatch(value);
}

class _IdentityMaterial {
  _IdentityMaterial(this.installationId, this.seed);

  final String installationId;
  final Uint8List seed;
}
