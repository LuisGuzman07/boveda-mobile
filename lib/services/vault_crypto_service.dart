import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class VaultUnlockResult {
  VaultUnlockResult({
    required this.vaultId,
    required this.cryptoVersion,
    required this.name,
    required this.description,
    required Uint8List vaultKey,
  }) : _vaultKey = vaultKey;

  final String vaultId;
  final int cryptoVersion;
  final String name;
  final String description;
  Uint8List? _vaultKey;

  /// Transfers the mutable key buffer to the in-memory unlock session.
  Uint8List takeVaultKey() {
    final vaultKey = _vaultKey;
    if (vaultKey == null) {
      throw StateError('El material de desbloqueo ya fue descartado.');
    }
    _vaultKey = null;
    return vaultKey;
  }

  void dispose() {
    final vaultKey = _vaultKey;
    if (vaultKey != null) {
      vaultKey.fillRange(0, vaultKey.length, 0);
      _vaultKey = null;
    }
  }
}

class VaultCryptoService {
  static const kdfParameters = {
    'algoritmo': 'Argon2id',
    'memoria_kib': 65536,
    'iteraciones': 3,
    'paralelismo': 1,
    'longitud': 32,
  };
  final _cipher = AesGcm.with256bits();

  static Uint8List randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
        List.generate(length, (_) => random.nextInt(256)));
  }

  static String newId() {
    final bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    final hex =
        bytes.map((value) => value.toRadixString(16).padLeft(2, '0')).join();
    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
  }

  Future<SecretKey> _derive(String password, List<int> salt) {
    return Argon2id(
            parallelism: 1, memory: 65536, iterations: 3, hashLength: 32)
        .deriveKeyFromPassword(password: password, nonce: salt);
  }

  Future<Map<String, dynamic>> encrypt(
      List<int> bytes, SecretKey key, String aad) async {
    final box = await _cipher.encrypt(bytes,
        secretKey: key, nonce: randomBytes(12), aad: utf8.encode(aad));
    return {
      'algoritmo': 'AES-256-GCM',
      'ciphertext': base64Encode(box.cipherText),
      'nonce': base64Encode(box.nonce),
      'tag': base64Encode(box.mac.bytes)
    };
  }

  Future<Uint8List> decrypt(
      Map<String, dynamic> envelope, SecretKey key, String aad) async {
    if (envelope['algoritmo'] != 'AES-256-GCM') {
      throw const FormatException('Algoritmo de cifrado no compatible');
    }
    final box = SecretBox(base64Decode(envelope['ciphertext'] as String),
        nonce: base64Decode(envelope['nonce'] as String),
        mac: Mac(base64Decode(envelope['tag'] as String)));
    return Uint8List.fromList(
        await _cipher.decrypt(box, secretKey: key, aad: utf8.encode(aad)));
  }

  Future<Map<String, dynamic>> prepare(
      {required String name,
      required String description,
      required String password,
      required String deviceId,
      required List<int> deviceKey}) async {
    final vaultId = newId();
    final salt = randomBytes(16);
    final vaultBytes = randomBytes(32);
    final derived = await _derive(password, salt);
    try {
      final vaultKey = SecretKey(vaultBytes);
      final passwordEnvelope =
          await encrypt(vaultBytes, derived, '$vaultId:password:v1');
      final deviceEnvelope = await encrypt(
          utf8.encode(jsonEncode(passwordEnvelope)),
          SecretKey(deviceKey),
          '$vaultId:$deviceId:device:v1');
      return {
        'id_boveda': vaultId,
        'nombre_cifrado': await encrypt(
            utf8.encode(name.trim()), vaultKey, '$vaultId:name:v1'),
        'descripcion_cifrada': description.trim().isEmpty
            ? null
            : await encrypt(utf8.encode(description.trim()), vaultKey,
                '$vaultId:description:v1'),
        'version_criptografica': 1,
        'kdf_salt': base64Encode(salt),
        'kdf_parametros': kdfParameters,
        'clave_envuelta': {
          ...deviceEnvelope,
          'id_dispositivo': deviceId,
          'version_clave': 1
        },
      };
    } finally {
      vaultBytes.fillRange(0, vaultBytes.length, 0);
      derived.destroy();
    }
  }

  Future<Map<String, String>> reopen(
    Map<String, dynamic> vault,
    String password,
    List<int> deviceKey, {
    String? expectedDeviceId,
  }) async {
    final result = await unlock(
      vault: vault,
      password: password,
      deviceKey: deviceKey,
      expectedDeviceId: expectedDeviceId,
    );
    try {
      return {'nombre': result.name, 'descripcion': result.description};
    } finally {
      result.dispose();
    }
  }

  Future<VaultUnlockResult> unlock({
    required Map<String, dynamic> vault,
    required String password,
    required List<int> deviceKey,
    String? expectedDeviceId,
  }) async {
    _validateVaultContract(vault);
    final vaultId = _requiredString(vault, 'id_boveda');
    final envelope = Map<String, dynamic>.from(vault['clave_envuelta'] as Map);
    final deviceId = _requiredString(envelope, 'id_dispositivo');
    if (expectedDeviceId != null && deviceId != expectedDeviceId) {
      throw const FormatException('El sobre no pertenece a este dispositivo.');
    }

    Uint8List? innerBytes;
    Uint8List? vaultBytes;
    Uint8List? nameBytes;
    Uint8List? descriptionBytes;
    final derived = await _derive(
        password, base64Decode(_requiredString(vault, 'kdf_salt')));
    try {
      innerBytes = await decrypt(
        envelope,
        SecretKey(deviceKey),
        '$vaultId:$deviceId:device:v1',
      );
      final inner =
          Map<String, dynamic>.from(jsonDecode(utf8.decode(innerBytes)) as Map);
      vaultBytes = await decrypt(inner, derived, '$vaultId:password:v1');
      final key = SecretKey(vaultBytes);
      nameBytes = await decrypt(
        Map<String, dynamic>.from(vault['nombre_cifrado'] as Map),
        key,
        '$vaultId:name:v1',
      );
      final description = vault['descripcion_cifrada'];
      descriptionBytes = description == null
          ? Uint8List(0)
          : await decrypt(
              Map<String, dynamic>.from(description as Map),
              key,
              '$vaultId:description:v1',
            );
      final unlockKey = vaultBytes;
      vaultBytes = null;
      return VaultUnlockResult(
        vaultId: vaultId,
        cryptoVersion: vault['version_criptografica'] as int,
        name: utf8.decode(nameBytes),
        description: utf8.decode(descriptionBytes),
        vaultKey: unlockKey,
      );
    } finally {
      vaultBytes?.fillRange(0, vaultBytes.length, 0);
      innerBytes?.fillRange(0, innerBytes.length, 0);
      nameBytes?.fillRange(0, nameBytes.length, 0);
      descriptionBytes?.fillRange(0, descriptionBytes.length, 0);
      derived.destroy();
    }
  }

  static String _requiredString(Map<String, dynamic> values, String key) {
    final value = values[key];
    if (value is! String || value.isEmpty) {
      throw const FormatException('Datos de bóveda incompatibles.');
    }
    return value;
  }

  static void _validateVaultContract(Map<String, dynamic> vault) {
    if (vault['version_criptografica'] != 1 ||
        vault['kdf_parametros'] is! Map) {
      throw const FormatException('Versión criptográfica no compatible');
    }
    final parameters =
        Map<String, dynamic>.from(vault['kdf_parametros'] as Map);
    if (kdfParameters.entries
        .any((entry) => parameters[entry.key] != entry.value)) {
      throw const FormatException('Versión criptográfica no compatible');
    }
  }
}
