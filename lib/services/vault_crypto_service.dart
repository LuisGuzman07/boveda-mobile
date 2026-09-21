import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as hashes;

class VaultCryptoService {
  static const kdfParameters = {
    'algoritmo': 'Argon2id',
    'memoria_kib': 65536,
    'iteraciones': 3,
    'paralelismo': 1,
    'longitud': 32,
  };
  final _cipher = AesGcm.with256bits();
  Uint8List? _activeVaultKey;

  bool get hasActiveVaultKey => _activeVaultKey != null;

  void clearSessionKey() {
    _activeVaultKey?.fillRange(0, _activeVaultKey!.length, 0);
    _activeVaultKey = null;
  }

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

  Future<Map<String, dynamic>> createEmergencyKit(
      String vaultId, String vaultKdfSalt, String password) async {
    final active = _activeVaultKey;
    if (active == null) throw StateError('La bóveda debe estar desbloqueada.');
    if (password.length < 12) {
      throw const FormatException('La contraseña del kit debe tener al menos 12 caracteres.');
    }
    final salt = randomBytes(16);
    final derived = await _derive(password, salt);
    try {
      final envelope = await encrypt(active, derived, '$vaultId:emergency-kit:v1');
      final fingerprint = hashes.sha256.convert(utf8.encode(jsonEncode({
        'version_kit': 1,
        'version_criptografica': 1,
        'kdf_salt': base64Encode(salt),
        'kdf_parametros': kdfParameters,
        'sobre_cifrado': envelope,
      }))).toString();
      return {
        'id_kit': newId(),
        'id_boveda': vaultId,
        'version_kit': 1,
        'version_criptografica': 1,
        'kdf_salt': base64Encode(salt),
        'kdf_salt_boveda': vaultKdfSalt,
        'kdf_parametros': kdfParameters,
        'sobre_cifrado': envelope,
        'huella_kit': fingerprint,
        'expira_en_dias': 365,
      };
    } finally {
      derived.destroy();
    }
  }

  Future<Map<String, dynamic>> prepareEmergencyRecovery(
      Map<String, dynamic> kit,
      Map<String, dynamic> vault,
      String password,
      String deviceId,
      List<int> deviceKey) async {
    if (kit['version_kit'] != 1 || kit['version_criptografica'] != 1) {
      throw const FormatException('Versión de Emergency Kit no compatible.');
    }
    final kitKey = await _derive(password, base64Decode(kit['kdf_salt'] as String));
    Uint8List? vaultBytes;
    SecretKey? vaultPasswordKey;
    try {
      vaultBytes = await decrypt(Map<String, dynamic>.from(kit['sobre_cifrado'] as Map), kitKey,
          '${vault['id_boveda']}:emergency-kit:v1');
      vaultPasswordKey = await _derive(password, base64Decode(vault['kdf_salt'] as String));
      final inner = await encrypt(vaultBytes, vaultPasswordKey, '${vault['id_boveda']}:password:v1');
      final outer = await encrypt(utf8.encode(jsonEncode(inner)), SecretKey(deviceKey),
          '${vault['id_boveda']}:$deviceId:device:v1');
      return {
        'id_kit': kit['id_kit'],
        'id_dispositivo': deviceId,
        'clave_envuelta': {...outer, 'id_dispositivo': deviceId, 'version_clave': 1},
      };
    } finally {
      kitKey.destroy();
      vaultPasswordKey?.destroy();
      if (vaultBytes != null) vaultBytes.fillRange(0, vaultBytes.length, 0);
    }
  }

  Future<Uint8List> decryptDownloadedFile(
      Map<String, dynamic> download, String vaultId) async {
    final active = _activeVaultKey;
    if (active == null) {
      throw StateError('La bóveda debe estar desbloqueada.');
    }
    final ciphertext = Uint8List.fromList(
        base64Decode(download['ciphertext'] as String));
    final expectedHash = (download['hash_cifrado'] as String).toLowerCase();
    try {
      if (ciphertext.length + 16 != download['tamano_cifrado'] ||
          hashes.sha256.convert(ciphertext).toString() != expectedHash) {
        throw const FormatException('La integridad del ciphertext no pudo verificarse.');
      }
      final wrapped = Map<String, dynamic>.from(
          download['clave_archivo_envuelta'] as Map);
      final fileKeyBytes = await decrypt(wrapped, SecretKey(active),
          '$vaultId:file-key:${download['id_version_archivo']}:v1');
      try {
        return await decrypt({
          'algoritmo': download['algoritmo'],
          'ciphertext': download['ciphertext'],
          'nonce': download['nonce_iv'],
          'tag': download['auth_tag'],
        }, SecretKey(fileKeyBytes),
            '$vaultId:file:${download['id_version_archivo']}:v1');
      } finally {
        fileKeyBytes.fillRange(0, fileKeyBytes.length, 0);
      }
    } finally {
      ciphertext.fillRange(0, ciphertext.length, 0);
    }
  }

  // CU-08: each version gets a fresh file key. Only its AES-GCM envelope is
  // sent to the backend; the active vault key remains in this process.
  Future<Map<String, dynamic>> encryptFile(
      {required List<int> bytes,
      required String fileName,
      required String vaultId}) async {
    final active = _activeVaultKey;
    if (active == null) {
      throw StateError('La bóveda debe estar desbloqueada.');
    }
    final fileId = newId();
    final versionId = newId();
    final fileKeyBytes = randomBytes(32);
    try {
      final fileKey = SecretKey(fileKeyBytes);
      final content = await encrypt(
          bytes, fileKey, '$vaultId:file:$versionId:v1');
      final wrapped = await encrypt(fileKeyBytes, SecretKey(active),
          '$vaultId:file-key:$versionId:v1');
      final encryptedName = await encrypt(utf8.encode(fileName), fileKey,
          '$vaultId:filename:$versionId:v1');
      final ciphertext = base64Decode(content['ciphertext'] as String);
      return {
        'id_archivo': fileId,
        'id_version_archivo': versionId,
        'nombre_cifrado': encryptedName,
        'contenido_cifrado': content,
        'clave_archivo_envuelta': wrapped,
        'tamano_cifrado': ciphertext.length + 16,
        'hash_cifrado': hashes.sha256.convert(ciphertext).toString(),
      };
    } finally {
      fileKeyBytes.fillRange(0, fileKeyBytes.length, 0);
    }
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
      Map<String, dynamic> vault, String password, List<int> deviceKey) async {
    clearSessionKey();
    if (vault['version_criptografica'] != 1 ||
        jsonEncode(vault['kdf_parametros']) != jsonEncode(kdfParameters)) {
      final parameters =
          Map<String, dynamic>.from(vault['kdf_parametros'] as Map);
      if (vault['version_criptografica'] != 1 ||
          kdfParameters.entries
              .any((entry) => parameters[entry.key] != entry.value)) {
        throw const FormatException('Versión criptográfica no compatible');
      }
    }
    final vaultId = vault['id_boveda'] as String;
    final envelope = Map<String, dynamic>.from(vault['clave_envuelta'] as Map);
    final deviceId = envelope['id_dispositivo'];
    final innerBytes = await decrypt(
        envelope, SecretKey(deviceKey), '$vaultId:$deviceId:device:v1');
    final derived =
        await _derive(password, base64Decode(vault['kdf_salt'] as String));
    Uint8List? vaultBytes;
    try {
      final inner =
          Map<String, dynamic>.from(jsonDecode(utf8.decode(innerBytes)) as Map);
      vaultBytes = await decrypt(inner, derived, '$vaultId:password:v1');
      final key = SecretKey(vaultBytes);
      final nameBytes = await decrypt(
          Map<String, dynamic>.from(vault['nombre_cifrado'] as Map),
          key,
          '$vaultId:name:v1');
      final description = vault['descripcion_cifrada'];
      final descriptionBytes = description == null
          ? Uint8List(0)
          : await decrypt(Map<String, dynamic>.from(description as Map), key,
              '$vaultId:description:v1');
      _activeVaultKey = Uint8List.fromList(vaultBytes);
      return {
        'nombre': utf8.decode(nameBytes),
        'descripcion': utf8.decode(descriptionBytes)
      };
    } finally {
      vaultBytes?.fillRange(0, vaultBytes.length, 0);
      innerBytes.fillRange(0, innerBytes.length, 0);
      derived.destroy();
    }
  }
}
