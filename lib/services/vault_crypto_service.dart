import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

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
      Map<String, dynamic> vault, String password, List<int> deviceKey) async {
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
