import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:boveda_mobile/services/vault_crypto_service.dart';

void main() {
  test('CU06 roundtrip, wrong password, altered metadata and wrong device',
      () async {
    final crypto = VaultCryptoService();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final vault = await crypto.prepare(
        name: 'Investigación',
        description: 'Datos ficticios',
        password: 'Contraseña maestra única 2026',
        deviceId: VaultCryptoService.newId(),
        deviceKey: deviceKey);
    expect(jsonEncode(vault), isNot(contains('Investigación')));
    expect(jsonEncode(vault), isNot(contains('Contraseña maestra')));
    final metadata =
        await crypto.reopen(vault, 'Contraseña maestra única 2026', deviceKey);
    expect(crypto.hasActiveVaultKey, isTrue);
    expect(metadata['nombre'], 'Investigación');
    expect(metadata['descripcion'], 'Datos ficticios');
    await expectLater(
        crypto.reopen(vault, 'Otra contraseña incorrecta', deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));
    await expectLater(
        crypto.reopen(vault, 'Contraseña maestra única 2026',
            VaultCryptoService.randomBytes(32)),
        throwsA(isA<SecretBoxAuthenticationError>()));
    expect(crypto.hasActiveVaultKey, isFalse);
    final name = Map<String, dynamic>.from(vault['nombre_cifrado'] as Map);
    final bytes = base64Decode(name['ciphertext'] as String);
    bytes[0] ^= 1;
    name['ciphertext'] = base64Encode(bytes);
    await expectLater(
        crypto.reopen({...vault, 'nombre_cifrado': name},
            'Contraseña maestra única 2026', deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));
    expect(crypto.hasActiveVaultKey, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('clears the unlocked vault key when the session is locked', () async {
    final crypto = VaultCryptoService();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final vault = await crypto.prepare(
        name: 'Session test',
        description: '',
        password: 'Contraseña maestra única 2026',
        deviceId: VaultCryptoService.newId(),
        deviceKey: deviceKey);
    await crypto.reopen(vault, 'Contraseña maestra única 2026', deviceKey);
    crypto.clearSessionKey();
    expect(crypto.hasActiveVaultKey, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('CU08 creates ciphertext-only versions with unique nonce and hash', () async {
    final crypto = VaultCryptoService();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final vault = await crypto.prepare(
        name: 'Upload test',
        description: '',
        password: 'Contraseña maestra única 2026',
        deviceId: VaultCryptoService.newId(),
        deviceKey: deviceKey);
    await crypto.reopen(vault, 'Contraseña maestra única 2026', deviceKey);

    final first = await crypto.encryptFile(
        bytes: [1, 2, 3, 4], fileName: 'secret.txt', vaultId: vault['id_boveda'] as String);
    final second = await crypto.encryptFile(
        bytes: [1, 2, 3, 4], fileName: 'secret.txt', vaultId: vault['id_boveda'] as String);
    expect(first['contenido_cifrado']['nonce'], isNot(second['contenido_cifrado']['nonce']));
    expect(first['hash_cifrado'], isNotEmpty);
    expect(jsonEncode(first), isNot(contains('secret.txt')));
    crypto.clearSessionKey();
  });

  test('CU10 verifies ciphertext before decrypting and rejects tampering', () async {
    final crypto = VaultCryptoService();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final vault = await crypto.prepare(
        name: 'Download test',
        description: '',
        password: 'Contraseña maestra única 2026',
        deviceId: VaultCryptoService.newId(),
        deviceKey: deviceKey);
    await crypto.reopen(vault, 'Contraseña maestra única 2026', deviceKey);
    final encrypted = await crypto.encryptFile(
        bytes: [7, 8, 9],
        fileName: 'safe.txt',
        vaultId: vault['id_boveda'] as String);
    final content = Map<String, dynamic>.from(encrypted['contenido_cifrado'] as Map);
    final download = {
      'id_archivo': encrypted['id_archivo'],
      'id_version_archivo': encrypted['id_version_archivo'],
      'tamano_cifrado': encrypted['tamano_cifrado'],
      'hash_cifrado': encrypted['hash_cifrado'],
      'algoritmo': content['algoritmo'],
      'nonce_iv': content['nonce'],
      'auth_tag': content['tag'],
      'ciphertext': content['ciphertext'],
      'clave_archivo_envuelta': encrypted['clave_archivo_envuelta'],
    };
    final plaintext = await crypto.decryptDownloadedFile(
        download, vault['id_boveda'] as String);
    expect(plaintext, [7, 8, 9]);
    plaintext.fillRange(0, plaintext.length, 0);

    final tampered = {...download, 'ciphertext': base64Encode([0, 1, 2])};
    await expectLater(
        crypto.decryptDownloadedFile(tampered, vault['id_boveda'] as String),
        throwsA(isA<FormatException>()));
    crypto.clearSessionKey();
  });

  test('CU20 creates an authenticated kit and rejects wrong or altered kits', () async {
    final crypto = VaultCryptoService();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final deviceId = VaultCryptoService.newId();
    final vault = await crypto.prepare(
        name: 'Emergency test',
        description: '',
        password: 'Original master password 2026!',
        deviceId: deviceId,
        deviceKey: deviceKey);
    await crypto.reopen(vault, 'Original master password 2026!', deviceKey);
    final kit = await crypto.createEmergencyKit(
        vault['id_boveda'] as String, vault['kdf_salt'] as String,
        'Emergency kit password 2026!');
    expect(jsonEncode(kit), isNot(contains('Emergency test')));
    expect(jsonEncode(kit), isNot(contains('Original master password')));

    final recovered = await crypto.prepareEmergencyRecovery(
        kit, vault, 'Emergency kit password 2026!', deviceId, deviceKey);
    expect(recovered['clave_envuelta'], isNotNull);
    await expectLater(
        crypto.prepareEmergencyRecovery(
            kit, vault, 'wrong kit password', deviceId, deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));

    final envelope = Map<String, dynamic>.from(kit['sobre_cifrado'] as Map);
    final ciphertext = base64Decode(envelope['ciphertext'] as String);
    ciphertext[0] ^= 1;
    envelope['ciphertext'] = base64Encode(ciphertext);
    await expectLater(
        crypto.prepareEmergencyRecovery(
            {...kit, 'sobre_cifrado': envelope}, vault,
            'Emergency kit password 2026!', deviceId, deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));
    crypto.clearSessionKey();
  }, timeout: const Timeout(Duration(minutes: 5)));
}
