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
    expect(metadata['nombre'], 'Investigación');
    expect(metadata['descripcion'], 'Datos ficticios');
    await expectLater(
        crypto.reopen(vault, 'Otra contraseña incorrecta', deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));
    await expectLater(
        crypto.reopen(vault, 'Contraseña maestra única 2026',
            VaultCryptoService.randomBytes(32)),
        throwsA(isA<SecretBoxAuthenticationError>()));
    final name = Map<String, dynamic>.from(vault['nombre_cifrado'] as Map);
    final bytes = base64Decode(name['ciphertext'] as String);
    bytes[0] ^= 1;
    name['ciphertext'] = base64Encode(bytes);
    await expectLater(
        crypto.reopen({...vault, 'nombre_cifrado': name},
            'Contraseña maestra única 2026', deviceKey),
        throwsA(isA<SecretBoxAuthenticationError>()));
  }, timeout: const Timeout(Duration(minutes: 5)));
}
