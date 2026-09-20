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

  test('CU07 rejects altered tag, nonce, AAD and unsupported versions',
      () async {
    final crypto = VaultCryptoService();
    final deviceId = VaultCryptoService.newId();
    final deviceKey = VaultCryptoService.randomBytes(32);
    final vault = await crypto.prepare(
      name: 'Bóveda',
      description: 'Metadatos',
      password: 'Master password CU07',
      deviceId: deviceId,
      deviceKey: deviceKey,
    );

    for (final field in <String>['tag', 'nonce']) {
      final altered = _copy(vault);
      final envelope =
          Map<String, dynamic>.from(altered['clave_envuelta'] as Map);
      final bytes = base64Decode(envelope[field] as String);
      bytes[0] ^= 1;
      envelope[field] = base64Encode(bytes);
      altered['clave_envuelta'] = envelope;
      await expectLater(
        crypto.reopen(
          altered,
          'Master password CU07',
          deviceKey,
          expectedDeviceId: deviceId,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    }

    final alteredAad = _copy(vault);
    alteredAad['id_boveda'] = VaultCryptoService.newId();
    await expectLater(
      crypto.reopen(
        alteredAad,
        'Master password CU07',
        deviceKey,
        expectedDeviceId: deviceId,
      ),
      throwsA(isA<SecretBoxAuthenticationError>()),
    );

    final futureVersion = _copy(vault);
    futureVersion['version_criptografica'] = 2;
    await expectLater(
      crypto.reopen(
        futureVersion,
        'Master password CU07',
        deviceKey,
        expectedDeviceId: deviceId,
      ),
      throwsA(isA<FormatException>()),
    );
    await expectLater(
      crypto.reopen(
        vault,
        'Master password CU07',
        deviceKey,
        expectedDeviceId: VaultCryptoService.newId(),
      ),
      throwsA(isA<FormatException>()),
    );
    deviceKey.fillRange(0, deviceKey.length, 0);
  }, timeout: const Timeout(Duration(minutes: 5)));
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    Map<String, dynamic>.from(jsonDecode(jsonEncode(value)) as Map);
