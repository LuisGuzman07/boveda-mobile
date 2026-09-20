import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boveda_mobile/services/vault_crypto_service.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

const _configPath = String.fromEnvironment('CU07_E2E_CONFIG');

void main() {
  test(
    'creates under CU06 then retrieves and unlocks a CU07 vault over real HTTP',
    skip: _configPath.isEmpty
        ? 'Requires the disposable CU07 E2E configuration.'
        : false,
    () async {
      final configFile = File(_configPath);
      final config = _jsonMap(await configFile.readAsString());
      final baseUrl = _requiredString(config, 'base_url');
      final nativeToken = _requiredString(config, 'native_token');
      final firstVaultToken = _requiredString(config, 'vault_token');
      final userId = _requiredString(config, 'user_id');
      final deviceId = _requiredString(config, 'device_id');
      final installationId = _requiredString(config, 'installation_id');
      final password = _requiredString(config, 'master_password');
      final name = _requiredString(config, 'vault_name');
      final description = _requiredString(config, 'vault_description');
      final installationSeed = Uint8List.fromList(
        base64Decode(_requiredString(config, 'installation_seed')),
      );
      final signingSeed = Uint8List.fromList(
        base64Decode(_requiredString(config, 'vault_signing_seed')),
      );
      final deviceKey = Uint8List.fromList(
        base64Decode(_requiredString(config, 'device_key')),
      );
      final installationKey = await Ed25519()
          .newKeyPairFromSeed(Uint8List.fromList(installationSeed));
      final signingKey =
          await Ed25519().newKeyPairFromSeed(Uint8List.fromList(signingSeed));
      final client = http.Client();
      final crypto = VaultCryptoService();

      try {
        // CU06 creates encrypted material but deliberately does not retain Kv.
        final createdBody = await crypto.prepare(
          name: name,
          description: description,
          password: password,
          deviceId: deviceId,
          deviceKey: deviceKey,
        );
        final created = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: firstVaultToken,
          method: 'POST',
          path: '/vaults',
          body: createdBody,
          retryKey: 'cu07-e2e-create-retry-0001',
        );
        expect(created.statusCode, 201);
        final createdVault = _jsonMap(created.body);
        expect(createdVault['id_boveda'], createdBody['id_boveda']);

        final listed = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: firstVaultToken,
          method: 'GET',
          path: '/vaults',
        );
        expect(listed.statusCode, 200);
        final listedItem =
            (_jsonMap(listed.body)['items'] as List).single as Map;
        expect(listedItem.containsKey('clave_envuelta'), isFalse);

        final closed = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: firstVaultToken,
          method: 'DELETE',
          path: '/vaults/session',
        );
        expect(closed.statusCode, 204);

        final secondVaultToken = await _openFreshVaultSession(
          client: client,
          baseUrl: baseUrl,
          nativeToken: nativeToken,
          userId: userId,
          deviceId: deviceId,
          installationId: installationId,
          installationKey: installationKey,
        );
        final active = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: secondVaultToken,
          method: 'GET',
          path: '/vaults/session',
        );
        expect(active.statusCode, 200);

        final retrieved = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: secondVaultToken,
          method: 'GET',
          path: '/vaults/${createdBody['id_boveda']}',
        );
        expect(retrieved.statusCode, 200);
        final retrievedVault = _jsonMap(retrieved.body);
        final recovered = await crypto.reopen(
          retrievedVault,
          password,
          deviceKey,
          expectedDeviceId: deviceId,
        );
        expect(recovered, <String, String>{
          'nombre': name,
          'descripcion': description,
        });

        await expectLater(
          crypto.reopen(
            retrievedVault,
            'incorrect password',
            deviceKey,
            expectedDeviceId: deviceId,
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        final alteredTag = _copy(retrievedVault);
        final envelope =
            Map<String, dynamic>.from(alteredTag['clave_envuelta'] as Map);
        final tag = base64Decode(envelope['tag'] as String);
        tag[0] ^= 1;
        envelope['tag'] = base64Encode(tag);
        alteredTag['clave_envuelta'] = envelope;
        await expectLater(
          crypto.reopen(
            alteredTag,
            password,
            deviceKey,
            expectedDeviceId: deviceId,
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );
        final alteredAad = _copy(retrievedVault);
        alteredAad['id_boveda'] = VaultCryptoService.newId();
        await expectLater(
          crypto.reopen(
            alteredAad,
            password,
            deviceKey,
            expectedDeviceId: deviceId,
          ),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );

        config['vault_id'] = createdBody['id_boveda'];
        config['cu07_flutter_complete'] = true;
        config['cu07_vault_token'] = secondVaultToken;
        await configFile.writeAsString(jsonEncode(config));
      } finally {
        installationSeed.fillRange(0, installationSeed.length, 0);
        signingSeed.fillRange(0, signingSeed.length, 0);
        deviceKey.fillRange(0, deviceKey.length, 0);
        installationKey.destroy();
        signingKey.destroy();
        client.close();
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

Future<String> _openFreshVaultSession({
  required http.Client client,
  required String baseUrl,
  required String nativeToken,
  required String userId,
  required String deviceId,
  required String installationId,
  required SimpleKeyPair installationKey,
}) async {
  final challengeResponse = await client.post(
    Uri.parse('$baseUrl/devices/challenge'),
    headers: <String, String>{
      'Authorization': 'Bearer $nativeToken',
      'Content-Type': 'application/json',
      'X-Device-Id': installationId,
    },
    body: jsonEncode(<String, String>{'proposito': 'VAULT_SESSION'}),
  );
  expect(challengeResponse.statusCode, 200);
  final challenge = _jsonMap(challengeResponse.body);
  final challengeId = _requiredString(challenge, 'id_desafio');
  final nonce = _requiredString(challenge, 'nonce');
  final expiry = DateTime.parse(_requiredString(challenge, 'fecha_expiracion'));
  final transcript = <String>[
    'boveda-device-challenge-v1',
    challengeId,
    'VAULT_SESSION',
    userId,
    deviceId,
    nonce,
    '${expiry.millisecondsSinceEpoch ~/ 1000}',
  ].join('\n');
  final proof = await Ed25519().sign(
    utf8.encode(transcript),
    keyPair: installationKey,
  );
  final response = await client.post(
    Uri.parse('$baseUrl/vaults/session'),
    headers: <String, String>{
      'Authorization': 'Bearer $nativeToken',
      'Content-Type': 'application/json',
      'X-Device-Id': installationId,
    },
    body: jsonEncode(<String, String>{
      'id_desafio': challengeId,
      'nonce': nonce,
      'firma': base64Encode(proof.bytes),
    }),
  );
  expect(response.statusCode, 200);
  return _requiredString(_jsonMap(response.body), 'access_token');
}

Future<http.Response> _signedRequest({
  required http.Client client,
  required SimpleKeyPair signingKey,
  required String baseUrl,
  required String vaultToken,
  required String method,
  required String path,
  Map<String, dynamic>? body,
  String? retryKey,
}) async {
  final text = body == null ? '' : jsonEncode(body);
  final uri = Uri.parse('$baseUrl$path');
  final payload = _jsonMap(
    utf8.decode(
      base64Url.decode(base64Url.normalize(vaultToken.split('.')[1])),
    ),
  );
  final timestamp = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
  final message = <String>[
    _requiredString(payload, 'jti'),
    timestamp,
    method,
    uri.path,
    retryKey ?? '',
    hashes.sha256.convert(utf8.encode(text)).toString(),
  ].join('\n');
  final signature =
      await Ed25519().sign(utf8.encode(message), keyPair: signingKey);
  final request = http.Request(method, uri)
    ..headers.addAll(<String, String>{
      'Authorization': 'Bearer $vaultToken',
      'Content-Type': 'application/json',
      'X-Vault-Timestamp': timestamp,
      'X-Vault-Signature': base64Encode(signature.bytes),
      if (retryKey != null) 'Idempotency-Key': retryKey,
    })
    ..body = text;
  return http.Response.fromStream(
    await client.send(request).timeout(const Duration(seconds: 20)),
  );
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    _jsonMap(jsonEncode(value));

Map<String, dynamic> _jsonMap(String value) {
  final decoded = jsonDecode(value);
  if (decoded is! Map) {
    throw const FormatException('Expected a JSON object.');
  }
  return Map<String, dynamic>.from(decoded);
}

String _requiredString(Map<String, dynamic> values, String key) {
  final value = values[key];
  if (value is! String || value.isEmpty) {
    throw StateError('Missing $key in the E2E configuration.');
  }
  return value;
}
