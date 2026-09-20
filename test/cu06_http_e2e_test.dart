import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boveda_mobile/services/vault_crypto_service.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

const _configPath = String.fromEnvironment('CU06_E2E_CONFIG');

void main() {
  test(
    'creates, retrieves and decrypts a CU06 vault over real HTTP',
    skip: _configPath.isEmpty
        ? 'Requires the disposable CU06 E2E configuration.'
        : false,
    () async {
      final configFile = File(_configPath);
      final config = _jsonMap(await configFile.readAsString());
      final baseUrl = _requiredString(config, 'base_url');
      final vaultToken = _requiredString(config, 'vault_token');
      final deviceId = _requiredString(config, 'device_id');
      final password = _requiredString(config, 'master_password');
      final name = _requiredString(config, 'vault_name');
      final description = _requiredString(config, 'vault_description');
      final signingSeed = Uint8List.fromList(
        base64Decode(_requiredString(config, 'vault_signing_seed')),
      );
      final deviceKey = Uint8List.fromList(
        base64Decode(_requiredString(config, 'device_key')),
      );
      final otherDeviceKey = Uint8List.fromList(
        base64Decode(_requiredString(config, 'other_device_key')),
      );
      final signingKey =
          await Ed25519().newKeyPairFromSeed(Uint8List.fromList(signingSeed));
      final client = http.Client();
      final crypto = VaultCryptoService();

      try {
        final body = await crypto.prepare(
          name: name,
          description: description,
          password: password,
          deviceId: deviceId,
          deviceKey: deviceKey,
        );
        expect(body['kdf_parametros'], VaultCryptoService.kdfParameters);
        expect(
          (body['clave_envuelta'] as Map)['id_dispositivo'],
          deviceId,
        );
        final serialized = jsonEncode(body);
        expect(serialized, isNot(contains(name)));
        expect(serialized, isNot(contains(password)));

        const retryKey = 'cu06-e2e-flutter-retry-0001';
        final created = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'POST',
          path: '/vaults',
          body: body,
          retryKey: retryKey,
        );
        expect(created.statusCode, 201);
        final createdVault = _jsonMap(created.body);

        final retried = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'POST',
          path: '/vaults',
          body: body,
          retryKey: retryKey,
        );
        expect(retried.statusCode, 201);
        expect(_jsonMap(retried.body), createdVault);

        final listed = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'GET',
          path: '/vaults',
        );
        expect(listed.statusCode, 200);
        final items = (_jsonMap(listed.body)['items'] as List)
            .map((item) => Map<String, dynamic>.from(item as Map))
            .toList();
        expect(items, hasLength(1));
        expect(items.single['id_boveda'], body['id_boveda']);

        final retrieved = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'GET',
          path: '/vaults/${body['id_boveda']}',
        );
        expect(retrieved.statusCode, 200);
        final retrievedVault = _jsonMap(retrieved.body);
        final recovered = await crypto.reopen(retrievedVault, password, deviceKey);
        expect(recovered, <String, String>{
          'nombre': name,
          'descripcion': description,
        });
        await expectLater(
          crypto.reopen(retrievedVault, password, otherDeviceKey),
          throwsA(isA<SecretBoxAuthenticationError>()),
        );

        final malformed = _jsonMap(jsonEncode(body));
        malformed['id_boveda'] = VaultCryptoService.newId();
        final malformedName =
            Map<String, dynamic>.from(malformed['nombre_cifrado'] as Map);
        malformedName['nonce'] = base64Encode(Uint8List(8));
        malformed['nombre_cifrado'] = malformedName;
        final rejected = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'POST',
          path: '/vaults',
          body: malformed,
          retryKey: 'cu06-e2e-flutter-invalid-envelope-0001',
        );
        expect(rejected.statusCode, 422);

        config['vault_id'] = createdVault['id_boveda'];
        config['flutter_e2e_complete'] = true;
        await configFile.writeAsString(jsonEncode(config));
      } finally {
        signingSeed.fillRange(0, signingSeed.length, 0);
        deviceKey.fillRange(0, deviceKey.length, 0);
        otherDeviceKey.fillRange(0, otherDeviceKey.length, 0);
        signingKey.destroy();
        client.close();
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
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
  final signature = await Ed25519().sign(utf8.encode(message), keyPair: signingKey);
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
