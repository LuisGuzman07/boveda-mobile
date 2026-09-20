import 'dart:convert';

import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:boveda_mobile/services/device_identity_api_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'helpers/lock_fakes.dart';

void main() {
  test('builds a login payload with distinct installation and vault keys',
      () async {
    final gateway = FakeLocalAuthenticationGateway();
    final lock = AppLockService(authenticator: gateway);
    addTearDown(lock.dispose);
    await lock.unlock();
    final identity = FakeInstallationIdentityProvider();
    final service = DeviceIdentityApiService(
      identity: identity,
      lockService: lock,
      baseUrl: 'https://api.example.test/api/v1',
    );

    final payload = await service.loginDevicePayload(
      vaultPublicKey: 'vault-signing-public-key',
    );

    expect(payload['nombre'], 'Bóveda móvil');
    expect(payload['tipo'], 'MOVIL');
    expect(payload['sistema_operativo'], isNotEmpty);
    expect(payload['identificador_seguro'], identity.identity.installationId);
    expect(payload['public_key'], identity.identity.publicKey);
    expect(payload['vault_public_key'], 'vault-signing-public-key');
    await expectLater(
      service.loginDevicePayload(vaultPublicKey: identity.identity.publicKey),
      throwsA(isA<DeviceIdentityApiException>()),
    );
  });

  test('proves enrollment with native session claims and installation identity',
      () async {
    final gateway = FakeLocalAuthenticationGateway();
    final lock = AppLockService(authenticator: gateway);
    addTearDown(lock.dispose);
    await lock.unlock();
    final identity = FakeInstallationIdentityProvider();
    final requests = <http.Request>[];
    final client = MockClient((request) async {
      requests.add(request);
      if (requests.length == 1) {
        return http.Response(
          jsonEncode(<String, dynamic>{
            'id_desafio': '44444444-4444-4444-8444-444444444444',
            'nonce': 'backend-nonce',
            'proposito': 'DEVICE_ENROLLMENT',
            'fecha_expiracion': '2026-01-01T12:02:00Z',
          }),
          200,
        );
      }
      return http.Response('{}', 200);
    });
    final service = DeviceIdentityApiService(
      identity: identity,
      lockService: lock,
      client: client,
      baseUrl: 'https://api.example.test/api/v1',
    );

    await service.enrollAndProve(accessToken: _nativeAccessToken());

    expect(requests, hasLength(2));
    expect(requests[0].url.path, '/api/v1/devices/challenge');
    expect(requests[1].url.path, '/api/v1/devices/challenge/prove');
    expect(requests[0].headers['authorization'], startsWith('Bearer '));
    expect(
        requests[0].headers['x-device-id'], identity.identity.installationId);
    expect(jsonDecode(requests[0].body), <String, dynamic>{
      'proposito': 'DEVICE_ENROLLMENT',
    });
    expect(jsonDecode(requests[1].body), <String, dynamic>{
      'id_desafio': '44444444-4444-4444-8444-444444444444',
      'nonce': 'backend-nonce',
      'firma': 'test-signature',
    });
    expect(identity.signedChallenge?['userId'],
        '33333333-3333-4333-8333-333333333333');
    expect(identity.signedChallenge?['deviceId'],
        '22222222-2222-4222-8222-222222222222');
  });

  test('returns a vault-session proof without submitting it as enrollment',
      () async {
    final gateway = FakeLocalAuthenticationGateway();
    final lock = AppLockService(authenticator: gateway);
    addTearDown(lock.dispose);
    await lock.unlock();
    final identity = FakeInstallationIdentityProvider();
    final requests = <http.Request>[];
    final client = MockClient((request) async {
      requests.add(request);
      return http.Response(
        jsonEncode(<String, dynamic>{
          'id_desafio': '55555555-5555-4555-8555-555555555555',
          'nonce': 'vault-nonce',
          'proposito': 'VAULT_SESSION',
          'fecha_expiracion': '2026-01-01T12:02:00Z',
        }),
        200,
      );
    });
    final service = DeviceIdentityApiService(
      identity: identity,
      lockService: lock,
      client: client,
      baseUrl: 'https://api.example.test/api/v1',
    );

    final proof = await service.vaultSessionProof(
      accessToken: _nativeAccessToken(),
    );

    expect(requests, hasLength(1));
    expect(jsonDecode(requests.single.body), <String, dynamic>{
      'proposito': 'VAULT_SESSION',
    });
    expect(proof.installationId, identity.identity.installationId);
    expect(proof.requestBody, <String, dynamic>{
      'id_desafio': '55555555-5555-4555-8555-555555555555',
      'nonce': 'vault-nonce',
      'firma': 'test-signature',
    });
  });

  test('does not call the backend while the app is locked', () async {
    final client = MockClient((_) async => http.Response('{}', 200));
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    addTearDown(lock.dispose);
    final service = DeviceIdentityApiService(
      identity: FakeInstallationIdentityProvider(),
      lockService: lock,
      client: client,
      baseUrl: 'https://api.example.test/api/v1',
    );

    await expectLater(
      service.deviceRegistrationPayload(),
      throwsA(isA<DeviceIdentityApiException>()),
    );
  });
}

String _nativeAccessToken() {
  final header = base64Url
      .encode(utf8.encode(jsonEncode(<String, dynamic>{'alg': 'none'})))
      .replaceAll('=', '');
  final payload = base64Url
      .encode(utf8.encode(jsonEncode(<String, dynamic>{
        'sub': '33333333-3333-4333-8333-333333333333',
        'did': '22222222-2222-4222-8222-222222222222',
      })))
      .replaceAll('=', '');
  return '$header.$payload.signature';
}
