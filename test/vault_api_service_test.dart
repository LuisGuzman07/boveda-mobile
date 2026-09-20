import 'dart:convert';

import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:boveda_mobile/services/installation_identity_service.dart';
import 'package:boveda_mobile/services/vault_api_service.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'helpers/lock_fakes.dart';

void main() {
  test(
      'uses installation identity for native challenges and CU06 key for vault requests',
      () async {
    const email = 'vault@example.test';
    const installationId = '11111111-1111-4111-8111-111111111111';
    final installationPublicKey = base64Encode(List<int>.filled(32, 7));
    final cu06Seed = base64Encode(List<int>.generate(32, (index) => index));
    final scope = hashes.sha256.convert(utf8.encode(email)).toString();
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'cu06_signing_$scope': cu06Seed,
    });
    final expectedSigningKey =
        await Ed25519().newKeyPairFromSeed(base64Decode(cu06Seed));
    final expectedVaultPublicKey = await expectedSigningKey.extractPublicKey();
    addTearDown(expectedSigningKey.destroy);

    final identity = FakeInstallationIdentityProvider(
      identity: InstallationIdentity(
        installationId: installationId,
        publicKey: installationPublicKey,
      ),
    );
    final nativeAccessToken = _token(<String, dynamic>{
      'sub': '33333333-3333-4333-8333-333333333333',
      'did': '22222222-2222-4222-8222-222222222222',
    });
    final vaultAccessToken = _token(<String, dynamic>{'jti': 'vault-jti'});
    final requests = <http.Request>[];
    final client = MockClient((request) async {
      requests.add(request);
      switch (requests.length) {
        case 1:
          return _response(<String, dynamic>{
            'mfa_required': true,
            'mfa_token': 'mfa-token',
          });
        case 2:
          return _response(<String, dynamic>{
            'access_token': nativeAccessToken,
            'refresh_token': 'refresh-token',
          });
        case 3:
          return _challengeResponse(
            id: '44444444-4444-4444-8444-444444444444',
            nonce: 'enrollment-nonce',
            purpose: 'DEVICE_ENROLLMENT',
          );
        case 4:
          return _response(<String, dynamic>{});
        case 5:
          return _challengeResponse(
            id: '55555555-5555-4555-8555-555555555555',
            nonce: 'vault-nonce',
            purpose: 'VAULT_SESSION',
          );
        case 6:
          return _response(<String, dynamic>{
            'access_token': vaultAccessToken,
            'id_dispositivo': '22222222-2222-4222-8222-222222222222',
            'id_usuario': '33333333-3333-4333-8333-333333333333',
          });
        case 7:
          return _response(<String, dynamic>{'items': <dynamic>[]});
        case 8:
          return http.Response('', 204);
        default:
          throw StateError('Solicitud inesperada: ${request.url}');
      }
    });
    final service = VaultApiService(
      baseUrl: 'https://api.example.test/api/v1',
      client: client,
      installationIdentity: identity,
    );

    await service.login(email, 'Account-password-1!', '123456');
    await service.listVaults();
    await service.revokeSession();

    expect(requests, hasLength(8));
    expect(requests[0].url.path, '/api/v1/auth/login');
    final login =
        Map<String, dynamic>.from(jsonDecode(requests[0].body) as Map);
    final device = Map<String, dynamic>.from(login['dispositivo'] as Map);
    expect(device['identificador_seguro'], installationId);
    expect(device['public_key'], installationPublicKey);
    expect(
      device['vault_public_key'],
      base64Encode(expectedVaultPublicKey.bytes),
    );
    expect(device['vault_public_key'], isNot(installationPublicKey));
    expect(login.containsKey('confiar_dispositivo'), isFalse);

    expect(requests[1].url.path, '/api/v1/auth/mfa/verify-login');
    expect(jsonDecode(requests[1].body), <String, dynamic>{
      'mfa_token': 'mfa-token',
      'code': '123456',
    });

    expect(requests[2].url.path, '/api/v1/devices/challenge');
    expect(requests[2].headers['authorization'], 'Bearer $nativeAccessToken');
    expect(requests[2].headers['x-device-id'], installationId);
    expect(jsonDecode(requests[2].body), <String, dynamic>{
      'proposito': 'DEVICE_ENROLLMENT',
    });
    expect(requests[3].url.path, '/api/v1/devices/challenge/prove');
    expect(requests[3].headers['x-device-id'], installationId);
    expect(jsonDecode(requests[3].body), <String, dynamic>{
      'id_desafio': '44444444-4444-4444-8444-444444444444',
      'nonce': 'enrollment-nonce',
      'firma': 'test-signature',
    });

    expect(requests[4].url.path, '/api/v1/devices/challenge');
    expect(requests[4].headers['x-device-id'], installationId);
    expect(jsonDecode(requests[4].body), <String, dynamic>{
      'proposito': 'VAULT_SESSION',
    });
    expect(requests[5].url.path, '/api/v1/vaults/session');
    expect(requests[5].headers['authorization'], 'Bearer $nativeAccessToken');
    expect(requests[5].headers['x-device-id'], installationId);
    expect(jsonDecode(requests[5].body), <String, dynamic>{
      'id_desafio': '55555555-5555-4555-8555-555555555555',
      'nonce': 'vault-nonce',
      'firma': 'test-signature',
    });

    expect(requests[6].url.path, '/api/v1/vaults');
    expect(requests[6].headers['authorization'], 'Bearer $vaultAccessToken');
    final timestamp = requests[6].headers['x-vault-timestamp'];
    final signature = requests[6].headers['x-vault-signature'];
    expect(timestamp, isNotNull);
    expect(signature, isNotNull);
    final message = <String>[
      'vault-jti',
      timestamp!,
      'GET',
      '/api/v1/vaults',
      '',
      hashes.sha256.convert(utf8.encode('')).toString(),
    ].join('\n');
    final verifiedWithCu06Key = await Ed25519().verify(
      utf8.encode(message),
      signature: Signature(
        base64Decode(signature!),
        publicKey: expectedVaultPublicKey,
      ),
    );
    final verifiedWithInstallationKey = await Ed25519().verify(
      utf8.encode(message),
      signature: Signature(
        base64Decode(signature),
        publicKey: SimplePublicKey(
          base64Decode(installationPublicKey),
          type: KeyPairType.ed25519,
        ),
      ),
    );
    expect(verifiedWithCu06Key, isTrue);
    expect(verifiedWithInstallationKey, isFalse);
    expect(requests[7].method, 'DELETE');
    expect(requests[7].url.path, '/api/v1/vaults/session');
    expect(requests[7].headers['authorization'], 'Bearer $vaultAccessToken');
    expect(service.authenticated, isFalse);
  });

  test('locks and removes vault-only data when remote revalidation is denied',
      () async {
    const email = 'revoked@example.test';
    const userId = '33333333-3333-4333-8333-333333333333';
    const deviceId = '22222222-2222-4222-8222-222222222222';
    final scope = hashes.sha256.convert(utf8.encode(email)).toString();
    final signingSeed = base64Encode(List<int>.filled(32, 9));
    const storage = FlutterSecureStorage();
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'cu06_signing_$scope': signingSeed,
      InstallationIdentityService.secureInstallationIdKey: 'installation-id',
      InstallationIdentityService.privateSeedKey: 'installation-seed',
      InstallationIdentityService.identityVersionKey: '1',
      'boveda_authenticator_accounts_v1': 'preserve-totp-record',
    });
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    addTearDown(lock.dispose);
    await unlockAppLock(lock);
    final nativeAccessToken = _token(<String, dynamic>{
      'sub': userId,
      'did': deviceId,
    });
    final vaultAccessToken = _token(<String, dynamic>{'jti': 'revoked-jti'});
    final requests = <http.Request>[];
    final client = MockClient((request) async {
      requests.add(request);
      switch (requests.length) {
        case 1:
          return _response(<String, dynamic>{
            'access_token': nativeAccessToken,
          });
        case 2:
          return _challengeResponse(
            id: '44444444-4444-4444-8444-444444444444',
            nonce: 'enrollment-nonce',
            purpose: 'DEVICE_ENROLLMENT',
          );
        case 3:
          return _response(<String, dynamic>{});
        case 4:
          return _challengeResponse(
            id: '55555555-5555-4555-8555-555555555555',
            nonce: 'vault-nonce',
            purpose: 'VAULT_SESSION',
          );
        case 5:
          return _response(<String, dynamic>{
            'access_token': vaultAccessToken,
            'id_dispositivo': deviceId,
            'id_usuario': userId,
          });
        case 6:
          return http.Response(
            jsonEncode(<String, dynamic>{'detail': 'Sesión revocada.'}),
            403,
          );
        default:
          throw StateError('Solicitud inesperada: ${request.url}');
      }
    });
    final service = VaultApiService(
      storage: storage,
      baseUrl: 'https://api.example.test/api/v1',
      client: client,
      lockService: lock,
      installationIdentity: FakeInstallationIdentityProvider(),
    );

    await service.login(email, 'Account-password-1!', '123456');
    await service.deviceKey();
    await service
        .savePending(<String, dynamic>{'body': 'pending'}, 'retry-key');
    await expectLater(
      service.revalidateSession(),
      throwsA(isA<VaultApiException>()),
    );

    expect(requests[5].url.path, '/api/v1/vaults');
    expect(lock.isLocked, isTrue);
    expect(service.authenticated, isFalse);
    expect(await storage.read(key: 'cu06_signing_$scope'), isNull);
    expect(await storage.read(key: 'cu06_wrapping_$userId'), isNull);
    expect(await storage.read(key: 'cu06_pending_$userId'), isNull);
    expect(
      await storage.read(
          key: InstallationIdentityService.secureInstallationIdKey),
      'installation-id',
    );
    expect(
      await storage.read(key: InstallationIdentityService.privateSeedKey),
      'installation-seed',
    );
    expect(
      await storage.read(key: 'boveda_authenticator_accounts_v1'),
      'preserve-totp-record',
    );
  });

  test('locks and removes vault material when device enrollment is denied',
      () async {
    const email = 'device-revoked@example.test';
    final scope = hashes.sha256.convert(utf8.encode(email)).toString();
    const storage = FlutterSecureStorage();
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'cu06_signing_$scope': base64Encode(List<int>.filled(32, 4)),
      InstallationIdentityService.secureInstallationIdKey: 'installation-id',
      InstallationIdentityService.privateSeedKey: 'installation-seed',
      InstallationIdentityService.identityVersionKey: '1',
      'boveda_authenticator_accounts_v1': 'preserve-totp-record',
    });
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    addTearDown(lock.dispose);
    await unlockAppLock(lock);
    final nativeAccessToken = _token(<String, dynamic>{
      'sub': '33333333-3333-4333-8333-333333333333',
      'did': '22222222-2222-4222-8222-222222222222',
    });
    final requests = <http.Request>[];
    final client = MockClient((request) async {
      requests.add(request);
      if (requests.length == 1) {
        return _response(<String, dynamic>{
          'access_token': nativeAccessToken,
        });
      }
      return http.Response(
        jsonEncode(<String, dynamic>{'detail': 'Dispositivo revocado.'}),
        401,
      );
    });
    final service = VaultApiService(
      storage: storage,
      baseUrl: 'https://api.example.test/api/v1',
      client: client,
      lockService: lock,
      installationIdentity: FakeInstallationIdentityProvider(),
    );

    await expectLater(
      service.login(email, 'Account-password-1!', '123456'),
      throwsA(isA<VaultApiException>()),
    );

    expect(requests, hasLength(2));
    expect(requests[1].url.path, '/api/v1/devices/challenge');
    expect(lock.isLocked, isTrue);
    expect(await storage.read(key: 'cu06_signing_$scope'), isNull);
    expect(
      await storage.read(
          key: InstallationIdentityService.secureInstallationIdKey),
      'installation-id',
    );
    expect(
      await storage.read(key: InstallationIdentityService.privateSeedKey),
      'installation-seed',
    );
    expect(
      await storage.read(key: 'boveda_authenticator_accounts_v1'),
      'preserve-totp-record',
    );
  });
}

http.Response _response(Map<String, dynamic> body) =>
    http.Response(jsonEncode(body), 200);

http.Response _challengeResponse({
  required String id,
  required String nonce,
  required String purpose,
}) =>
    _response(<String, dynamic>{
      'id_desafio': id,
      'nonce': nonce,
      'proposito': purpose,
      'fecha_expiracion': '2026-01-01T12:02:00Z',
    });

String _token(Map<String, dynamic> payload) {
  final header = base64Url
      .encode(utf8.encode(jsonEncode(<String, dynamic>{'alg': 'none'})))
      .replaceAll('=', '');
  final encodedPayload =
      base64Url.encode(utf8.encode(jsonEncode(payload))).replaceAll('=', '');
  return '$header.$encodedPayload.signature';
}
