import 'dart:convert';

import 'package:boveda_mobile/services/installation_identity_service.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

class MemorySecureInstallationIdentityStore
    implements SecureInstallationIdentityStore {
  final Map<String, String> values = <String, String>{};

  @override
  Future<void> delete(String key) async {
    values.remove(key);
  }

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async {
    values[key] = value;
  }
}

class MemoryInstallationIdentityStateStore
    implements InstallationIdentityStateStore {
  bool? initialized;

  @override
  Future<bool?> isInitialized() async => initialized;

  @override
  Future<void> markInitialized() async {
    initialized = true;
  }
}

void main() {
  InstallationIdentityService serviceFor(
    MemorySecureInstallationIdentityStore secure,
    MemoryInstallationIdentityStateStore state,
  ) =>
      InstallationIdentityService(secureStore: secure, stateStore: state);

  test('creates stable secure installation identity and signs challenge',
      () async {
    final secure = MemorySecureInstallationIdentityStore();
    final state = MemoryInstallationIdentityStateStore();
    final service = serviceFor(secure, state);

    final identity = await service.loadOrCreate();
    final secondRead = await service.loadOrCreate();
    final signature = await service.signChallenge(
      challengeId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      purpose: 'DEVICE_ENROLLMENT',
      userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      deviceId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      nonce: 'nonce-value',
      expiresAt: DateTime.utc(2026, 1, 1, 12, 2),
    );

    expect(identity.installationId, secondRead.installationId);
    expect(identity.publicKey, secondRead.publicKey);
    expect(state.initialized, isTrue);
    expect(
        secure.values[InstallationIdentityService.privateSeedKey], isNotNull);
    expect(secure.values.containsValue(identity.publicKey), isFalse);

    final transcript = utf8.encode(<String>[
      'boveda-device-challenge-v1',
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'DEVICE_ENROLLMENT',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      'nonce-value',
      '${DateTime.utc(2026, 1, 1, 12, 2).millisecondsSinceEpoch ~/ 1000}',
    ].join('\n'));
    final verified = await Ed25519().verify(
      transcript,
      signature: Signature(
        base64Decode(signature),
        publicKey: SimplePublicKey(
          base64Decode(identity.publicKey),
          type: KeyPairType.ed25519,
        ),
      ),
    );
    expect(verified, isTrue);
  });

  test('does not silently replace a missing private identity', () async {
    final secure = MemorySecureInstallationIdentityStore();
    final state = MemoryInstallationIdentityStateStore();
    final service = serviceFor(secure, state);
    final identity = await service.loadOrCreate();
    secure.values.remove(InstallationIdentityService.privateSeedKey);

    await expectLater(
      service.loadOrCreate(),
      throwsA(isA<InstallationIdentityException>()),
    );

    expect(
      secure.values[InstallationIdentityService.secureInstallationIdKey],
      identity.installationId,
    );
    expect(
        secure.values.containsKey(InstallationIdentityService.privateSeedKey),
        isFalse);
  });

  test('does not silently replace a corrupt private identity', () async {
    final secure = MemorySecureInstallationIdentityStore();
    final state = MemoryInstallationIdentityStateStore();
    final service = serviceFor(secure, state);
    await service.loadOrCreate();
    secure.values[InstallationIdentityService.privateSeedKey] = 'not-base64';

    await expectLater(
      service.loadOrCreate(),
      throwsA(isA<InstallationIdentityException>()),
    );
    expect(
      secure.values[InstallationIdentityService.privateSeedKey],
      'not-base64',
    );
  });

  test('only explicit recovery creates a replacement identity', () async {
    final secure = MemorySecureInstallationIdentityStore();
    final state = MemoryInstallationIdentityStateStore();
    final service = serviceFor(secure, state);
    final original = await service.loadOrCreate();
    secure.values.remove(InstallationIdentityService.privateSeedKey);

    final recovered = await service.recover();

    expect(recovered.installationId, isNot(original.installationId));
    expect(
        secure.values[InstallationIdentityService.privateSeedKey], isNotNull);
    expect(state.initialized, isTrue);
  });
}
