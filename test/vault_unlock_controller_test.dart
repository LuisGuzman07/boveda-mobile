import 'dart:async';
import 'dart:convert';

import 'package:boveda_mobile/features/vault_unlock/data/vault_envelope_repository.dart';
import 'package:boveda_mobile/features/vault_unlock/domain/unlock_attempt_policy.dart';
import 'package:boveda_mobile/features/vault_unlock/domain/vault_unlock_session.dart';
import 'package:boveda_mobile/features/vault_unlock/presentation/vault_unlock_controller.dart';
import 'package:boveda_mobile/services/vault_crypto_service.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _Clock {
  _Clock(this.now);

  DateTime now;

  DateTime call() => now;
}

class _FakeVaultEnvelopeRepository implements VaultEnvelopeRepository {
  _FakeVaultEnvelopeRepository({
    required this.vault,
    required this.deviceId,
    required this.deviceKey,
  });

  Map<String, dynamic> vault;
  @override
  final String deviceId;
  final Uint8List deviceKey;
  final listeners = <VoidCallback>{};
  VaultEnvelopeFailure? failure;
  Object? unexpectedError;
  Completer<void>? validationCompleter;
  Uint8List? lastIssuedDeviceKey;
  bool invalidated = false;

  @override
  void addInvalidationListener(VoidCallback listener) =>
      listeners.add(listener);

  @override
  Future<Map<String, dynamic>> fetchAuthorizedVault(String vaultId) async {
    _throwFailure();
    return _copy(vault);
  }

  @override
  Future<void> invalidateRemoteSession() async {
    invalidated = true;
    for (final listener in List<VoidCallback>.from(listeners)) {
      listener();
    }
  }

  @override
  Future<Uint8List> loadDeviceKey() async {
    _throwFailure();
    return lastIssuedDeviceKey = Uint8List.fromList(deviceKey);
  }

  @override
  void removeInvalidationListener(VoidCallback listener) =>
      listeners.remove(listener);

  @override
  Future<void> validateRemoteSession() async {
    final completer = validationCompleter;
    if (completer != null) {
      await completer.future;
    }
    _throwFailure();
  }

  void emitRemoteInvalidation() {
    for (final listener in List<VoidCallback>.from(listeners)) {
      listener();
    }
  }

  void _throwFailure() {
    final unexpected = unexpectedError;
    if (unexpected != null) {
      throw unexpected;
    }
    final value = failure;
    if (value != null) {
      throw VaultEnvelopeException(value);
    }
  }
}

class _Fixture {
  const _Fixture(
      {required this.vault, required this.deviceId, required this.deviceKey});

  final Map<String, dynamic> vault;
  final String deviceId;
  final Uint8List deviceKey;
}

Future<_Fixture> _fixture() async {
  final crypto = VaultCryptoService();
  const deviceId = '11111111-1111-4111-8111-111111111111';
  final deviceKey = VaultCryptoService.randomBytes(32);
  final vault = await crypto.prepare(
    name: 'Bóveda de pruebas',
    description: 'Solo metadatos cifrados',
    password: 'Master password for CU07 tests',
    deviceId: deviceId,
    deviceKey: deviceKey,
  );
  return _Fixture(vault: vault, deviceId: deviceId, deviceKey: deviceKey);
}

VaultUnlockController _controller({
  required _FakeVaultEnvelopeRepository repository,
  _Clock? clock,
  VaultUnlockSession? session,
  UnlockAttemptPolicy? policy,
}) {
  final controller = VaultUnlockController(
    repository: repository,
    clock: clock?.call,
    session: session,
    attemptPolicy: policy,
  );
  controller.selectVault(repository.vault['id_boveda'] as String);
  return controller;
}

Map<String, dynamic> _copy(Map<String, dynamic> value) =>
    Map<String, dynamic>.from(jsonDecode(jsonEncode(value)) as Map);

void main() {
  test('unlocks only in memory and clears the device-key copy after use',
      () async {
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final fixture = await _fixture();
    final repository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    );
    final controller = _controller(repository: repository);
    addTearDown(controller.dispose);

    expect(await controller.unlock('Master password for CU07 tests'), isTrue);
    expect(controller.isUnlocked, isTrue);
    expect(controller.vaultName, 'Bóveda de pruebas');
    expect(controller.vaultDescription, 'Solo metadatos cifrados');
    expect(controller.session.hasInMemoryKey, isTrue);
    expect(
      repository.lastIssuedDeviceKey!.every((value) => value == 0),
      isTrue,
    );

    const storage = FlutterSecureStorage();
    expect(await storage.readAll(), isEmpty);
    expect((await SharedPreferences.getInstance()).getKeys(), isEmpty);

    controller.lock();
    expect(controller.isUnlocked, isFalse);
    expect(controller.vaultName, isNull);
    expect(controller.session.hasInMemoryKey, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('returns the same safe message for bad password and altered ciphertext',
      () async {
    final fixture = await _fixture();
    final wrongRepository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    );
    final wrongController = _controller(repository: wrongRepository);
    addTearDown(wrongController.dispose);

    expect(await wrongController.unlock('wrong password'), isFalse);
    expect(
        wrongController.failure, VaultUnlockFailure.cryptographicVerification);
    expect(
      wrongController.failure!.userMessage,
      'No fue posible desbloquear la bóveda. Verifica tus credenciales e inténtalo nuevamente.',
    );

    final altered = _copy(fixture.vault);
    final envelope =
        Map<String, dynamic>.from(altered['clave_envuelta'] as Map);
    final ciphertext = base64Decode(envelope['ciphertext'] as String);
    ciphertext[0] ^= 1;
    envelope['ciphertext'] = base64Encode(ciphertext);
    altered['clave_envuelta'] = envelope;
    final alteredRepository = _FakeVaultEnvelopeRepository(
      vault: altered,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    );
    final alteredController = _controller(repository: alteredRepository);
    addTearDown(alteredController.dispose);

    expect(
      await alteredController.unlock('Master password for CU07 tests'),
      isFalse,
    );
    expect(alteredController.failure,
        VaultUnlockFailure.cryptographicVerification);
    expect(
      alteredController.failure!.userMessage,
      wrongController.failure!.userMessage,
    );
  }, timeout: const Timeout(Duration(minutes: 5)));

  test(
      'rejects another-device envelopes and unsupported crypto versions locally',
      () async {
    final fixture = await _fixture();
    final otherDevice = _copy(fixture.vault);
    final envelope =
        Map<String, dynamic>.from(otherDevice['clave_envuelta'] as Map);
    envelope['id_dispositivo'] = '22222222-2222-4222-8222-222222222222';
    otherDevice['clave_envuelta'] = envelope;
    final deviceController = _controller(
      repository: _FakeVaultEnvelopeRepository(
        vault: otherDevice,
        deviceId: fixture.deviceId,
        deviceKey: fixture.deviceKey,
      ),
    );
    addTearDown(deviceController.dispose);
    expect(
      await deviceController.unlock('Master password for CU07 tests'),
      isFalse,
    );
    expect(deviceController.failure, VaultUnlockFailure.envelopeIncompatible);

    final futureVersion = _copy(fixture.vault);
    futureVersion['version_criptografica'] = 2;
    final versionController = _controller(
      repository: _FakeVaultEnvelopeRepository(
        vault: futureVersion,
        deviceId: fixture.deviceId,
        deviceKey: fixture.deviceKey,
      ),
    );
    addTearDown(versionController.dispose);
    expect(
      await versionController.unlock('Master password for CU07 tests'),
      isFalse,
    );
    expect(versionController.failure, VaultUnlockFailure.envelopeIncompatible);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('maps remote authorization failures without opening local state',
      () async {
    final fixture = await _fixture();
    final expected = <VaultEnvelopeFailure, VaultUnlockFailure>{
      VaultEnvelopeFailure.sessionExpired:
          VaultUnlockFailure.remoteSessionExpired,
      VaultEnvelopeFailure.mfaRequired: VaultUnlockFailure.mfaRequired,
      VaultEnvelopeFailure.devicePending: VaultUnlockFailure.devicePending,
      VaultEnvelopeFailure.deviceRevoked: VaultUnlockFailure.deviceRevoked,
      VaultEnvelopeFailure.envelopeMissing: VaultUnlockFailure.envelopeMissing,
    };

    for (final entry in expected.entries) {
      final repository = _FakeVaultEnvelopeRepository(
        vault: fixture.vault,
        deviceId: fixture.deviceId,
        deviceKey: fixture.deviceKey,
      )..failure = entry.key;
      final controller = _controller(repository: repository);
      expect(
          await controller.unlock('Master password for CU07 tests'), isFalse);
      expect(controller.failure, entry.value);
      expect(controller.isUnlocked, isFalse);
      controller.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('does not classify unexpected local failures as password failures',
      () async {
    final fixture = await _fixture();
    final repository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    )..unexpectedError = StateError('simulated storage failure');
    final controller = _controller(repository: repository);
    addTearDown(controller.dispose);

    expect(await controller.unlock('Master password for CU07 tests'), isFalse);
    expect(controller.failure, VaultUnlockFailure.unexpected);
    expect(controller.remainingBackoff, Duration.zero);
    expect(controller.isUnlocked, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('invalidates the remote capability after five local failures', () async {
    final clock = _Clock(DateTime.utc(2026, 1, 1));
    final fixture = await _fixture();
    final repository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    );
    final policy = UnlockAttemptPolicy(
      clock: clock.call,
      maxAttempts: 5,
      baseDelay: const Duration(seconds: 1),
      maxDelay: const Duration(seconds: 8),
    );
    final controller = _controller(
      repository: repository,
      clock: clock,
      policy: policy,
    );
    addTearDown(controller.dispose);

    for (var attempt = 0; attempt < 5; attempt++) {
      expect(await controller.unlock('wrong password'), isFalse);
      if (attempt < 4) {
        clock.now = clock.now.add(controller.remainingBackoff);
      }
    }

    expect(repository.invalidated, isTrue);
    expect(controller.failure, VaultUnlockFailure.reauthenticationRequired);
    expect(controller.isUnlocked, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('invalidates stale async results and all covered lifecycle states',
      () async {
    final fixture = await _fixture();
    final repository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    )..validationCompleter = Completer<void>();
    final controller = _controller(repository: repository);
    addTearDown(controller.dispose);

    final pending = controller.unlock('Master password for CU07 tests');
    controller.lock();
    repository.validationCompleter!.complete();
    expect(await pending, isFalse);
    expect(controller.isUnlocked, isFalse);

    for (final state in <AppLifecycleState>[
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ]) {
      controller.session.activate(
        vaultId: fixture.vault['id_boveda'] as String,
        cryptoVersion: 1,
        vaultKey: Uint8List.fromList(List<int>.filled(32, 4)),
      );
      controller.handleAppLifecycleState(state);
      expect(controller.isUnlocked, isFalse, reason: '$state must lock');
    }
    controller.handleAppLifecycleState(AppLifecycleState.resumed);
    expect(controller.isUnlocked, isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('clears the local context when the API session is revoked remotely',
      () async {
    final fixture = await _fixture();
    final repository = _FakeVaultEnvelopeRepository(
      vault: fixture.vault,
      deviceId: fixture.deviceId,
      deviceKey: fixture.deviceKey,
    );
    final controller = _controller(repository: repository);
    addTearDown(controller.dispose);

    expect(await controller.unlock('Master password for CU07 tests'), isTrue);
    repository.emitRemoteInvalidation();

    expect(controller.isUnlocked, isFalse);
    expect(controller.vaultName, isNull);
  }, timeout: const Timeout(Duration(minutes: 5)));
}
