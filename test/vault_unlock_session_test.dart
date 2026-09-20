import 'dart:typed_data';

import 'package:boveda_mobile/features/vault_unlock/domain/unlock_attempt_policy.dart';
import 'package:boveda_mobile/features/vault_unlock/domain/vault_unlock_session.dart';
import 'package:flutter_test/flutter_test.dart';

class _Clock {
  _Clock(this.now);

  DateTime now;

  DateTime call() => now;
}

void main() {
  test('keeps the vault key only in the active in-memory session', () {
    final clock = _Clock(DateTime.utc(2026, 1, 1));
    final session = VaultUnlockSession(
      clock: clock.call,
      timeout: const Duration(minutes: 2),
    );
    final key = Uint8List.fromList(List<int>.generate(32, (index) => index));

    session.activate(vaultId: 'vault-a', cryptoVersion: 1, vaultKey: key);

    expect(session.hasInMemoryKey, isTrue);
    expect(session.vaultId, 'vault-a');
    expect(session.cryptoVersion, 1);
    expect(session.openedAt, clock.now);
    expect(session.expiresAt, clock.now.add(const Duration(minutes: 2)));

    session.lock();

    expect(session.hasInMemoryKey, isFalse);
    expect(session.vaultId, isNull);
    expect(key.every((value) => value == 0), isTrue);
    session.dispose();
  });

  test(
      'renews activity, times out deterministically and invalidates generations',
      () {
    final clock = _Clock(DateTime.utc(2026, 1, 1));
    final session = VaultUnlockSession(
      clock: clock.call,
      timeout: const Duration(minutes: 1),
    );
    session.activate(
      vaultId: 'vault-a',
      cryptoVersion: 1,
      vaultKey: Uint8List.fromList(List<int>.filled(32, 7)),
    );
    final generation = session.generation;

    clock.now = clock.now.add(const Duration(seconds: 30));
    expect(session.touch(), isTrue);
    expect(session.isGenerationCurrent(generation), isTrue);

    clock.now = clock.now.add(const Duration(minutes: 1));
    expect(session.expireIfNeeded(), isTrue);
    expect(session.isActive, isFalse);
    expect(session.isGenerationCurrent(generation), isFalse);
    session.dispose();
  });

  test('applies incremental backoff without sleeping in tests', () {
    final clock = _Clock(DateTime.utc(2026, 1, 1));
    final policy = UnlockAttemptPolicy(
      clock: clock.call,
      maxAttempts: 3,
      baseDelay: const Duration(seconds: 2),
      maxDelay: const Duration(seconds: 5),
    );

    final first = policy.registerFailure();
    expect(first.failedAttempts, 1);
    expect(first.requiresRemoteRenewal, isFalse);
    expect(policy.canAttempt, isFalse);
    expect(policy.remainingDelay, const Duration(seconds: 2));

    clock.now = clock.now.add(const Duration(seconds: 2));
    final second = policy.registerFailure();
    expect(second.nextAttemptAt, clock.now.add(const Duration(seconds: 4)));

    clock.now = clock.now.add(const Duration(seconds: 4));
    final terminal = policy.registerFailure();
    expect(terminal.requiresRemoteRenewal, isTrue);
    expect(policy.canAttempt, isFalse);

    policy.reset();
    expect(policy.canAttempt, isTrue);
    expect(policy.failedAttempts, 0);
  });
}
