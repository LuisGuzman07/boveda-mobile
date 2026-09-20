import 'vault_unlock_session.dart';

class UnlockAttemptResult {
  const UnlockAttemptResult({
    required this.failedAttempts,
    required this.nextAttemptAt,
    required this.requiresRemoteRenewal,
  });

  final int failedAttempts;
  final DateTime? nextAttemptAt;
  final bool requiresRemoteRenewal;
}

/// Deterministic local throttling; no password-derived data leaves Flutter.
class UnlockAttemptPolicy {
  UnlockAttemptPolicy({
    VaultClock? clock,
    this.maxAttempts = 5,
    this.baseDelay = const Duration(seconds: 1),
    this.maxDelay = const Duration(seconds: 16),
  })  : _clock = clock ?? DateTime.now,
        assert(maxAttempts > 0),
        assert(baseDelay > Duration.zero),
        assert(maxDelay >= baseDelay);

  final VaultClock _clock;
  final int maxAttempts;
  final Duration baseDelay;
  final Duration maxDelay;
  int _failedAttempts = 0;
  DateTime? _nextAttemptAt;

  int get failedAttempts => _failedAttempts;
  bool get requiresRemoteRenewal => _failedAttempts >= maxAttempts;

  bool get canAttempt {
    if (requiresRemoteRenewal) {
      return false;
    }
    final nextAttemptAt = _nextAttemptAt;
    return nextAttemptAt == null || !_clock().isBefore(nextAttemptAt);
  }

  Duration get remainingDelay {
    final nextAttemptAt = _nextAttemptAt;
    if (nextAttemptAt == null || !_clock().isBefore(nextAttemptAt)) {
      return Duration.zero;
    }
    return nextAttemptAt.difference(_clock());
  }

  UnlockAttemptResult registerFailure() {
    _failedAttempts++;
    if (requiresRemoteRenewal) {
      _nextAttemptAt = null;
      return UnlockAttemptResult(
        failedAttempts: _failedAttempts,
        nextAttemptAt: null,
        requiresRemoteRenewal: true,
      );
    }
    final multiplier = 1 << (_failedAttempts - 1);
    final milliseconds = baseDelay.inMilliseconds * multiplier;
    final delay = Duration(
      milliseconds: milliseconds
          .clamp(
            baseDelay.inMilliseconds,
            maxDelay.inMilliseconds,
          )
          .toInt(),
    );
    _nextAttemptAt = _clock().add(delay);
    return UnlockAttemptResult(
      failedAttempts: _failedAttempts,
      nextAttemptAt: _nextAttemptAt,
      requiresRemoteRenewal: false,
    );
  }

  void reset() {
    _failedAttempts = 0;
    _nextAttemptAt = null;
  }
}
