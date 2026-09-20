import 'dart:async';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import '../../../services/app_lock_service.dart';
import '../../../services/vault_crypto_service.dart';
import '../data/vault_envelope_repository.dart';
import '../domain/unlock_attempt_policy.dart';
import '../domain/vault_unlock_session.dart';

enum VaultUnlockFailure {
  localAuthenticationRequired,
  remoteSessionExpired,
  mfaRequired,
  devicePending,
  deviceRevoked,
  securityStateChanged,
  envelopeMissing,
  envelopeIncompatible,
  cryptographicVerification,
  network,
  unexpected,
  backoff,
  reauthenticationRequired,
}

extension VaultUnlockFailureMessage on VaultUnlockFailure {
  String get userMessage {
    switch (this) {
      case VaultUnlockFailure.localAuthenticationRequired:
        return 'Desbloquea la aplicación antes de abrir la bóveda.';
      case VaultUnlockFailure.remoteSessionExpired:
      case VaultUnlockFailure.mfaRequired:
      case VaultUnlockFailure.devicePending:
      case VaultUnlockFailure.deviceRevoked:
      case VaultUnlockFailure.securityStateChanged:
      case VaultUnlockFailure.envelopeMissing:
        return 'La sesión de bóveda ya no es válida. Inicia sesión y completa la verificación nuevamente.';
      case VaultUnlockFailure.envelopeIncompatible:
      case VaultUnlockFailure.cryptographicVerification:
        return 'No fue posible desbloquear la bóveda. Verifica tus credenciales e inténtalo nuevamente.';
      case VaultUnlockFailure.network:
        return 'No se pudo contactar al backend para autorizar la bóveda. Inténtalo nuevamente.';
      case VaultUnlockFailure.unexpected:
        return 'No fue posible completar el desbloqueo. Inténtalo nuevamente.';
      case VaultUnlockFailure.backoff:
        return 'Espera un momento antes de volver a intentarlo.';
      case VaultUnlockFailure.reauthenticationRequired:
        return 'Debes iniciar sesión y completar una nueva verificación antes de intentar desbloquear la bóveda.';
    }
  }
}

class VaultUnlockController extends ChangeNotifier {
  VaultUnlockController({
    required VaultEnvelopeRepository repository,
    VaultCryptoService? crypto,
    VaultUnlockSession? session,
    UnlockAttemptPolicy? attemptPolicy,
    VaultClock? clock,
  })  : _repository = repository,
        _crypto = crypto ?? VaultCryptoService(),
        session = session ?? VaultUnlockSession(clock: clock),
        _ownsSession = session == null,
        _attemptPolicy = attemptPolicy ?? UnlockAttemptPolicy(clock: clock),
        _clock = clock ?? DateTime.now {
    this.session.addListener(_onSessionChanged);
    _repository.addInvalidationListener(_onRemoteInvalidated);
  }

  final VaultEnvelopeRepository _repository;
  final VaultCryptoService _crypto;
  final bool _ownsSession;
  final UnlockAttemptPolicy _attemptPolicy;
  final VaultClock _clock;
  final VaultUnlockSession session;
  AppLockService? _appLock;
  Timer? _timeoutTimer;
  Timer? _backoffTimer;
  bool _busy = false;
  bool _disposed = false;
  int _operation = 0;
  String? _vaultName;
  String? _vaultDescription;
  VaultUnlockFailure? _failure;

  bool get isBusy => _busy;
  bool get isUnlocked => session.isActive;
  String? get vaultName => _vaultName;
  String? get vaultDescription => _vaultDescription;
  VaultUnlockFailure? get failure => _failure;
  DateTime? get expiresAt => session.expiresAt;
  Duration get remainingBackoff => _attemptPolicy.remainingDelay;
  bool get canAttempt => _attemptPolicy.canAttempt;

  void attachAppLockService(AppLockService? appLock) {
    if (identical(appLock, _appLock)) {
      return;
    }
    _appLock?.removeListener(_onAppLockChanged);
    _appLock = appLock;
    _appLock?.addListener(_onAppLockChanged);
    if (!_allowsSensitiveActions) {
      lock();
    }
  }

  Future<bool> unlock(String password) async {
    if (_disposed || _busy) {
      return false;
    }
    if (!_allowsSensitiveActions) {
      _setFailure(VaultUnlockFailure.localAuthenticationRequired);
      return false;
    }
    if (!_attemptPolicy.canAttempt) {
      _setFailure(
        _attemptPolicy.requiresRemoteRenewal
            ? VaultUnlockFailure.reauthenticationRequired
            : VaultUnlockFailure.backoff,
      );
      return false;
    }

    final operation = ++_operation;
    _busy = true;
    _failure = null;
    _notify();
    Uint8List? deviceKey;
    VaultUnlockResult? result;
    try {
      await _repository.validateRemoteSession();
      _ensureCurrent(operation);
      final vault = await _repository
          .fetchAuthorizedVault(session.vaultId ?? _requestedVaultId);
      _ensureCurrent(operation);
      if (vault['id_boveda'] != _requestedVaultId) {
        throw const FormatException('La bóveda recuperada no coincide.');
      }
      final expectedDeviceId = _repository.deviceId;
      deviceKey = await _repository.loadDeviceKey();
      _ensureCurrent(operation);
      result = await _crypto.unlock(
        vault: vault,
        password: password,
        deviceKey: deviceKey,
        expectedDeviceId: expectedDeviceId,
      );
      _ensureCurrent(operation);
      session.activate(
        vaultId: result.vaultId,
        cryptoVersion: result.cryptoVersion,
        vaultKey: result.takeVaultKey(),
      );
      _vaultName = result.name;
      _vaultDescription = result.description;
      _attemptPolicy.reset();
      _scheduleTimeout();
      _notify();
      return true;
    } on _StaleUnlockResult {
      return false;
    } on VaultEnvelopeException catch (error) {
      _handleEnvelopeFailure(operation, error.failure);
      return false;
    } on FormatException {
      await _handleCryptographicFailure(operation, incompatible: true);
      return false;
    } on SecretBoxAuthenticationError {
      await _handleCryptographicFailure(operation);
      return false;
    } catch (_) {
      _handleUnexpectedFailure(operation);
      return false;
    } finally {
      deviceKey?.fillRange(0, deviceKey.length, 0);
      result?.dispose();
      if (_isCurrentOperation(operation)) {
        _busy = false;
        _notify();
      }
    }
  }

  /// The selected vault is bound for one controller instance and never persisted.
  String _requestedVaultId = '';

  void selectVault(String vaultId) {
    if (_disposed || vaultId == _requestedVaultId) {
      return;
    }
    lock();
    _requestedVaultId = vaultId;
    _notify();
  }

  void recordActivity() {
    if (session.touch()) {
      _scheduleTimeout();
    }
  }

  void checkForTimeout() {
    if (session.expireIfNeeded()) {
      _clearUnlockedState();
      _notify();
    }
  }

  void handleAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        lock();
        return;
      case AppLifecycleState.resumed:
        return;
    }
  }

  void lock() {
    if (_disposed) {
      return;
    }
    _operation++;
    _busy = false;
    _timeoutTimer?.cancel();
    _timeoutTimer = null;
    _clearUnlockedState();
    _failure = null;
    _notify();
  }

  void _onAppLockChanged() {
    if (!_allowsSensitiveActions) {
      lock();
    }
  }

  void _onRemoteInvalidated() {
    lock();
  }

  void _onSessionChanged() {
    if (!session.isActive) {
      _timeoutTimer?.cancel();
      _timeoutTimer = null;
      _vaultName = null;
      _vaultDescription = null;
    }
    _notify();
  }

  void _handleEnvelopeFailure(int operation, VaultEnvelopeFailure failure) {
    if (!_isCurrentOperation(operation)) {
      return;
    }
    lock();
    _failure = switch (failure) {
      VaultEnvelopeFailure.sessionExpired =>
        VaultUnlockFailure.remoteSessionExpired,
      VaultEnvelopeFailure.mfaRequired => VaultUnlockFailure.mfaRequired,
      VaultEnvelopeFailure.devicePending => VaultUnlockFailure.devicePending,
      VaultEnvelopeFailure.deviceRevoked => VaultUnlockFailure.deviceRevoked,
      VaultEnvelopeFailure.securityStateChanged =>
        VaultUnlockFailure.securityStateChanged,
      VaultEnvelopeFailure.envelopeMissing =>
        VaultUnlockFailure.envelopeMissing,
      VaultEnvelopeFailure.unauthorized =>
        VaultUnlockFailure.remoteSessionExpired,
      VaultEnvelopeFailure.network => VaultUnlockFailure.network,
      VaultEnvelopeFailure.localAuthenticationRequired =>
        VaultUnlockFailure.localAuthenticationRequired,
    };
    _notify();
  }

  Future<void> _handleCryptographicFailure(
    int operation, {
    bool incompatible = false,
  }) async {
    if (!_isCurrentOperation(operation)) {
      return;
    }
    final result = _attemptPolicy.registerFailure();
    if (!result.requiresRemoteRenewal) {
      _failure = incompatible
          ? VaultUnlockFailure.envelopeIncompatible
          : VaultUnlockFailure.cryptographicVerification;
      _scheduleBackoffRefresh();
      _notify();
      return;
    }

    try {
      await _repository.invalidateRemoteSession();
    } catch (_) {
      // The local context is invalidated even if the best-effort remote revoke fails.
    } finally {
      if (!_disposed) {
        lock();
        _appLock?.lock();
        _failure = VaultUnlockFailure.reauthenticationRequired;
        _notify();
      }
    }
  }

  void _handleUnexpectedFailure(int operation) {
    if (!_isCurrentOperation(operation)) {
      return;
    }
    _failure = VaultUnlockFailure.unexpected;
    _notify();
  }

  void _clearUnlockedState() {
    session.lock();
    _vaultName = null;
    _vaultDescription = null;
  }

  void _scheduleTimeout() {
    _timeoutTimer?.cancel();
    final expiresAt = session.expiresAt;
    if (expiresAt == null) {
      return;
    }
    final delay = expiresAt.difference(_clock());
    _timeoutTimer =
        Timer(delay.isNegative ? Duration.zero : delay, checkForTimeout);
  }

  void _scheduleBackoffRefresh() {
    _backoffTimer?.cancel();
    final delay = _attemptPolicy.remainingDelay;
    if (delay <= Duration.zero) {
      return;
    }
    _backoffTimer = Timer(delay, _notify);
  }

  bool get _allowsSensitiveActions =>
      _appLock == null || _appLock!.allowsSensitiveActions;

  bool _isCurrentOperation(int operation) =>
      !_disposed && operation == _operation && _allowsSensitiveActions;

  void _ensureCurrent(int operation) {
    if (!_isCurrentOperation(operation)) {
      throw const _StaleUnlockResult();
    }
  }

  void _setFailure(VaultUnlockFailure failure) {
    if (_disposed) {
      return;
    }
    _failure = failure;
    _notify();
  }

  void _notify() {
    if (!_disposed) {
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _timeoutTimer?.cancel();
    _backoffTimer?.cancel();
    _appLock?.removeListener(_onAppLockChanged);
    _repository.removeInvalidationListener(_onRemoteInvalidated);
    session.removeListener(_onSessionChanged);
    if (_ownsSession) {
      session.dispose();
    }
    super.dispose();
  }
}

class _StaleUnlockResult implements Exception {
  const _StaleUnlockResult();
}
