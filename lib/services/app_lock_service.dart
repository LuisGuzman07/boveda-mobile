import 'package:flutter/widgets.dart';
import 'package:local_auth/local_auth.dart';

abstract class LocalAuthenticationGateway {
  Future<bool> isDeviceSupported();

  Future<bool> authenticate({
    required String localizedReason,
    required bool biometricOnly,
    required bool persistAcrossBackgrounding,
  });
}

class LocalAuthGateway implements LocalAuthenticationGateway {
  LocalAuthGateway({LocalAuthentication? authentication})
      : _authentication = authentication ?? LocalAuthentication();

  final LocalAuthentication _authentication;

  @override
  Future<bool> isDeviceSupported() async {
    final canUseBiometrics = await _authentication.canCheckBiometrics;
    return canUseBiometrics || await _authentication.isDeviceSupported();
  }

  @override
  Future<bool> authenticate({
    required String localizedReason,
    required bool biometricOnly,
    required bool persistAcrossBackgrounding,
  }) {
    return _authentication.authenticate(
      localizedReason: localizedReason,
      biometricOnly: biometricOnly,
      persistAcrossBackgrounding: persistAcrossBackgrounding,
    );
  }
}

enum AppLockAuthenticationFailure {
  cancelled,
  recoverable,
  unavailable,
  failed,
}

class AppLockAuthentication {
  const AppLockAuthentication._(this._attempt, this._securityEpoch);

  final int _attempt;
  final int _securityEpoch;
}

class AppLockService extends ChangeNotifier with WidgetsBindingObserver {
  AppLockService({
    LocalAuthenticationGateway? authenticator,
  }) : _authenticator = authenticator ?? LocalAuthGateway();

  final LocalAuthenticationGateway _authenticator;

  bool _locked = true;
  bool _authenticating = false;
  bool _inForeground = true;
  bool _started = false;
  bool _disposed = false;
  String? _unlockError;
  AppLockAuthenticationFailure? _unlockFailure;
  int _securityEpoch = 0;
  int _authenticationSequence = 0;
  int? _activeAuthentication;
  int? _successfulAuthentication;

  bool get isLocked => _locked;
  bool get isAuthenticating => _authenticating;
  bool get obscuresSensitiveContent => !_inForeground;
  bool get allowsSensitiveActions => !_locked && _inForeground;
  String? get unlockError => _unlockError;
  AppLockAuthenticationFailure? get unlockFailure => _unlockFailure;
  int get securityEpoch => _securityEpoch;

  void start() {
    if (_started || _disposed) {
      return;
    }
    _started = true;
    WidgetsBinding.instance.addObserver(this);
  }

  Future<AppLockAuthentication?> authenticate() async {
    if (_disposed || !_locked || _authenticating || !_inForeground) {
      return null;
    }

    final attempt = ++_authenticationSequence;
    final securityEpoch = _securityEpoch;
    _activeAuthentication = attempt;
    _successfulAuthentication = null;
    _authenticating = true;
    _unlockError = null;
    _unlockFailure = null;
    _notify();

    try {
      if (!await _authenticator.isDeviceSupported()) {
        if (!_isCurrentAuthentication(attempt, securityEpoch)) {
          return null;
        }
        _setAuthenticationFailure(
          AppLockAuthenticationFailure.unavailable,
          'Configura una biometría o una credencial de pantalla del dispositivo para desbloquear la aplicación.',
        );
        return null;
      }

      final authenticated = await _authenticator.authenticate(
        localizedReason:
            'Desbloquea Bóveda Authenticator con la biometría o credencial de este dispositivo.',
        biometricOnly: false,
        persistAcrossBackgrounding: false,
      );
      if (!_isCurrentAuthentication(attempt, securityEpoch)) {
        return null;
      }
      if (!authenticated) {
        _setAuthenticationFailure(
          AppLockAuthenticationFailure.cancelled,
          'La autenticación fue cancelada. Intenta desbloquear nuevamente.',
        );
        return null;
      }

      _successfulAuthentication = attempt;
      return AppLockAuthentication._(attempt, securityEpoch);
    } on LocalAuthException catch (error) {
      if (_isCurrentAuthentication(attempt, securityEpoch)) {
        _setLocalAuthenticationFailure(error);
      }
      return null;
    } catch (_) {
      if (_isCurrentAuthentication(attempt, securityEpoch)) {
        _setAuthenticationFailure(
          AppLockAuthenticationFailure.failed,
          'No se pudo completar la autenticación local. Intenta nuevamente.',
        );
      }
      return null;
    } finally {
      if (_activeAuthentication == attempt) {
        _activeAuthentication = null;
        _authenticating = false;
        _notify();
      }
    }
  }

  bool isAuthenticationValid(AppLockAuthentication authentication) {
    return !_disposed &&
        _locked &&
        _inForeground &&
        authentication._securityEpoch == _securityEpoch &&
        _successfulAuthentication == authentication._attempt;
  }

  bool completeUnlock(AppLockAuthentication authentication) {
    if (!isAuthenticationValid(authentication)) {
      return false;
    }
    _locked = false;
    _successfulAuthentication = null;
    _unlockError = null;
    _unlockFailure = null;
    _notify();
    return true;
  }

  void lock() {
    _lock(clearError: true);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    handleAppLifecycleState(state);
  }

  void handleAppLifecycleState(AppLifecycleState state) {
    if (_disposed) {
      return;
    }
    switch (state) {
      case AppLifecycleState.resumed:
        _handleResumed();
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        _handleCoveredLifecycleState();
    }
  }

  void _handleCoveredLifecycleState() {
    _inForeground = false;
    _lock(clearError: true);
  }

  void _handleResumed() {
    if (!_inForeground) {
      _inForeground = true;
      _notify();
    }
  }

  bool _isCurrentAuthentication(int attempt, int securityEpoch) {
    return !_disposed &&
        _locked &&
        _inForeground &&
        _activeAuthentication == attempt &&
        _securityEpoch == securityEpoch;
  }

  void _lock({required bool clearError}) {
    if (_disposed) {
      return;
    }
    _locked = true;
    _authenticating = false;
    _activeAuthentication = null;
    _successfulAuthentication = null;
    _securityEpoch++;
    if (clearError) {
      _unlockError = null;
      _unlockFailure = null;
    }
    _notify();
  }

  void _setLocalAuthenticationFailure(LocalAuthException error) {
    final code = error.code;
    if (code == LocalAuthExceptionCode.userCanceled ||
        code == LocalAuthExceptionCode.systemCanceled ||
        code == LocalAuthExceptionCode.timeout ||
        code == LocalAuthExceptionCode.userRequestedFallback) {
      _setAuthenticationFailure(
        AppLockAuthenticationFailure.cancelled,
        'La autenticación fue cancelada. Intenta desbloquear nuevamente.',
      );
      return;
    }
    if (code == LocalAuthExceptionCode.temporaryLockout ||
        code == LocalAuthExceptionCode.biometricLockout ||
        code ==
            LocalAuthExceptionCode.biometricHardwareTemporarilyUnavailable ||
        code == LocalAuthExceptionCode.uiUnavailable ||
        code == LocalAuthExceptionCode.authInProgress) {
      _setAuthenticationFailure(
        AppLockAuthenticationFailure.recoverable,
        'La autenticación local no está disponible temporalmente. Intenta nuevamente.',
      );
      return;
    }
    if (code == LocalAuthExceptionCode.noCredentialsSet ||
        code == LocalAuthExceptionCode.noBiometricsEnrolled ||
        code == LocalAuthExceptionCode.noBiometricHardware) {
      _setAuthenticationFailure(
        AppLockAuthenticationFailure.unavailable,
        'Configura una biometría o una credencial de pantalla del dispositivo para desbloquear la aplicación.',
      );
      return;
    }
    _setAuthenticationFailure(
      AppLockAuthenticationFailure.failed,
      'No se pudo completar la autenticación local. Intenta nuevamente.',
    );
  }

  void _setAuthenticationFailure(
    AppLockAuthenticationFailure failure,
    String message,
  ) {
    _unlockFailure = failure;
    _unlockError = message;
  }

  void _notify() {
    if (!_disposed) {
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    if (_started) {
      WidgetsBinding.instance.removeObserver(this);
    }
    super.dispose();
  }
}
