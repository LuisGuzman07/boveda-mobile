import 'dart:async';

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

class AppLockService extends ChangeNotifier with WidgetsBindingObserver {
  AppLockService({
    LocalAuthenticationGateway? authenticator,
    Duration? backgroundTimeout,
    DateTime Function()? now,
  })  : _authenticator = authenticator ?? LocalAuthGateway(),
        _backgroundTimeout = backgroundTimeout ?? const Duration(seconds: 30),
        _now = now ?? DateTime.now;

  final LocalAuthenticationGateway _authenticator;
  final Duration _backgroundTimeout;
  final DateTime Function() _now;

  Timer? _backgroundTimer;
  DateTime? _backgroundedAt;
  bool _locked = true;
  bool _authenticating = false;
  bool _started = false;
  bool _disposed = false;
  String? _unlockError;

  bool get isLocked => _locked;
  bool get isAuthenticating => _authenticating;
  bool get obscuresSensitiveContent => _backgroundedAt != null;
  bool get allowsSensitiveActions => !_locked && !obscuresSensitiveContent;
  String? get unlockError => _unlockError;

  void start() {
    if (_started || _disposed) {
      return;
    }
    _started = true;
    WidgetsBinding.instance.addObserver(this);
  }

  Future<bool> unlock() async {
    if (_disposed || !_locked || _authenticating) {
      return !_locked;
    }

    _authenticating = true;
    _unlockError = null;
    _notify();

    try {
      if (!await _authenticator.isDeviceSupported()) {
        _unlockError =
            'Configura una biometría o una credencial de pantalla del dispositivo para desbloquear la aplicación.';
        return false;
      }

      final authenticated = await _authenticator.authenticate(
        localizedReason:
            'Desbloquea Bóveda Authenticator con la biometría o credencial de este dispositivo.',
        biometricOnly: false,
        persistAcrossBackgrounding: false,
      );
      if (!authenticated) {
        _unlockError = 'No se pudo verificar la credencial del dispositivo.';
        return false;
      }
      if (_backgroundedAt != null) {
        _unlockError =
            'La aplicación pasó a segundo plano. Intenta desbloquearla nuevamente.';
        return false;
      }

      _locked = false;
      return true;
    } on LocalAuthException {
      _unlockError =
          'La autenticación local no está disponible. Revisa la biometría o credencial del dispositivo.';
      return false;
    } catch (_) {
      _unlockError =
          'No se pudo completar la autenticación local. Intenta nuevamente.';
      return false;
    } finally {
      _authenticating = false;
      _notify();
    }
  }

  void lock() {
    if (_disposed) {
      return;
    }
    _backgroundTimer?.cancel();
    _backgroundTimer = null;
    final changed = !_locked || _backgroundedAt != null || _unlockError != null;
    _locked = true;
    _backgroundedAt = null;
    _unlockError = null;
    if (changed) {
      _notify();
    }
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
        break;
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        _handleBackgrounded();
    }
  }

  void _handleBackgrounded() {
    if (_backgroundedAt != null) {
      return;
    }
    _backgroundedAt = _now();
    if (_backgroundTimeout <= Duration.zero) {
      lock();
      return;
    }
    _backgroundTimer?.cancel();
    _backgroundTimer = Timer(_backgroundTimeout, () {
      if (_backgroundedAt != null) {
        lock();
      }
    });
    _notify();
  }

  void _handleResumed() {
    final backgroundedAt = _backgroundedAt;
    if (backgroundedAt == null) {
      if (_locked) {
        _notify();
      }
      return;
    }
    _backgroundTimer?.cancel();
    _backgroundTimer = null;
    _backgroundedAt = null;
    if (_now().difference(backgroundedAt) >= _backgroundTimeout) {
      lock();
      return;
    }
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
    _backgroundTimer?.cancel();
    if (_started) {
      WidgetsBinding.instance.removeObserver(this);
    }
    super.dispose();
  }
}
