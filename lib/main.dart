import 'package:flutter/material.dart';

import 'screens/home_screen.dart';
import 'services/app_lock_service.dart';
import 'services/installation_identity_service.dart';
import 'widgets/app_lock_gate.dart';

void main() {
  runApp(const BovedaApp());
}

class BovedaApp extends StatefulWidget {
  const BovedaApp({
    super.key,
    this.lockService,
    this.identityService,
  });

  final AppLockService? lockService;
  final InstallationIdentityProvider? identityService;

  @override
  State<BovedaApp> createState() => _BovedaAppState();
}

class _BovedaAppState extends State<BovedaApp> {
  late final AppLockService _lockService;
  late final InstallationIdentityProvider _identityService;
  late final bool _ownsLockService;
  late int _knownSecurityEpoch;
  bool _identityBusy = false;
  String? _identityError;
  int _unlockOperation = 0;

  @override
  void initState() {
    super.initState();
    _ownsLockService = widget.lockService == null;
    _lockService = widget.lockService ?? AppLockService();
    _identityService = widget.identityService ?? InstallationIdentityService();
    _knownSecurityEpoch = _lockService.securityEpoch;
    _lockService.addListener(_onLockChanged);
    _lockService.start();
  }

  @override
  void dispose() {
    _lockService.removeListener(_onLockChanged);
    if (_ownsLockService) {
      _lockService.dispose();
    }
    super.dispose();
  }

  void _onLockChanged() {
    final securityEpoch = _lockService.securityEpoch;
    if (securityEpoch == _knownSecurityEpoch) {
      return;
    }
    _knownSecurityEpoch = securityEpoch;
    _unlockOperation++;
    if (mounted && _identityBusy) {
      setState(() => _identityBusy = false);
    }
  }

  bool _isCurrentUnlock(int operation) =>
      mounted && operation == _unlockOperation;

  Future<void> _unlock() => _authenticateAndVerify(
        _identityService.loadOrCreate,
        'No se pudo verificar la identidad criptográfica local.',
      );

  Future<void> _recoverIdentity() => _authenticateAndVerify(
        _identityService.recover,
        'No se pudo restablecer la identidad criptográfica local.',
      );

  Future<void> _authenticateAndVerify(
    Future<InstallationIdentity> Function() identityOperation,
    String unexpectedError,
  ) async {
    if (_identityBusy || !mounted) {
      return;
    }
    final operation = ++_unlockOperation;
    setState(() {
      _identityBusy = true;
      _identityError = null;
    });

    AppLockAuthentication? authentication;
    try {
      authentication = await _lockService.authenticate();
      if (authentication == null || !_isCurrentUnlock(operation)) {
        return;
      }
      await identityOperation();
      if (!_isCurrentUnlock(operation) ||
          !_lockService.completeUnlock(authentication)) {
        return;
      }
      if (mounted) {
        setState(() => _identityError = null);
      }
    } on InstallationIdentityException catch (error) {
      if (authentication != null &&
          _isCurrentUnlock(operation) &&
          _lockService.isAuthenticationValid(authentication)) {
        _failUnlock(operation, error.message);
      }
    } catch (_) {
      if (authentication != null &&
          _isCurrentUnlock(operation) &&
          _lockService.isAuthenticationValid(authentication)) {
        _failUnlock(operation, unexpectedError);
      }
    } finally {
      if (_isCurrentUnlock(operation)) {
        setState(() => _identityBusy = false);
      }
    }
  }

  void _failUnlock(int operation, String message) {
    if (!_isCurrentUnlock(operation)) {
      return;
    }
    if (mounted) {
      setState(() => _identityError = message);
    }
    _lockService.lock();
  }

  @override
  Widget build(BuildContext context) {
    return AppLockScope(
      service: _lockService,
      child: MaterialApp(
        title: 'Bóveda Híbrida',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFF2563EB),
            brightness: Brightness.dark,
          ),
          useMaterial3: true,
        ),
        builder: (context, child) => AppLockOverlay(
          service: _lockService,
          onUnlock: _unlock,
          onRecoverIdentity: _recoverIdentity,
          identityBusy: _identityBusy,
          identityError: _identityError,
          child: child ?? const SizedBox.shrink(),
        ),
        home: HomeScreen(installationIdentity: _identityService),
      ),
    );
  }
}
