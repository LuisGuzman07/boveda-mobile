import 'package:flutter/material.dart';

import 'config/app_config.dart';
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
  bool _identityBusy = false;
  String? _identityError;

  @override
  void initState() {
    super.initState();
    _ownsLockService = widget.lockService == null;
    _lockService = widget.lockService ??
        AppLockService(backgroundTimeout: AppConfig.backgroundLockTimeout);
    _identityService = widget.identityService ?? InstallationIdentityService();
    _lockService.start();
  }

  @override
  void dispose() {
    if (_ownsLockService) {
      _lockService.dispose();
    }
    super.dispose();
  }

  Future<void> _unlock() async {
    if (_identityBusy || !mounted) {
      return;
    }
    setState(() {
      _identityBusy = true;
      _identityError = null;
    });
    try {
      final unlocked = await _lockService.unlock();
      if (!unlocked || !_lockService.allowsSensitiveActions) {
        return;
      }
      await _identityService.loadOrCreate();
      if (!mounted) {
        return;
      }
    } on InstallationIdentityException catch (error) {
      _lockService.lock();
      if (mounted) {
        setState(() => _identityError = error.message);
      }
    } catch (_) {
      _lockService.lock();
      if (mounted) {
        setState(() => _identityError =
            'No se pudo verificar la identidad criptográfica local.');
      }
    } finally {
      if (mounted) {
        setState(() => _identityBusy = false);
      }
    }
  }

  Future<void> _recoverIdentity() async {
    if (_identityBusy || !mounted) {
      return;
    }
    setState(() => _identityBusy = true);
    try {
      final unlocked = await _lockService.unlock();
      if (!unlocked || !_lockService.allowsSensitiveActions) {
        return;
      }
      await _identityService.recover();
      if (mounted) {
        setState(() => _identityError = null);
      }
    } on InstallationIdentityException catch (error) {
      _lockService.lock();
      if (mounted) {
        setState(() => _identityError = error.message);
      }
    } catch (_) {
      _lockService.lock();
      if (mounted) {
        setState(() => _identityError =
            'No se pudo restablecer la identidad criptográfica local.');
      }
    } finally {
      if (mounted) {
        setState(() => _identityBusy = false);
      }
    }
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
        home: const HomeScreen(),
      ),
    );
  }
}
