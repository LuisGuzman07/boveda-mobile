import 'package:flutter/material.dart';

import '../services/app_lock_service.dart';

class AppLockScope extends InheritedNotifier<AppLockService> {
  const AppLockScope({
    super.key,
    required AppLockService service,
    required super.child,
  }) : super(notifier: service);

  static AppLockService? maybeOf(BuildContext context) {
    return context.dependOnInheritedWidgetOfExactType<AppLockScope>()?.notifier;
  }
}

class AppLockOverlay extends StatelessWidget {
  const AppLockOverlay({
    super.key,
    required this.service,
    required this.child,
    required this.onUnlock,
    required this.onRecoverIdentity,
    required this.identityBusy,
    this.identityError,
  });

  final AppLockService service;
  final Widget child;
  final Future<void> Function() onUnlock;
  final Future<void> Function() onRecoverIdentity;
  final bool identityBusy;
  final String? identityError;

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: service,
      child: child,
      builder: (context, child) {
        final shouldObscure =
            service.isLocked || service.obscuresSensitiveContent;
        if (!shouldObscure) {
          return child!;
        }
        return Stack(
          children: <Widget>[
            child!,
            Positioned.fill(
              child: Material(
                color: const Color(0xFF0F172A),
                child: service.isLocked
                    ? _UnlockPanel(
                        busy: identityBusy || service.isAuthenticating,
                        identityError: identityError,
                        authenticationError: service.unlockError,
                        onUnlock: onUnlock,
                        onRecoverIdentity: onRecoverIdentity,
                      )
                    : const Center(
                        child: Icon(
                          Icons.shield_rounded,
                          size: 52,
                          color: Color(0xFF60A5FA),
                        ),
                      ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class _UnlockPanel extends StatelessWidget {
  const _UnlockPanel({
    required this.busy,
    required this.onUnlock,
    required this.onRecoverIdentity,
    this.identityError,
    this.authenticationError,
  });

  final bool busy;
  final String? identityError;
  final String? authenticationError;
  final Future<void> Function() onUnlock;
  final Future<void> Function() onRecoverIdentity;

  @override
  Widget build(BuildContext context) {
    final error = identityError ?? authenticationError;
    return SafeArea(
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                const Icon(
                  Icons.lock_rounded,
                  size: 62,
                  color: Color(0xFF60A5FA),
                ),
                const SizedBox(height: 20),
                const Text(
                  'Aplicación bloqueada',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 10),
                const Text(
                  'Usa la biometría o la credencial de pantalla del dispositivo para continuar.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Color(0xFFCBD5E1), height: 1.4),
                ),
                if (error != null) ...<Widget>[
                  const SizedBox(height: 20),
                  Text(
                    error,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      color: Color(0xFFFCA5A5),
                      height: 1.4,
                    ),
                  ),
                ],
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: busy
                      ? null
                      : () async {
                          await onUnlock();
                        },
                  icon: busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.lock_open_rounded),
                  label: Text(busy ? 'Verificando...' : 'Desbloquear'),
                ),
                if (identityError != null) ...<Widget>[
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: busy
                        ? null
                        : () async {
                            final confirmed = await showDialog<bool>(
                              context: context,
                              builder: (dialogContext) => AlertDialog(
                                title: const Text(
                                  'Restablecer identidad local',
                                ),
                                content: const Text(
                                  'Esto elimina la identidad criptográfica local dañada y crea una nueva. Deberás enrolar nuevamente este dispositivo en el backend.',
                                ),
                                actions: <Widget>[
                                  TextButton(
                                    onPressed: () =>
                                        Navigator.pop(dialogContext, false),
                                    child: const Text('Cancelar'),
                                  ),
                                  FilledButton(
                                    onPressed: () =>
                                        Navigator.pop(dialogContext, true),
                                    child: const Text('Restablecer'),
                                  ),
                                ],
                              ),
                            );
                            if (confirmed == true && context.mounted) {
                              await onRecoverIdentity();
                            }
                          },
                    child: const Text('Restablecer identidad local'),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
