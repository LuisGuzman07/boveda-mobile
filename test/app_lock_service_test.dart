import 'dart:async';

import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:local_auth/local_auth.dart';

import 'helpers/lock_fakes.dart';

void main() {
  test('requires explicit completion after device authentication', () async {
    final gateway = FakeLocalAuthenticationGateway();
    final service = AppLockService(authenticator: gateway);
    addTearDown(service.dispose);

    expect(service.isLocked, isTrue);
    final authentication = await service.authenticate();
    expect(authentication, isNotNull);
    expect(service.isLocked, isTrue);
    expect(service.allowsSensitiveActions, isFalse);
    expect(service.completeUnlock(authentication!), isTrue);
    expect(service.isLocked, isFalse);
    expect(gateway.authenticationCalls, 1);
    expect(gateway.biometricOnly, isFalse);
    expect(gateway.persistAcrossBackgrounding, isFalse);
  });

  test('covers and locks synchronously for every non-resumed lifecycle state',
      () async {
    for (final state in <AppLifecycleState>[
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ]) {
      final service = AppLockService(
        authenticator: FakeLocalAuthenticationGateway(),
      );
      await unlockAppLock(service);

      service.handleAppLifecycleState(state);

      expect(service.isLocked, isTrue, reason: '$state must lock');
      expect(service.obscuresSensitiveContent, isTrue,
          reason: '$state must cover sensitive content');
      expect(service.allowsSensitiveActions, isFalse);

      service.handleAppLifecycleState(AppLifecycleState.resumed);
      expect(service.isLocked, isTrue,
          reason: 'resuming must not restore an unlocked session');
      expect(service.obscuresSensitiveContent, isFalse);
      expect(service.allowsSensitiveActions, isFalse);
      service.dispose();
    }
  });

  test('cannot complete a local authentication after a lifecycle lock',
      () async {
    final pendingAuthentication = Completer<bool>();
    final gateway = FakeLocalAuthenticationGateway()
      ..authenticationCompleter = pendingAuthentication;
    final service = AppLockService(authenticator: gateway);
    addTearDown(service.dispose);

    final authentication = service.authenticate();
    expect(service.isAuthenticating, isTrue);

    service.handleAppLifecycleState(AppLifecycleState.inactive);
    service.handleAppLifecycleState(AppLifecycleState.resumed);
    pendingAuthentication.complete(true);

    expect(await authentication, isNull);
    expect(service.isLocked, isTrue);
    expect(service.allowsSensitiveActions, isFalse);
  });

  test('invalidates a prior authentication when a new attempt starts',
      () async {
    final service = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    addTearDown(service.dispose);

    final first = await service.authenticate();
    final second = await service.authenticate();

    expect(first, isNotNull);
    expect(second, isNotNull);
    expect(service.completeUnlock(first!), isFalse);
    expect(service.completeUnlock(second!), isTrue);
  });

  test('distinguishes cancelled and recoverable local authentication errors',
      () async {
    final cancelledGateway = FakeLocalAuthenticationGateway()
      ..authenticationError = const LocalAuthException(
        code: LocalAuthExceptionCode.userCanceled,
      );
    final cancelled = AppLockService(authenticator: cancelledGateway);
    addTearDown(cancelled.dispose);

    expect(await cancelled.authenticate(), isNull);
    expect(cancelled.unlockFailure, AppLockAuthenticationFailure.cancelled);
    expect(cancelled.unlockError, contains('cancelada'));

    final recoverableGateway = FakeLocalAuthenticationGateway()
      ..authenticationError = const LocalAuthException(
        code: LocalAuthExceptionCode.temporaryLockout,
      );
    final recoverable = AppLockService(authenticator: recoverableGateway);
    addTearDown(recoverable.dispose);

    expect(await recoverable.authenticate(), isNull);
    expect(
      recoverable.unlockFailure,
      AppLockAuthenticationFailure.recoverable,
    );
    expect(recoverable.unlockError, contains('temporalmente'));
  });
}
