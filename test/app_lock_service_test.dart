import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers/lock_fakes.dart';

void main() {
  test('starts locked and uses device authentication without a custom PIN',
      () async {
    final gateway = FakeLocalAuthenticationGateway();
    final service = AppLockService(authenticator: gateway);
    addTearDown(service.dispose);

    expect(service.isLocked, isTrue);
    expect(await service.unlock(), isTrue);
    expect(service.isLocked, isFalse);
    expect(gateway.authenticationCalls, 1);
    expect(gateway.biometricOnly, isFalse);
    expect(gateway.persistAcrossBackgrounding, isFalse);
  });

  test('locks after the configured background timeout', () async {
    var now = DateTime.utc(2026, 1, 1, 12);
    final service = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
      backgroundTimeout: const Duration(seconds: 30),
      now: () => now,
    );
    addTearDown(service.dispose);
    await service.unlock();

    service.handleAppLifecycleState(AppLifecycleState.paused);
    expect(service.allowsSensitiveActions, isFalse);
    now = now.add(const Duration(seconds: 29));
    service.handleAppLifecycleState(AppLifecycleState.resumed);
    expect(service.isLocked, isFalse);

    service.handleAppLifecycleState(AppLifecycleState.hidden);
    now = now.add(const Duration(seconds: 30));
    service.handleAppLifecycleState(AppLifecycleState.resumed);
    expect(service.isLocked, isTrue);
  });

  test('locks immediately when the timeout is zero', () async {
    final service = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
      backgroundTimeout: Duration.zero,
    );
    addTearDown(service.dispose);
    await service.unlock();

    service.handleAppLifecycleState(AppLifecycleState.paused);

    expect(service.isLocked, isTrue);
    expect(service.allowsSensitiveActions, isFalse);
  });
}
