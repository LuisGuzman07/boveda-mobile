import 'dart:async';

import 'package:boveda_mobile/main.dart';
import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:boveda_mobile/services/installation_identity_service.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'helpers/lock_fakes.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues(<String, Object>{});
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
  });

  testWidgets('requires explicit unlock and relocks when backgrounded',
      (tester) async {
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    addTearDown(lock.dispose);
    await tester.pumpWidget(
      BovedaApp(
        lockService: lock,
        identityService: FakeInstallationIdentityProvider(),
      ),
    );

    expect(find.text('Aplicación bloqueada'), findsOneWidget);
    expect(find.text('Desbloquear'), findsOneWidget);
    await tester.tap(find.text('Desbloquear'));
    await tester.pumpAndSettle();
    expect(find.text('Aplicación bloqueada'), findsNothing);
    expect(find.byTooltip('Escanear QR'), findsOneWidget);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();

    expect(lock.isLocked, isTrue);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(find.text('Aplicación bloqueada'), findsOneWidget);
  });

  testWidgets('surfaces a recoverable installation identity error',
      (tester) async {
    final gateway = FakeLocalAuthenticationGateway();
    final lock = AppLockService(authenticator: gateway);
    final identity = FakeInstallationIdentityProvider()
      ..loadError = InstallationIdentityException('Identidad privada dañada.')
      ..isLocked = () => lock.isLocked;
    addTearDown(lock.dispose);
    await tester.pumpWidget(
      BovedaApp(lockService: lock, identityService: identity),
    );

    await tester.tap(find.text('Desbloquear'));
    await tester.pump();
    await tester.pump();

    expect(find.text('Identidad privada dañada.'), findsOneWidget);
    expect(find.text('Restablecer identidad local'), findsOneWidget);
    expect(gateway.authenticationCalls, 1);
    expect(identity.wasLockedOnLoad, isTrue);
    expect(lock.isLocked, isTrue);
  });

  testWidgets('keeps the app covered until local identity verification ends',
      (tester) async {
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    final identity = FakeInstallationIdentityProvider()
      ..loadCompleter = Completer<InstallationIdentity>();
    addTearDown(lock.dispose);
    await tester.pumpWidget(
      BovedaApp(lockService: lock, identityService: identity),
    );

    await tester.tap(find.text('Desbloquear'));
    await tester.pump();

    expect(identity.loadCalls, 1);
    expect(lock.isLocked, isTrue);
    expect(find.text('Aplicación bloqueada'), findsOneWidget);

    identity.loadCompleter!.complete(identity.identity);
    await tester.pump();
    await tester.pump();

    expect(lock.isLocked, isFalse);
    expect(find.text('Aplicación bloqueada'), findsNothing);
  });

  testWidgets('does not unlock when lifecycle changes during verification',
      (tester) async {
    final lock = AppLockService(
      authenticator: FakeLocalAuthenticationGateway(),
    );
    final identity = FakeInstallationIdentityProvider()
      ..loadCompleter = Completer<InstallationIdentity>();
    addTearDown(lock.dispose);
    await tester.pumpWidget(
      BovedaApp(lockService: lock, identityService: identity),
    );

    await tester.tap(find.text('Desbloquear'));
    await tester.pump();
    expect(identity.loadCalls, 1);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    identity.loadCompleter!.complete(identity.identity);
    await tester.pumpAndSettle();

    expect(lock.isLocked, isTrue);
    expect(lock.allowsSensitiveActions, isFalse);
    expect(find.text('Aplicación bloqueada'), findsOneWidget);
  });
}
