import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:boveda_mobile/main.dart';
import 'package:boveda_mobile/services/app_lock_service.dart';

import 'helpers/lock_fakes.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    FlutterSecureStorage.setMockInitialValues({});
  });

  testWidgets('App smoke test: starts behind the local lock',
      (WidgetTester tester) async {
    final lock =
        AppLockService(authenticator: FakeLocalAuthenticationGateway());
    addTearDown(lock.dispose);
    await tester.pumpWidget(BovedaApp(
      lockService: lock,
      identityService: FakeInstallationIdentityProvider(),
    ));
    expect(find.text('Aplicación bloqueada'), findsOneWidget);
  });
}
