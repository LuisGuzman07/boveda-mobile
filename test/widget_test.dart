import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:boveda_mobile/main.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    FlutterSecureStorage.setMockInitialValues({});
  });

  testWidgets('App smoke test: HomeScreen loads Authenticator',
      (WidgetTester tester) async {
    await tester.pumpWidget(const BovedaApp());
    expect(find.text('Bóveda Authenticator'), findsWidgets);
  });
}
