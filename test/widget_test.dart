import 'package:flutter_test/flutter_test.dart';
import 'package:boveda_mobile/main.dart';

void main() {
  testWidgets('App smoke test: HomeScreen loads Authenticator', (WidgetTester tester) async {
    await tester.pumpWidget(const BovedaApp());
    expect(find.text('Bóveda Authenticator'), findsWidgets);
  });
}
