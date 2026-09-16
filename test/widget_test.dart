import 'package:flutter_test/flutter_test.dart';
import 'package:boveda_mobile/main.dart';

void main() {
  testWidgets('App smoke test: HomeScreen loads', (WidgetTester tester) async {
    await tester.pumpWidget(const BovedaApp());
    expect(find.text('Bóveda Híbrida'), findsWidgets);
  });
}
