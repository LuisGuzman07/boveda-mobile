import 'package:boveda_mobile/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('CU06 opens from home and validates required credentials',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const BovedaApp());
    await tester.pumpAndSettle();
    expect(find.byTooltip('Escanear QR'), findsOneWidget);
    await tester.tap(find.byTooltip('Bóvedas cifradas'));
    await tester.pumpAndSettle();
    expect(find.text('Bóvedas cifradas'), findsOneWidget);
    expect(find.byType(TextField), findsNWidgets(3));
    await tester.tap(find.text('Ingresar'));
    await tester.pumpAndSettle();
    expect(
        find.text('Completa correo, contraseña y código TOTP de seis dígitos.'),
        findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });
}
