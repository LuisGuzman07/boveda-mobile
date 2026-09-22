import 'package:boveda_mobile/screens/vault_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('CU06 opens from home and validates required credentials',
      (tester) async {
    SharedPreferences.setMockInitialValues({});
    await tester.pumpWidget(const MaterialApp(home: VaultScreen()));
    await tester.pumpAndSettle();
    expect(find.text('Bóvedas cifradas'), findsOneWidget);
    expect(find.byType(TextField), findsNWidgets(3));
    await tester.tap(find.text('Ingresar'));
    await tester.pumpAndSettle();
    expect(
        find.text('Completa correo, contraseña y código TOTP de seis dígitos.'),
        findsOneWidget);
  });
}
