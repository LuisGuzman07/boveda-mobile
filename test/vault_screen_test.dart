import 'package:boveda_mobile/main.dart';
import 'package:boveda_mobile/screens/vault_screen.dart';
import 'package:boveda_mobile/services/vault_api_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class TrackingVaultApiService extends VaultApiService {
  bool loggedOut = false;

  @override
  void logout() {
    loggedOut = true;
    super.logout();
  }
}

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
    final totpField = find.byType(TextField).at(2);
    final totp = tester.widget<TextField>(totpField);
    final totpController = totp.controller!;
    expect(totp.obscureText, isTrue);
    expect(totp.keyboardType, TextInputType.number);
    expect(totp.maxLength, 6);
    expect(totp.autocorrect, isFalse);
    expect(totp.enableSuggestions, isFalse);

    await tester.enterText(totpField, '12a34567');
    expect(totpController.text, '123456');
    await tester.enterText(totpField, '123');
    await tester.tap(find.text('Ingresar'));
    await tester.pumpAndSettle();
    expect(totpController.text, isEmpty);
    expect(
        find.text('Completa correo, contraseña y código TOTP de seis dígitos.'),
        findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('clears TOTP when the app pauses', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: VaultScreen()));
    final totpField = find.byType(TextField).at(2);
    final totpController = tester.widget<TextField>(totpField).controller!;
    await tester.enterText(totpField, '123456');
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    expect(totpController.text, isEmpty);
  });

  testWidgets('clears TOTP when the vault screen is abandoned', (tester) async {
    final api = TrackingVaultApiService();
    await tester.pumpWidget(MaterialApp(
        home: Builder(
            builder: (context) => FilledButton(
                onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => VaultScreen(api: api))),
                child: const Text('Abrir bóvedas')))));
    await tester.tap(find.text('Abrir bóvedas'));
    await tester.pumpAndSettle();

    final totpField = find.byType(TextField).at(2);
    final totpController = tester.widget<TextField>(totpField).controller!;
    await tester.enterText(totpField, '654321');
    Navigator.of(tester.element(totpField)).pop();
    await tester.pumpAndSettle();
    expect(totpController.text, isEmpty);
    expect(api.loggedOut, isTrue);
  });
}
