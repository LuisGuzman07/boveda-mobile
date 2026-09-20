import 'package:boveda_mobile/features/vault_unlock/data/vault_envelope_repository.dart';
import 'package:boveda_mobile/features/vault_unlock/presentation/vault_unlock_controller.dart';
import 'package:boveda_mobile/features/vault_unlock/presentation/vault_unlock_screen.dart';
import 'package:boveda_mobile/services/vault_api_service.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class _FailingRepository implements VaultEnvelopeRepository {
  final listeners = <VoidCallback>{};

  @override
  String get deviceId => '11111111-1111-4111-8111-111111111111';

  @override
  void addInvalidationListener(VoidCallback listener) =>
      listeners.add(listener);

  @override
  Future<Map<String, dynamic>> fetchAuthorizedVault(String vaultId) async =>
      throw const VaultEnvelopeException(VaultEnvelopeFailure.network);

  @override
  Future<void> invalidateRemoteSession() async {}

  @override
  Future<Uint8List> loadDeviceKey() async => Uint8List(32);

  @override
  void removeInvalidationListener(VoidCallback listener) =>
      listeners.remove(listener);

  @override
  Future<void> validateRemoteSession() async =>
      throw const VaultEnvelopeException(VaultEnvelopeFailure.network);
}

Widget _app(VaultUnlockController controller, {double textScale = 1}) {
  return MaterialApp(
    home: MediaQuery(
      data: MediaQueryData(
        size: const Size(320, 640),
        textScaler: TextScaler.linear(textScale),
      ),
      child: VaultUnlockScreen(
        api: VaultApiService(),
        vaultId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        controller: controller,
      ),
    ),
  );
}

void main() {
  testWidgets(
      'uses a protected password field and clears it after a failed attempt',
      (tester) async {
    final controller = VaultUnlockController(repository: _FailingRepository());
    addTearDown(controller.dispose);
    await tester.pumpWidget(_app(controller));

    final passwordField = find.byKey(const ValueKey('vault-unlock-password'));
    final field = tester.widget<TextField>(passwordField);
    expect(field.obscureText, isTrue);
    expect(field.autocorrect, isFalse);
    expect(field.enableSuggestions, isFalse);
    expect(field.enableIMEPersonalizedLearning, isFalse);
    expect(find.byTooltip('Mostrar contraseña'), findsOneWidget);

    await tester.enterText(passwordField, 'not persisted');
    await tester.pump();
    expect(tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNotNull);
    await tester.tap(find.byType(FilledButton));
    await tester.pumpAndSettle();

    expect(
      find.text(
          'No se pudo contactar al backend para autorizar la bóveda. Inténtalo nuevamente.'),
      findsOneWidget,
    );
    expect(tester.widget<TextField>(passwordField).controller!.text, isEmpty);
  });

  testWidgets('clears the password on every covered lifecycle state',
      (tester) async {
    final controller = VaultUnlockController(repository: _FailingRepository());
    addTearDown(controller.dispose);
    await tester.pumpWidget(_app(controller));
    final passwordField = find.byKey(const ValueKey('vault-unlock-password'));
    final field = tester.widget<TextField>(passwordField);

    for (final state in <AppLifecycleState>[
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ]) {
      await tester.enterText(passwordField, 'temporary value');
      tester.binding.handleAppLifecycleStateChanged(state);
      await tester.pump();
      expect(field.controller!.text, isEmpty,
          reason: '$state must clear input');
    }
  });

  testWidgets(
      'renders narrow high-scale text and locks an open in-memory session',
      (tester) async {
    final controller = VaultUnlockController(repository: _FailingRepository());
    addTearDown(controller.dispose);
    await tester.pumpWidget(_app(controller, textScale: 2));

    controller.session.activate(
      vaultId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      cryptoVersion: 1,
      vaultKey: Uint8List.fromList(List<int>.filled(32, 5)),
    );
    await tester.pumpAndSettle();

    expect(find.text('Bóveda desbloqueada'), findsOneWidget);
    expect(find.textContaining('operaciones de archivos'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.ensureVisible(find.text('Bloquear'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Bloquear'));
    await tester.pump();
    expect(controller.isUnlocked, isFalse);
  });
}
