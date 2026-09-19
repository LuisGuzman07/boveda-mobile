import 'dart:convert';

import 'package:boveda_mobile/models/authenticator_account.dart';
import 'package:boveda_mobile/services/account_storage_service.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeLegacyAccountStore implements LegacyAccountStore {
  FakeLegacyAccountStore(this.value);

  List<String>? value;
  bool failDelete = false;

  @override
  Future<void> delete() async {
    if (failDelete) {
      throw StateError('delete failed');
    }
    value = null;
  }

  @override
  Future<List<String>?> read() async => value;

  @override
  Future<void> write(List<String> newValue) async {
    value = List<String>.from(newValue);
  }
}

class FakeSecureAccountStore implements SecureAccountStore {
  String? value;
  bool failWrite = false;

  @override
  Future<String?> read() async => value;

  @override
  Future<void> write(String newValue) async {
    if (failWrite) {
      throw StateError('write failed');
    }
    value = newValue;
  }
}

AuthenticatorAccount account(String id) => AuthenticatorAccount(
      id: id,
      issuer: 'Test issuer',
      accountName: 'account-$id',
      secret: 'not-a-real-secret-$id',
      createdAt: DateTime.utc(2026, 1, 1),
    );

String legacyValue(AuthenticatorAccount value) => jsonEncode(value.toJson());

void main() {
  test('initializes a new installation in secure storage', () async {
    final secure = FakeSecureAccountStore();
    final repository = AccountStorageRepository(
      legacyStore: FakeLegacyAccountStore(null),
      secureStore: secure,
    );

    expect(await repository.getAccounts(), isEmpty);
    expect(secure.value, isNotNull);
  });

  test('migrates valid legacy accounts before deleting the legacy value',
      () async {
    final first = account('one');
    final second = account('two');
    final legacy =
        FakeLegacyAccountStore([legacyValue(first), legacyValue(second)]);
    final secure = FakeSecureAccountStore();
    final repository = AccountStorageRepository(
      legacyStore: legacy,
      secureStore: secure,
    );

    expect((await repository.getAccounts()).map((item) => item.id),
        ['one', 'two']);
    expect(secure.value, isNotNull);
    expect(legacy.value, isNull);
  });

  test('keeps legacy data when secure migration write fails', () async {
    final original = account('one');
    final legacy = FakeLegacyAccountStore([legacyValue(original)]);
    final secure = FakeSecureAccountStore()..failWrite = true;
    final repository = AccountStorageRepository(
      legacyStore: legacy,
      secureStore: secure,
    );

    expect((await repository.getAccounts()).single.id, 'one');
    expect(legacy.value, isNotNull);
    expect(secure.value, isNull);
    await expectLater(
      repository.saveAccount(account('two')),
      throwsA(isA<AccountStorageException>()),
    );
  });

  test('skips corrupt legacy entries without deleting the source data',
      () async {
    final valid = account('one');
    final legacy = FakeLegacyAccountStore(['not-json', legacyValue(valid)]);
    final secure = FakeSecureAccountStore();
    final repository = AccountStorageRepository(
      legacyStore: legacy,
      secureStore: secure,
    );

    expect((await repository.getAccounts()).map((item) => item.id), ['one']);
    expect(legacy.value, isNotNull);
    expect(secure.value, isNull);
  });

  test('repeated migration reads the verified secure copy without duplicates',
      () async {
    final original = account('one');
    final legacy = FakeLegacyAccountStore([legacyValue(original)]);
    final repository = AccountStorageRepository(
      legacyStore: legacy,
      secureStore: FakeSecureAccountStore(),
    );

    await repository.getAccounts();
    expect((await repository.getAccounts()).map((item) => item.id), ['one']);
  });
}
