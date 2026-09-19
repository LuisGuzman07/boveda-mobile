import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/authenticator_account.dart';

class AccountStorageException implements Exception {
  AccountStorageException(this.message);

  final String message;

  @override
  String toString() => message;
}

abstract class LegacyAccountStore {
  Future<List<String>?> read();
  Future<void> write(List<String> value);
  Future<void> delete();
}

abstract class SecureAccountStore {
  Future<String?> read();
  Future<void> write(String value);
}

class SharedPreferencesLegacyAccountStore implements LegacyAccountStore {
  SharedPreferencesLegacyAccountStore(this._key);

  final String _key;

  @override
  Future<List<String>?> read() async {
    final preferences = await SharedPreferences.getInstance();
    return preferences.getStringList(_key);
  }

  @override
  Future<void> write(List<String> value) async {
    final preferences = await SharedPreferences.getInstance();
    if (!await preferences.setStringList(_key, value)) {
      throw AccountStorageException(
          'No se pudo guardar el almacenamiento legacy.');
    }
  }

  @override
  Future<void> delete() async {
    final preferences = await SharedPreferences.getInstance();
    if (!await preferences.remove(_key)) {
      throw AccountStorageException(
          'No se pudo limpiar el almacenamiento legacy.');
    }
  }
}

class FlutterSecureAccountStore implements SecureAccountStore {
  FlutterSecureAccountStore(this._key, {FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  final String _key;
  final FlutterSecureStorage _storage;

  @override
  Future<String?> read() => _storage.read(key: _key);

  @override
  Future<void> write(String value) => _storage.write(key: _key, value: value);
}

class AccountStorageService {
  static final AccountStorageRepository _repository =
      AccountStorageRepository();

  static Future<List<AuthenticatorAccount>> getAccounts() =>
      _repository.getAccounts();

  static Future<void> saveAccount(AuthenticatorAccount account) =>
      _repository.saveAccount(account);

  static Future<void> deleteAccount(String id) => _repository.deleteAccount(id);
}

class AccountStorageRepository {
  AccountStorageRepository({
    LegacyAccountStore? legacyStore,
    SecureAccountStore? secureStore,
  })  : _legacyStore = legacyStore ??
            SharedPreferencesLegacyAccountStore(_legacyStorageKey),
        _secureStore =
            secureStore ?? FlutterSecureAccountStore(_secureStorageKey);

  static const String _legacyStorageKey = 'boveda_authenticator_accounts';
  static const String _secureStorageKey = 'boveda_authenticator_accounts_v1';
  static const int _storageVersion = 1;

  final LegacyAccountStore _legacyStore;
  final SecureAccountStore _secureStore;
  Future<void> _operationTail = Future.value();

  Future<List<AuthenticatorAccount>> getAccounts() =>
      _runSerialized(() async => (await _loadAccounts()).accounts);

  Future<void> saveAccount(AuthenticatorAccount account) =>
      _runSerialized(() async {
        final snapshot = await _loadAccounts();
        _ensureWritable(snapshot);
        final accounts = List<AuthenticatorAccount>.from(snapshot.accounts)
          ..removeWhere((existing) =>
              existing.id == account.id ||
              (existing.accountName == account.accountName &&
                  existing.issuer == account.issuer))
          ..insert(0, account);
        await _writeVerifiedSecureAccounts(accounts);
      });

  Future<void> deleteAccount(String id) => _runSerialized(() async {
        final snapshot = await _loadAccounts();
        _ensureWritable(snapshot);
        final accounts = List<AuthenticatorAccount>.from(snapshot.accounts)
          ..removeWhere((account) => account.id == id);
        await _writeVerifiedSecureAccounts(accounts);
      });

  Future<T> _runSerialized<T>(Future<T> Function() action) {
    final next = _operationTail.then<T>((_) => action());
    _operationTail = next.then<void>(
      (_) {},
      onError: (Object _, StackTrace __) {},
    );
    return next;
  }

  Future<_StorageSnapshot> _loadAccounts() async {
    final secureValue = await _secureStore.read();
    if (secureValue != null) {
      final decoded = _decodeSecureAccounts(secureValue);
      return _StorageSnapshot(decoded.accounts, decoded.hasInvalidEntries);
    }

    final legacyValues = await _legacyStore.read();
    if (legacyValues == null) {
      return _initializeEmptySecureStorage();
    }

    final decoded = _decodeAccounts(legacyValues);
    if (decoded.hasInvalidEntries) {
      return _StorageSnapshot(decoded.accounts, true);
    }

    try {
      await _writeVerifiedSecureAccounts(decoded.accounts);
    } on AccountStorageException {
      return _StorageSnapshot(decoded.accounts, true);
    }

    try {
      await _legacyStore.delete();
    } catch (_) {
      // The verified secure copy remains authoritative if cleanup is interrupted.
    }
    return _StorageSnapshot(decoded.accounts, false);
  }

  Future<_StorageSnapshot> _initializeEmptySecureStorage() async {
    try {
      await _writeVerifiedSecureAccounts(const []);
      return const _StorageSnapshot([], false);
    } on AccountStorageException {
      return const _StorageSnapshot([], true);
    }
  }

  void _ensureWritable(_StorageSnapshot snapshot) {
    if (snapshot.requiresRecovery) {
      throw AccountStorageException(
        'El almacenamiento requiere recuperación antes de modificar cuentas.',
      );
    }
  }

  Future<void> _writeVerifiedSecureAccounts(
      List<AuthenticatorAccount> accounts) async {
    final payload = jsonEncode({
      'version': _storageVersion,
      'accounts': accounts.map((account) => account.toJson()).toList(),
    });

    try {
      await _secureStore.write(payload);
      final persisted = await _secureStore.read();
      if (persisted == null) {
        throw AccountStorageException(
          'No se pudo verificar el almacenamiento seguro.',
        );
      }
      final verified = _decodeSecureAccounts(persisted);
      if (verified.hasInvalidEntries ||
          !_sameAccounts(verified.accounts, accounts)) {
        throw AccountStorageException(
          'No se pudo verificar el almacenamiento seguro.',
        );
      }
    } on AccountStorageException {
      rethrow;
    } catch (_) {
      throw AccountStorageException(
          'No se pudo escribir el almacenamiento seguro.');
    }
  }

  _DecodedAccounts _decodeSecureAccounts(String payload) {
    try {
      final decoded = jsonDecode(payload);
      if (decoded is! Map ||
          decoded['version'] != _storageVersion ||
          decoded['accounts'] is! List) {
        return const _DecodedAccounts([], true);
      }
      return _decodeAccounts(decoded['accounts'] as List<dynamic>);
    } catch (_) {
      return const _DecodedAccounts([], true);
    }
  }

  _DecodedAccounts _decodeAccounts(Iterable<dynamic> values) {
    final accounts = <AuthenticatorAccount>[];
    var hasInvalidEntries = false;

    for (final value in values) {
      try {
        final dynamic decoded = value is String ? jsonDecode(value) : value;
        if (decoded is! Map) {
          throw const FormatException();
        }
        final account = AuthenticatorAccount.fromJson(
          Map<String, dynamic>.from(decoded),
        );
        if (account.id.isEmpty ||
            account.accountName.isEmpty ||
            account.secret.isEmpty) {
          throw const FormatException();
        }
        accounts.add(account);
      } catch (_) {
        hasInvalidEntries = true;
      }
    }

    return _DecodedAccounts(_deduplicate(accounts), hasInvalidEntries);
  }

  List<AuthenticatorAccount> _deduplicate(List<AuthenticatorAccount> accounts) {
    final ids = <String>{};
    final identities = <String>{};
    return accounts.where((account) {
      final identity = '${account.issuer}\u0000${account.accountName}';
      return ids.add(account.id) && identities.add(identity);
    }).toList();
  }

  bool _sameAccounts(
    List<AuthenticatorAccount> left,
    List<AuthenticatorAccount> right,
  ) {
    if (left.length != right.length) {
      return false;
    }
    for (var index = 0; index < left.length; index++) {
      if (jsonEncode(left[index].toJson()) !=
          jsonEncode(right[index].toJson())) {
        return false;
      }
    }
    return true;
  }
}

class _StorageSnapshot {
  const _StorageSnapshot(this.accounts, this.requiresRecovery);

  final List<AuthenticatorAccount> accounts;
  final bool requiresRecovery;
}

class _DecodedAccounts {
  const _DecodedAccounts(this.accounts, this.hasInvalidEntries);

  final List<AuthenticatorAccount> accounts;
  final bool hasInvalidEntries;
}
