import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/authenticator_account.dart';

class AccountStorageService {
  static const String _storageKey = 'boveda_authenticator_accounts';

  static Future<List<AuthenticatorAccount>> getAccounts() async {
    final prefs = await SharedPreferences.getInstance();
    final jsonList = prefs.getStringList(_storageKey);
    if (jsonList == null || jsonList.isEmpty) {
      return [];
    }
    return jsonList
        .map((item) => AuthenticatorAccount.fromJson(jsonDecode(item)))
        .toList();
  }

  static Future<void> saveAccount(AuthenticatorAccount account) async {
    final prefs = await SharedPreferences.getInstance();
    final accounts = await getAccounts();
    accounts.removeWhere((a) => a.id == account.id || (a.accountName == account.accountName && a.issuer == account.issuer));
    accounts.insert(0, account);

    final jsonList = accounts.map((a) => jsonEncode(a.toJson())).toList();
    await prefs.setStringList(_storageKey, jsonList);
  }

  static Future<void> deleteAccount(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final accounts = await getAccounts();
    accounts.removeWhere((a) => a.id == id);

    final jsonList = accounts.map((a) => jsonEncode(a.toJson())).toList();
    await prefs.setStringList(_storageKey, jsonList);
  }
}
