import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../../../services/vault_api_service.dart';

enum VaultEnvelopeFailure {
  network,
  sessionExpired,
  mfaRequired,
  devicePending,
  deviceRevoked,
  securityStateChanged,
  envelopeMissing,
  unauthorized,
  localAuthenticationRequired,
}

class VaultEnvelopeException implements Exception {
  const VaultEnvelopeException(this.failure);

  final VaultEnvelopeFailure failure;
}

abstract interface class VaultEnvelopeRepository {
  String get deviceId;

  Future<void> validateRemoteSession();
  Future<Map<String, dynamic>> fetchAuthorizedVault(String vaultId);
  Future<Uint8List> loadDeviceKey();
  Future<void> invalidateRemoteSession();
  void addInvalidationListener(VoidCallback listener);
  void removeInvalidationListener(VoidCallback listener);
}

class VaultApiEnvelopeRepository implements VaultEnvelopeRepository {
  VaultApiEnvelopeRepository(this._api);

  final VaultApiService _api;

  @override
  String get deviceId {
    try {
      return _api.deviceId;
    } on VaultApiException catch (error) {
      throw VaultEnvelopeException(_failureFor(error));
    }
  }

  @override
  Future<void> validateRemoteSession() => _map(_api.validateVaultSession);

  @override
  Future<Map<String, dynamic>> fetchAuthorizedVault(String vaultId) =>
      _map(() => _api.getVault(vaultId));

  @override
  Future<Uint8List> loadDeviceKey() => _map(_api.deviceKey);

  @override
  Future<void> invalidateRemoteSession() => _map(_api.revokeSession);

  @override
  void addInvalidationListener(VoidCallback listener) =>
      _api.addSessionInvalidationListener(listener);

  @override
  void removeInvalidationListener(VoidCallback listener) =>
      _api.removeSessionInvalidationListener(listener);

  Future<T> _map<T>(Future<T> Function() operation) async {
    try {
      return await operation();
    } on VaultApiException catch (error) {
      throw VaultEnvelopeException(_failureFor(error));
    } on TimeoutException {
      throw const VaultEnvelopeException(VaultEnvelopeFailure.network);
    } on SocketException {
      throw const VaultEnvelopeException(VaultEnvelopeFailure.network);
    } on http.ClientException {
      throw const VaultEnvelopeException(VaultEnvelopeFailure.network);
    }
  }

  VaultEnvelopeFailure _failureFor(VaultApiException error) {
    final message = error.message.toLowerCase();
    if (message.contains('desbloquea la aplicación')) {
      return VaultEnvelopeFailure.localAuthenticationRequired;
    }
    if (message.contains('mfa')) {
      return VaultEnvelopeFailure.mfaRequired;
    }
    if (message.contains('pend') || message.contains('trusted')) {
      return VaultEnvelopeFailure.devicePending;
    }
    if (message.contains('revocad')) {
      return error.statusCode == 401
          ? VaultEnvelopeFailure.sessionExpired
          : VaultEnvelopeFailure.deviceRevoked;
    }
    if (message.contains('seguridad cambi')) {
      return VaultEnvelopeFailure.securityStateChanged;
    }
    if (message.contains('sesión de bóveda no está activa') ||
        message.contains('inicia sesión nuevamente')) {
      return VaultEnvelopeFailure.sessionExpired;
    }
    if (message.contains('no disponible')) {
      return VaultEnvelopeFailure.envelopeMissing;
    }
    if (error.statusCode == 401) {
      return VaultEnvelopeFailure.sessionExpired;
    }
    if (error.statusCode == 403) {
      return VaultEnvelopeFailure.unauthorized;
    }
    return VaultEnvelopeFailure.network;
  }
}
