import 'package:flutter/foundation.dart';
import 'package:cryptography/cryptography.dart';

import '../../../services/vault_crypto_service.dart';

typedef VaultClock = DateTime Function();

/// Holds the vault key only for the lifetime of the active local unlock.
class VaultUnlockSession extends ChangeNotifier {
  VaultUnlockSession({
    VaultClock? clock,
    this.timeout = const Duration(minutes: 5),
  })  : _clock = clock ?? DateTime.now,
        assert(timeout > Duration.zero);

  final VaultClock _clock;
  final Duration timeout;
  Uint8List? _vaultKey;
  String? _vaultId;
  int? _cryptoVersion;
  DateTime? _openedAt;
  DateTime? _expiresAt;
  int _generation = 0;
  bool _disposed = false;

  String? get vaultId => _vaultId;
  int? get cryptoVersion => _cryptoVersion;
  DateTime? get openedAt => _openedAt;
  DateTime? get expiresAt => _expiresAt;
  int get generation => _generation;
  bool get hasInMemoryKey => isActive;

  bool get isActive {
    expireIfNeeded();
    return _vaultKey != null;
  }

  bool isGenerationCurrent(int generation) =>
      isActive && generation == _generation;

  /// Encrypts a file key with the private in-memory vault key without exposing Kv.
  Future<Map<String, dynamic>> wrapFileKey({
    required VaultCryptoService crypto,
    required Uint8List fileKey,
    required String aad,
    required List<int> nonce,
  }) async {
    if (_disposed || !isActive) {
      throw StateError('La sesión de desbloqueo ya no está activa.');
    }
    final vaultKey = _vaultKey;
    if (vaultKey == null) {
      throw StateError('La sesión de desbloqueo ya no está activa.');
    }
    final generation = _generation;
    final wrappingKey = SecretKey(vaultKey);
    try {
      final envelope = await crypto.encrypt(
        fileKey,
        wrappingKey,
        aad,
        nonce: nonce,
      );
      if (!isGenerationCurrent(generation)) {
        throw StateError('La sesión de desbloqueo cambió durante el cifrado.');
      }
      return envelope;
    } finally {
      wrappingKey.destroy();
    }
  }

  void activate({
    required String vaultId,
    required int cryptoVersion,
    required Uint8List vaultKey,
  }) {
    if (_disposed) {
      vaultKey.fillRange(0, vaultKey.length, 0);
      throw StateError('La sesión de desbloqueo ya fue descartada.');
    }
    if (vaultKey.isEmpty) {
      throw ArgumentError.value(vaultKey, 'vaultKey', 'No puede estar vacía.');
    }
    _wipeKey();
    final now = _clock();
    _vaultKey = vaultKey;
    _vaultId = vaultId;
    _cryptoVersion = cryptoVersion;
    _openedAt = now;
    _expiresAt = now.add(timeout);
    _generation++;
    notifyListeners();
  }

  bool touch() {
    if (_disposed || expireIfNeeded() || _vaultKey == null) {
      return false;
    }
    _expiresAt = _clock().add(timeout);
    notifyListeners();
    return true;
  }

  bool expireIfNeeded() {
    final expiresAt = _expiresAt;
    if (_disposed || _vaultKey == null || expiresAt == null) {
      return false;
    }
    if (!_clock().isBefore(expiresAt)) {
      lock();
      return true;
    }
    return false;
  }

  void lock() {
    if (_disposed) {
      return;
    }
    _wipeKey();
    _vaultId = null;
    _cryptoVersion = null;
    _openedAt = null;
    _expiresAt = null;
    _generation++;
    notifyListeners();
  }

  void _wipeKey() {
    final vaultKey = _vaultKey;
    if (vaultKey != null) {
      vaultKey.fillRange(0, vaultKey.length, 0);
      _vaultKey = null;
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _wipeKey();
    _vaultId = null;
    _cryptoVersion = null;
    _openedAt = null;
    _expiresAt = null;
    _generation++;
    super.dispose();
  }
}
