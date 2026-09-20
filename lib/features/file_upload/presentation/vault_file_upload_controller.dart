import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

import '../../../services/vault_crypto_service.dart';
import '../../vault_unlock/domain/vault_unlock_session.dart';
import '../data/presigned_ciphertext_uploader.dart';
import '../domain/vault_file_picker.dart';
import '../domain/vault_file_upload_api.dart';

enum VaultFileUploadState {
  idle,
  selecting,
  awaitingConfirmation,
  preparing,
  uploading,
  completing,
  completed,
  failed,
  cancelled,
}

class VaultFileUploadController extends ChangeNotifier {
  VaultFileUploadController({
    required this.vaultId,
    required VaultFileUploadApi api,
    required VaultUnlockSession session,
    required VaultFilePicker picker,
    required PresignedCiphertextUploader uploader,
    VaultCryptoService? crypto,
    DateTime Function()? clock,
  })  : _api = api,
        _session = session,
        _picker = picker,
        _uploader = uploader,
        _crypto = crypto ?? VaultCryptoService(),
        _clock = clock ?? DateTime.now {
    _session.addListener(_onUnlockSessionChanged);
  }

  static const maximumFileBytes = 20 * 1024 * 1024;

  final String vaultId;
  final VaultFileUploadApi _api;
  final VaultUnlockSession _session;
  final VaultFilePicker _picker;
  final PresignedCiphertextUploader _uploader;
  final VaultCryptoService _crypto;
  final DateTime Function() _clock;

  VaultFileUploadState _state = VaultFileUploadState.idle;
  VaultPickedFile? _pendingFile;
  String? _pendingName;
  int? _pendingLength;
  int? _pendingGeneration;
  _UploadReservation? _reservation;
  _EncryptedUploadArtifact? _artifact;
  String? _errorMessage;
  int _sentBytes = 0;
  int _totalBytes = 0;
  int _operation = 0;
  bool _disposed = false;

  VaultFileUploadState get state => _state;
  String? get pendingName => _pendingName;
  int? get pendingLength => _pendingLength;
  String? get errorMessage => _errorMessage;
  int get sentBytes => _sentBytes;
  int get totalBytes => _totalBytes;
  bool get hasPendingFile => _pendingFile != null;
  bool get isBusy => switch (_state) {
        VaultFileUploadState.selecting ||
        VaultFileUploadState.preparing ||
        VaultFileUploadState.uploading ||
        VaultFileUploadState.completing =>
          true,
        _ => false,
      };
  bool get canSelectFile => !isBusy && _hasBoundSession;
  bool get canRetry =>
      _state == VaultFileUploadState.failed &&
      _artifact != null &&
      _reservation != null &&
      _isSessionCurrent(_reservation!.generation);
  bool get canCancel =>
      _pendingFile != null || _reservation != null || isBusy || hasPendingFile;

  Future<bool> selectFile() async {
    if (_disposed || isBusy || !_hasBoundSession) {
      return false;
    }
    if (_pendingFile != null || _reservation != null || _artifact != null) {
      await cancel();
      if (_disposed || !_hasBoundSession) {
        return false;
      }
    }

    final operation = ++_operation;
    final generation = _session.generation;
    _state = VaultFileUploadState.selecting;
    _errorMessage = null;
    _notify();

    VaultPickedFile? picked;
    try {
      picked = await _picker.pickSingleFile();
      _ensureCurrent(operation, generation);
      if (picked == null) {
        _state = VaultFileUploadState.idle;
        _notify();
        return false;
      }
      final length = await picked.length();
      _ensureCurrent(operation, generation);
      if (length < 0 || length > maximumFileBytes) {
        await _disposePickedFile(picked);
        picked = null;
        _state = VaultFileUploadState.failed;
        _errorMessage = 'El archivo supera el límite de 20 MiB.';
        _notify();
        return false;
      }

      _pendingFile = picked;
      _pendingName = picked.name;
      _pendingLength = length;
      _pendingGeneration = generation;
      picked = null;
      _state = VaultFileUploadState.awaitingConfirmation;
      _notify();
      return true;
    } on _UploadCancelled {
      await _disposePickedFile(picked);
      return false;
    } catch (_) {
      await _disposePickedFile(picked);
      if (_isCurrent(operation, generation)) {
        _state = VaultFileUploadState.failed;
        _errorMessage = 'No se pudo preparar el archivo seleccionado.';
        _notify();
      }
      return false;
    }
  }

  Future<void> discardSelectedFile() async {
    final pending = _takePendingFile();
    _pendingLength = null;
    _pendingGeneration = null;
    if (pending == null) {
      return;
    }
    ++_operation;
    await _disposePickedFile(pending);
    if (!_disposed) {
      _state = VaultFileUploadState.idle;
      _errorMessage = null;
      _notify();
    }
  }

  Future<void> confirmSelectedFile() async {
    final name = _pendingName;
    final selected = _takePendingFile();
    final length = _pendingLength;
    final generation = _pendingGeneration;
    _pendingLength = null;
    _pendingGeneration = null;
    if (selected == null || length == null || generation == null || _disposed) {
      await _disposePickedFile(selected);
      return;
    }

    final operation = ++_operation;
    _state = VaultFileUploadState.preparing;
    _errorMessage = null;
    _sentBytes = 0;
    _totalBytes = length;
    _notify();

    Uint8List? plaintext;
    _UploadReservation? reservation;
    _EncryptedUploadArtifact? artifact;
    try {
      _ensureCurrent(operation, generation);
      plaintext = await selected.readBytes();
      _ensureCurrent(operation, generation);
      if (plaintext.length != length || plaintext.length > maximumFileBytes) {
        throw const _UploadFailure(
            'El archivo seleccionado cambió durante la carga.');
      }

      final intentRetryKey = VaultCryptoService.newId();
      final intent = await _api.createFileUploadIntent(
        vaultId,
        plaintext.length,
        intentRetryKey,
      );
      _ensureCurrent(operation, generation);
      reservation = _reservationFromIntent(
        intent,
        generation,
        intentRetryKey: intentRetryKey,
      );
      _reservation = reservation;
      final uploadUrl = _uploadUrlFromIntent(intent, reservation);

      artifact = await _encryptArtifact(plaintext, reservation, name ?? '');
      _ensureCurrent(operation, generation);
      _artifact = artifact;
      artifact = null;
      await _uploadAndComplete(operation, reservation, _artifact!, uploadUrl);
    } on _UploadCancelled {
      artifact?.dispose();
      await _finishCancelled(operation, reservation);
    } on _UploadFailure catch (error) {
      artifact?.dispose();
      await _finishFailure(operation, generation, reservation, error.message);
    } catch (_) {
      artifact?.dispose();
      await _finishFailure(
        operation,
        generation,
        reservation,
        'No se pudo cifrar ni cargar el archivo. Inténtalo nuevamente.',
      );
    } finally {
      plaintext?.fillRange(0, plaintext.length, 0);
      await _disposePickedFile(selected);
    }
  }

  Future<void> retry() async {
    final reservation = _reservation;
    final artifact = _artifact;
    if (_disposed ||
        _state != VaultFileUploadState.failed ||
        reservation == null ||
        artifact == null) {
      return;
    }

    final operation = ++_operation;
    _state = VaultFileUploadState.preparing;
    _errorMessage = null;
    _sentBytes = 0;
    _totalBytes = artifact.ciphertext.length;
    _notify();
    try {
      _ensureCurrent(operation, reservation.generation);
      final intent = await _api.createFileUploadIntent(
        vaultId,
        artifact.ciphertext.length,
        reservation.intentRetryKey,
      );
      _ensureCurrent(operation, reservation.generation);
      final retryReservation = _reservationFromIntent(
        intent,
        reservation.generation,
        intentRetryKey: reservation.intentRetryKey,
        completeRetryKey: reservation.completeRetryKey,
        abortRetryKey: reservation.abortRetryKey,
      );
      if (!reservation.matches(retryReservation)) {
        throw const _UploadFailure('La reserva de carga ya no coincide.');
      }
      if (intent['estado'] == 'AVAILABLE') {
        _markCompleted(operation, reservation);
        return;
      }
      final uploadUrl = _uploadUrlFromIntent(intent, reservation);
      await _uploadAndComplete(operation, reservation, artifact, uploadUrl);
    } on _UploadCancelled {
      await _finishCancelled(operation, reservation);
    } on _UploadFailure catch (error) {
      await _finishFailure(
        operation,
        reservation.generation,
        reservation,
        error.message,
      );
    } catch (_) {
      await _finishFailure(
        operation,
        reservation.generation,
        reservation,
        'No se pudo reintentar la carga cifrada.',
      );
    }
  }

  Future<void> cancel() async {
    if (_disposed) {
      return;
    }
    final pending = _takePendingFile();
    _pendingLength = null;
    _pendingGeneration = null;
    final reservation = _reservation;
    ++_operation;
    _uploader.cancel();
    _clearActiveUpload();
    _state = VaultFileUploadState.cancelled;
    _errorMessage = null;
    _sentBytes = 0;
    _totalBytes = 0;
    _notify();

    await _disposePickedFile(pending);
    if (reservation != null) {
      await _abortReservation(reservation);
    }
  }

  Future<_EncryptedUploadArtifact> _encryptArtifact(
    Uint8List plaintext,
    _UploadReservation reservation,
    String name,
  ) async {
    final contentNonce = _newNonce(<String>{});
    final wrappingNonce = _newNonce(<String>{base64Encode(contentNonce)});
    final metadataNonce = _newNonce(<String>{
      base64Encode(contentNonce),
      base64Encode(wrappingNonce),
    });
    final fileKey = VaultCryptoService.randomBytes(32);
    final secretKey = SecretKey(fileKey);
    VaultAesGcmCiphertext? content;
    VaultAesGcmCiphertext? metadata;
    Uint8List? metadataBytes;
    try {
      final aadPrefix =
          '$vaultId:${reservation.fileId}:${reservation.versionId}';
      content = await _crypto.encryptBytes(
        plaintext,
        secretKey,
        '$aadPrefix:content:v1',
        nonce: contentNonce,
      );
      final wrappedFileKey = await _session.wrapFileKey(
        crypto: _crypto,
        fileKey: fileKey,
        aad: '$aadPrefix:dek:v1',
        nonce: wrappingNonce,
      );
      metadataBytes = Uint8List.fromList(
        utf8.encode(
          jsonEncode(<String, dynamic>{
            'nombre': name,
            'mime': _mimeTypeFor(name),
            'tamano_plaintext': plaintext.length,
            'checksum_plaintext_sha256':
                hashes.sha256.convert(plaintext).toString(),
            'fecha_local': _clock().toIso8601String(),
          }),
        ),
      );
      metadata = await _crypto.encryptBytes(
        metadataBytes,
        secretKey,
        '$aadPrefix:metadata:v1',
        nonce: metadataNonce,
      );
      final encryptedContent = content;
      final artifact = _EncryptedUploadArtifact(
        content: encryptedContent,
        contentInfo: encryptedContent.toContentInfoJson(),
        wrappedFileKey: wrappedFileKey,
        encryptedMetadata: metadata.toEnvelopeJson(),
      );
      content = null;
      return artifact;
    } finally {
      content?.dispose();
      metadata?.dispose();
      metadataBytes?.fillRange(0, metadataBytes.length, 0);
      contentNonce.fillRange(0, contentNonce.length, 0);
      wrappingNonce.fillRange(0, wrappingNonce.length, 0);
      metadataNonce.fillRange(0, metadataNonce.length, 0);
      fileKey.fillRange(0, fileKey.length, 0);
      secretKey.destroy();
    }
  }

  Future<void> _uploadAndComplete(
    int operation,
    _UploadReservation reservation,
    _EncryptedUploadArtifact artifact,
    String uploadUrl,
  ) async {
    _ensureCurrent(operation, reservation.generation);
    _state = VaultFileUploadState.uploading;
    _sentBytes = 0;
    _totalBytes = artifact.ciphertext.length;
    _notify();
    await _uploader.upload(
      uploadUrl: uploadUrl,
      ciphertext: artifact.ciphertext,
      isCurrent: () => _isCurrent(operation, reservation.generation),
      onProgress: (sentBytes, totalBytes) {
        if (!_isCurrent(operation, reservation.generation)) {
          return;
        }
        _sentBytes = sentBytes;
        _totalBytes = totalBytes;
        _notify();
      },
    );
    _ensureCurrent(operation, reservation.generation);
    _state = VaultFileUploadState.completing;
    _notify();
    final result = await _api.completeFileUpload(
      vaultId,
      reservation.fileId,
      reservation.versionId,
      artifact.completeBody(),
      reservation.completeRetryKey,
    );
    _ensureCurrent(operation, reservation.generation);
    if (result['id_archivo'] != reservation.fileId ||
        result['id_version'] != reservation.versionId ||
        result['estado'] != 'AVAILABLE') {
      throw const _UploadFailure('La confirmación de la carga no es válida.');
    }
    _markCompleted(operation, reservation);
  }

  _UploadReservation _reservationFromIntent(
    Map<String, dynamic> intent,
    int generation, {
    required String intentRetryKey,
    String? completeRetryKey,
    String? abortRetryKey,
  }) {
    final fileId = _requiredResponseString(intent, 'id_archivo');
    final versionId = _requiredResponseString(intent, 'id_version');
    return _UploadReservation(
      fileId: fileId,
      versionId: versionId,
      generation: generation,
      intentRetryKey: intentRetryKey,
      completeRetryKey: completeRetryKey ?? VaultCryptoService.newId(),
      abortRetryKey: abortRetryKey ?? VaultCryptoService.newId(),
    );
  }

  String _uploadUrlFromIntent(
    Map<String, dynamic> intent,
    _UploadReservation reservation,
  ) {
    if (intent['id_archivo'] != reservation.fileId ||
        intent['id_version'] != reservation.versionId ||
        intent['estado'] != 'UPLOADING' ||
        intent['content_type'] != 'application/octet-stream') {
      throw const _UploadFailure('La reserva de carga no es válida.');
    }
    return _requiredResponseString(intent, 'upload_url');
  }

  Future<void> _finishCancelled(
    int operation,
    _UploadReservation? reservation,
  ) async {
    if (reservation != null && identical(_reservation, reservation)) {
      await _abortReservation(reservation);
      _clearActiveUpload();
    }
    if (!_disposed && _operation == operation) {
      _state = VaultFileUploadState.cancelled;
      _errorMessage = null;
      _sentBytes = 0;
      _totalBytes = 0;
      _notify();
    }
  }

  Future<void> _finishFailure(
    int operation,
    int generation,
    _UploadReservation? reservation,
    String message,
  ) async {
    if (!_isCurrent(operation, generation)) {
      await _finishCancelled(operation, reservation);
      return;
    }
    if (_artifact == null ||
        reservation == null ||
        !identical(_reservation, reservation)) {
      if (reservation != null) {
        await _abortReservation(reservation);
      }
      _clearActiveUpload();
    }
    if (_isCurrent(operation, generation)) {
      _state = VaultFileUploadState.failed;
      _errorMessage = message;
      _notify();
    }
  }

  void _markCompleted(int operation, _UploadReservation reservation) {
    if (!_isCurrent(operation, reservation.generation)) {
      throw const _UploadCancelled();
    }
    _clearActiveUpload();
    _state = VaultFileUploadState.completed;
    _errorMessage = null;
    _notify();
  }

  Future<void> _abortReservation(_UploadReservation reservation) async {
    if (!_isSessionCurrent(reservation.generation)) {
      return;
    }
    try {
      await _api.abortFileUpload(
        vaultId,
        reservation.fileId,
        reservation.versionId,
        reservation.abortRetryKey,
      );
    } catch (_) {
      // The server expires unrecoverable uploads and the reconciler removes staging data.
    }
  }

  VaultPickedFile? _takePendingFile() {
    final pending = _pendingFile;
    _pendingFile = null;
    _pendingName = null;
    return pending;
  }

  void _clearActiveUpload() {
    _artifact?.dispose();
    _artifact = null;
    _reservation = null;
  }

  bool get _hasBoundSession => _session.isActive && _session.vaultId == vaultId;

  bool _isSessionCurrent(int generation) =>
      _hasBoundSession && _session.isGenerationCurrent(generation);

  bool _isCurrent(int operation, int generation) =>
      !_disposed && operation == _operation && _isSessionCurrent(generation);

  void _ensureCurrent(int operation, int generation) {
    if (!_isCurrent(operation, generation)) {
      throw const _UploadCancelled();
    }
  }

  void _onUnlockSessionChanged() {
    if (_disposed || _hasBoundSession) {
      return;
    }
    unawaited(cancel());
  }

  void _notify() {
    if (!_disposed) {
      notifyListeners();
    }
  }

  @override
  void dispose() {
    final reservation = _reservation;
    if (reservation != null) {
      // Start the authenticated abort before locking makes the vault session unusable.
      unawaited(_abortReservation(reservation));
    }
    _disposed = true;
    ++_operation;
    final pending = _takePendingFile();
    _pendingLength = null;
    _pendingGeneration = null;
    _clearActiveUpload();
    _uploader.dispose();
    _session.removeListener(_onUnlockSessionChanged);
    if (pending != null) {
      unawaited(_disposePickedFile(pending));
    }
    super.dispose();
  }

  static Future<void> _disposePickedFile(VaultPickedFile? picked) async {
    if (picked == null) {
      return;
    }
    try {
      await picked.dispose();
    } catch (_) {
      // Plugin cache cleanup is best effort; plaintext buffers are still wiped locally.
    }
  }

  static String _requiredResponseString(Map<String, dynamic> body, String key) {
    final value = body[key];
    if (value is! String || value.isEmpty) {
      throw const _UploadFailure('El backend devolvió una reserva inválida.');
    }
    return value;
  }

  static Uint8List _newNonce(Set<String> used) {
    while (true) {
      final nonce = VaultCryptoService.randomBytes(12);
      if (used.add(base64Encode(nonce))) {
        return nonce;
      }
      nonce.fillRange(0, nonce.length, 0);
    }
  }

  static String _mimeTypeFor(String name) {
    final extension = name.toLowerCase().split('.').last;
    return switch (extension) {
      'pdf' => 'application/pdf',
      'png' => 'image/png',
      'jpg' || 'jpeg' => 'image/jpeg',
      'gif' => 'image/gif',
      'txt' => 'text/plain',
      'csv' => 'text/csv',
      'json' => 'application/json',
      'docx' =>
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xlsx' =>
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      _ => 'application/octet-stream',
    };
  }
}

class _UploadReservation {
  const _UploadReservation({
    required this.fileId,
    required this.versionId,
    required this.generation,
    required this.intentRetryKey,
    required this.completeRetryKey,
    required this.abortRetryKey,
  });

  final String fileId;
  final String versionId;
  final int generation;
  final String intentRetryKey;
  final String completeRetryKey;
  final String abortRetryKey;

  bool matches(_UploadReservation other) =>
      fileId == other.fileId && versionId == other.versionId;
}

class _EncryptedUploadArtifact {
  _EncryptedUploadArtifact({
    required VaultAesGcmCiphertext content,
    required this.contentInfo,
    required this.wrappedFileKey,
    required this.encryptedMetadata,
  }) : _content = content;

  VaultAesGcmCiphertext? _content;
  final Map<String, dynamic> contentInfo;
  final Map<String, dynamic> wrappedFileKey;
  final Map<String, dynamic> encryptedMetadata;

  Uint8List get ciphertext {
    final value = _content;
    if (value == null) {
      throw StateError('El material de carga ya fue descartado.');
    }
    return value.ciphertext;
  }

  Map<String, dynamic> completeBody() => <String, dynamic>{
        'tamano_ciphertext': ciphertext.length,
        'checksum_ciphertext_sha256':
            hashes.sha256.convert(ciphertext).toString(),
        'contenido_cifrado': Map<String, dynamic>.from(contentInfo),
        'clave_archivo_envuelta': Map<String, dynamic>.from(wrappedFileKey),
        'metadata_cifrada': Map<String, dynamic>.from(encryptedMetadata),
        'version_criptografica': 1,
      };

  void dispose() {
    _content?.dispose();
    _content = null;
    contentInfo.clear();
    wrappedFileKey.clear();
    encryptedMetadata.clear();
  }
}

class _UploadCancelled implements Exception {
  const _UploadCancelled();
}

class _UploadFailure implements Exception {
  const _UploadFailure(this.message);

  final String message;
}
