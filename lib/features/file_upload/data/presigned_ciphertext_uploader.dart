import 'dart:async';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../../../config/app_config.dart';

class PresignedCiphertextUploadException implements Exception {
  const PresignedCiphertextUploadException(this.message);

  final String message;

  @override
  String toString() => message;
}

typedef CiphertextProgress = void Function(int sentBytes, int totalBytes);

abstract interface class PresignedCiphertextUploader {
  Future<void> upload({
    required String uploadUrl,
    required Uint8List ciphertext,
    required bool Function() isCurrent,
    required CiphertextProgress onProgress,
  });

  void cancel();
  void dispose();
}

class HttpPresignedCiphertextUploader implements PresignedCiphertextUploader {
  HttpPresignedCiphertextUploader({http.Client Function()? clientFactory})
      : _clientFactory = clientFactory ?? http.Client.new;

  static const _chunkSize = 64 * 1024;

  final http.Client Function() _clientFactory;
  http.Client? _activeClient;
  bool _cancelled = false;

  @override
  Future<void> upload({
    required String uploadUrl,
    required Uint8List ciphertext,
    required bool Function() isCurrent,
    required CiphertextProgress onProgress,
  }) async {
    if (_activeClient != null) {
      throw const PresignedCiphertextUploadException(
          'Ya existe una carga activa.');
    }
    Uri uri;
    try {
      uri = AppConfig.validateObjectStorageUploadUrl(uploadUrl);
    } on StateError {
      throw const PresignedCiphertextUploadException(
        'La autorización temporal de carga no es válida.',
      );
    }

    final client = _clientFactory();
    _activeClient = client;
    _cancelled = false;
    final request = http.StreamedRequest('PUT', uri)
      ..contentLength = ciphertext.length
      ..followRedirects = false
      ..maxRedirects = 0
      ..headers['Content-Type'] = 'application/octet-stream';
    try {
      final responseFuture = client.send(request);
      var sent = 0;
      while (sent < ciphertext.length) {
        if (_cancelled || !isCurrent()) {
          throw const PresignedCiphertextUploadException('Carga cancelada.');
        }
        final end = (sent + _chunkSize).clamp(0, ciphertext.length).toInt();
        request.sink.add(Uint8List.sublistView(ciphertext, sent, end));
        sent = end;
        onProgress(sent, ciphertext.length);
        await Future<void>.delayed(Duration.zero);
      }
      await request.sink.close();
      final response =
          await responseFuture.timeout(const Duration(seconds: 30));
      await response.stream.drain<void>();
      if (_cancelled || !isCurrent()) {
        throw const PresignedCiphertextUploadException('Carga cancelada.');
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw const PresignedCiphertextUploadException(
          'No se pudo enviar el ciphertext al almacenamiento cifrado.',
        );
      }
    } on TimeoutException {
      throw const PresignedCiphertextUploadException(
        'La carga del ciphertext agotó el tiempo de espera.',
      );
    } on http.ClientException {
      if (_cancelled) {
        throw const PresignedCiphertextUploadException('Carga cancelada.');
      }
      throw const PresignedCiphertextUploadException(
        'No se pudo conectar con el almacenamiento cifrado.',
      );
    } finally {
      if (identical(_activeClient, client)) {
        _activeClient = null;
      }
      client.close();
    }
  }

  @override
  void cancel() {
    _cancelled = true;
    _activeClient?.close();
    _activeClient = null;
  }

  @override
  void dispose() => cancel();
}
