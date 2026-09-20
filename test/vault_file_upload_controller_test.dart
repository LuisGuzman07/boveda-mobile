import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:boveda_mobile/features/file_upload/data/presigned_ciphertext_uploader.dart';
import 'package:boveda_mobile/features/file_upload/domain/vault_file_picker.dart';
import 'package:boveda_mobile/features/file_upload/domain/vault_file_upload_api.dart';
import 'package:boveda_mobile/features/file_upload/presentation/vault_file_upload_controller.dart';
import 'package:boveda_mobile/features/vault_unlock/domain/vault_unlock_session.dart';
import 'package:boveda_mobile/services/vault_crypto_service.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

const _vaultId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const _fileId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const _versionId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

class _FakeUploadApi implements VaultFileUploadApi {
  final intentRetryKeys = <String>[];
  final completeBodies = <Map<String, dynamic>>[];
  final abortRetryKeys = <String>[];
  String intentState = 'UPLOADING';

  @override
  Future<Map<String, dynamic>> createFileUploadIntent(
    String vaultId,
    int ciphertextLength,
    String retryKey,
  ) async {
    intentRetryKeys.add(retryKey);
    return <String, dynamic>{
      'id_archivo': _fileId,
      'id_version': _versionId,
      'estado': intentState,
      if (intentState == 'UPLOADING') ...<String, dynamic>{
        'upload_url':
            'https://storage.example.test/ciphertext/opaque-capability',
        'content_type': 'application/octet-stream',
      },
    };
  }

  @override
  Future<Map<String, dynamic>> completeFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    Map<String, dynamic> body,
    String retryKey,
  ) async {
    completeBodies.add(body);
    return <String, dynamic>{
      'id_archivo': fileId,
      'id_version': versionId,
      'estado': 'AVAILABLE',
    };
  }

  @override
  Future<Map<String, dynamic>> abortFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    String retryKey,
  ) async {
    abortRetryKeys.add(retryKey);
    return <String, dynamic>{
      'id_archivo': fileId,
      'id_version': versionId,
      'estado': 'ABORTED',
    };
  }
}

class _FakePicker implements VaultFilePicker {
  _FakePicker(this.name, this.bytes);

  final String name;
  final Uint8List bytes;
  bool disposed = false;

  @override
  Future<VaultPickedFile?> pickSingleFile() async => VaultPickedFile(
        name: name,
        length: () async => bytes.length,
        readBytes: () async => Uint8List.fromList(bytes),
        dispose: () async {
          disposed = true;
        },
      );
}

class _FakeUploader implements PresignedCiphertextUploader {
  _FakeUploader({this.failuresBeforeSuccess = 0});

  final int failuresBeforeSuccess;
  int calls = 0;
  bool cancelled = false;
  Uint8List? uploadedCiphertext;

  @override
  Future<void> upload({
    required String uploadUrl,
    required Uint8List ciphertext,
    required bool Function() isCurrent,
    required CiphertextProgress onProgress,
  }) async {
    calls++;
    if (!isCurrent()) {
      throw const PresignedCiphertextUploadException('Carga cancelada.');
    }
    onProgress(ciphertext.length, ciphertext.length);
    if (calls <= failuresBeforeSuccess) {
      throw const PresignedCiphertextUploadException('Error temporal.');
    }
    uploadedCiphertext = Uint8List.fromList(ciphertext);
  }

  @override
  void cancel() {
    cancelled = true;
  }

  @override
  void dispose() => cancel();
}

class _BlockingUploader implements PresignedCiphertextUploader {
  final started = Completer<void>();
  final released = Completer<void>();
  bool cancelled = false;

  @override
  Future<void> upload({
    required String uploadUrl,
    required Uint8List ciphertext,
    required bool Function() isCurrent,
    required CiphertextProgress onProgress,
  }) async {
    started.complete();
    await released.future;
    throw const PresignedCiphertextUploadException('Carga cancelada.');
  }

  @override
  void cancel() {
    cancelled = true;
    if (!released.isCompleted) {
      released.complete();
    }
  }

  @override
  void dispose() => cancel();
}

VaultUnlockSession _activeSession(Uint8List vaultKey) {
  final session = VaultUnlockSession();
  session.activate(vaultId: _vaultId, cryptoVersion: 1, vaultKey: vaultKey);
  return session;
}

VaultFileUploadController _controller({
  required VaultFileUploadApi api,
  required VaultUnlockSession session,
  required VaultFilePicker picker,
  required PresignedCiphertextUploader uploader,
  VaultCryptoService? crypto,
}) =>
    VaultFileUploadController(
      vaultId: _vaultId,
      api: api,
      session: session,
      picker: picker,
      uploader: uploader,
      crypto: crypto,
      clock: () => DateTime(2026, 9, 20, 9, 30),
    );

void main() {
  test('encrypts content and metadata before a ciphertext-only direct upload',
      () async {
    final vaultKey =
        Uint8List.fromList(List<int>.generate(32, (index) => index));
    final session = _activeSession(vaultKey);
    final api = _FakeUploadApi();
    final picker = _FakePicker(
      'tesis-secreta.pdf',
      Uint8List.fromList(utf8.encode('contenido confidencial')),
    );
    final uploader = _FakeUploader();
    final crypto = VaultCryptoService();
    final controller = _controller(
      api: api,
      session: session,
      picker: picker,
      uploader: uploader,
      crypto: crypto,
    );
    addTearDown(controller.dispose);
    addTearDown(session.dispose);

    expect(await controller.selectFile(), isTrue);
    expect(controller.state, VaultFileUploadState.awaitingConfirmation);
    await controller.confirmSelectedFile();

    expect(controller.state, VaultFileUploadState.completed);
    expect(picker.disposed, isTrue);
    expect(api.intentRetryKeys, hasLength(1));
    expect(api.completeBodies, hasLength(1));
    expect(uploader.uploadedCiphertext, isNotNull);
    expect(uploader.uploadedCiphertext, isNot(equals(picker.bytes)));

    final body = api.completeBodies.single;
    expect(body['tamano_ciphertext'], picker.bytes.length);
    expect(jsonEncode(body), isNot(contains('tesis-secreta.pdf')));
    expect(jsonEncode(body), isNot(contains('contenido confidencial')));
    final content = Map<String, dynamic>.from(body['contenido_cifrado'] as Map);
    final wrappedKey =
        Map<String, dynamic>.from(body['clave_archivo_envuelta'] as Map);
    final metadata = Map<String, dynamic>.from(body['metadata_cifrada'] as Map);
    expect(
      <String>{
        content['nonce'] as String,
        wrappedKey['nonce'] as String,
        metadata['nonce'] as String,
      },
      hasLength(3),
    );

    final fileKey = await crypto.decrypt(
      wrappedKey,
      SecretKey(vaultKey),
      '$_vaultId:$_fileId:$_versionId:dek:v1',
    );
    try {
      final contentEnvelope = <String, dynamic>{
        ...content,
        'ciphertext': base64Encode(uploader.uploadedCiphertext!),
      };
      final decryptedContent = await crypto.decrypt(
        contentEnvelope,
        SecretKey(fileKey),
        '$_vaultId:$_fileId:$_versionId:content:v1',
      );
      final decryptedMetadata = await crypto.decrypt(
        metadata,
        SecretKey(fileKey),
        '$_vaultId:$_fileId:$_versionId:metadata:v1',
      );
      expect(utf8.decode(decryptedContent), 'contenido confidencial');
      expect(
        jsonDecode(utf8.decode(decryptedMetadata)),
        <String, dynamic>{
          'nombre': 'tesis-secreta.pdf',
          'mime': 'application/pdf',
          'tamano_plaintext': picker.bytes.length,
          'checksum_plaintext_sha256':
              '7159b273eff24a975f690ca2c267383090278a334eef134b59945e969ba95a1a',
          'fecha_local': '2026-09-20T09:30:00.000',
        },
      );
      decryptedContent.fillRange(0, decryptedContent.length, 0);
      decryptedMetadata.fillRange(0, decryptedMetadata.length, 0);
    } finally {
      fileKey.fillRange(0, fileKey.length, 0);
    }
  });

  test('reuses the intent idempotency key when retrying encrypted material',
      () async {
    final session = _activeSession(Uint8List.fromList(List<int>.filled(32, 8)));
    final api = _FakeUploadApi();
    final controller = _controller(
      api: api,
      session: session,
      picker: _FakePicker('nota.txt', Uint8List.fromList(utf8.encode('nota'))),
      uploader: _FakeUploader(failuresBeforeSuccess: 1),
    );
    addTearDown(controller.dispose);
    addTearDown(session.dispose);

    expect(await controller.selectFile(), isTrue);
    await controller.confirmSelectedFile();
    expect(controller.state, VaultFileUploadState.failed);
    expect(controller.canRetry, isTrue);

    await controller.retry();

    expect(controller.state, VaultFileUploadState.completed);
    expect(api.intentRetryKeys, hasLength(2));
    expect(api.intentRetryKeys[1], api.intentRetryKeys.first);
  });

  test('manual cancellation aborts the reservation and clears local work',
      () async {
    final session = _activeSession(Uint8List.fromList(List<int>.filled(32, 3)));
    final api = _FakeUploadApi();
    final uploader = _BlockingUploader();
    final picker = _FakePicker(
        'cancelar.txt', Uint8List.fromList(utf8.encode('temporal')));
    final controller = _controller(
      api: api,
      session: session,
      picker: picker,
      uploader: uploader,
    );
    addTearDown(controller.dispose);
    addTearDown(session.dispose);

    expect(await controller.selectFile(), isTrue);
    final upload = controller.confirmSelectedFile();
    await uploader.started.future;
    await controller.cancel();
    await upload;

    expect(uploader.cancelled, isTrue);
    expect(api.abortRetryKeys, hasLength(1));
    expect(picker.disposed, isTrue);
    expect(controller.state, VaultFileUploadState.cancelled);
  });

  test('disposing an active controller aborts its server reservation',
      () async {
    final session = _activeSession(Uint8List.fromList(List<int>.filled(32, 6)));
    final api = _FakeUploadApi();
    final uploader = _BlockingUploader();
    final controller = _controller(
      api: api,
      session: session,
      picker: _FakePicker(
        'salir.txt',
        Uint8List.fromList(utf8.encode('temporal')),
      ),
      uploader: uploader,
    );
    addTearDown(session.dispose);

    expect(await controller.selectFile(), isTrue);
    final upload = controller.confirmSelectedFile();
    await uploader.started.future;

    controller.dispose();
    await Future<void>.delayed(Duration.zero);
    await upload;

    expect(uploader.cancelled, isTrue);
    expect(api.abortRetryKeys, hasLength(1));
  });
}
