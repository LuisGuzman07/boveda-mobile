import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boveda_mobile/features/file_upload/data/presigned_ciphertext_uploader.dart';
import 'package:boveda_mobile/features/file_upload/domain/vault_file_picker.dart';
import 'package:boveda_mobile/features/file_upload/domain/vault_file_upload_api.dart';
import 'package:boveda_mobile/features/file_upload/presentation/vault_file_upload_controller.dart';
import 'package:boveda_mobile/features/vault_unlock/domain/vault_unlock_session.dart';
import 'package:boveda_mobile/services/vault_crypto_service.dart';
import 'package:crypto/crypto.dart' as hashes;
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

const _configPath = String.fromEnvironment('CU08_E2E_CONFIG');

class _E2EPicker implements VaultFilePicker {
  _E2EPicker(this.name, this._bytes);

  final String name;
  final Uint8List _bytes;

  @override
  Future<VaultPickedFile?> pickSingleFile() async => VaultPickedFile(
        name: name,
        length: () async => _bytes.length,
        readBytes: () async => Uint8List.fromList(_bytes),
        dispose: () async {},
      );
}

class _RecordingUploader implements PresignedCiphertextUploader {
  _RecordingUploader() : _delegate = HttpPresignedCiphertextUploader();

  final HttpPresignedCiphertextUploader _delegate;
  String? uploadUrl;
  Uint8List? ciphertext;

  @override
  Future<void> upload({
    required String uploadUrl,
    required Uint8List ciphertext,
    required bool Function() isCurrent,
    required CiphertextProgress onProgress,
  }) async {
    this.uploadUrl = uploadUrl;
    this.ciphertext = Uint8List.fromList(ciphertext);
    await _delegate.upload(
      uploadUrl: uploadUrl,
      ciphertext: ciphertext,
      isCurrent: isCurrent,
      onProgress: onProgress,
    );
  }

  @override
  void cancel() => _delegate.cancel();

  @override
  void dispose() {
    _delegate.dispose();
    ciphertext?.fillRange(0, ciphertext!.length, 0);
    ciphertext = null;
    uploadUrl = null;
  }
}

class _SignedUploadApi implements VaultFileUploadApi {
  _SignedUploadApi({
    required this.client,
    required this.signingKey,
    required this.baseUrl,
    required this.vaultToken,
  });

  final http.Client client;
  final SimpleKeyPair signingKey;
  final String baseUrl;
  final String vaultToken;
  String? completedFileId;
  String? completedVersionId;

  @override
  Future<Map<String, dynamic>> createFileUploadIntent(
    String vaultId,
    int ciphertextLength,
    String retryKey,
  ) async {
    final response = await _signedRequest(
      client: client,
      signingKey: signingKey,
      baseUrl: baseUrl,
      vaultToken: vaultToken,
      method: 'POST',
      path: '/vaults/$vaultId/files/upload-intents',
      body: <String, dynamic>{
        'tamano_ciphertext_esperado': ciphertextLength,
        'version_criptografica': 1,
      },
      retryKey: retryKey,
    );
    expect(response.statusCode, 201);
    return _jsonMap(response.body);
  }

  @override
  Future<Map<String, dynamic>> completeFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    Map<String, dynamic> body,
    String retryKey,
  ) async {
    final response = await _signedRequest(
      client: client,
      signingKey: signingKey,
      baseUrl: baseUrl,
      vaultToken: vaultToken,
      method: 'POST',
      path: '/vaults/$vaultId/files/$fileId/versions/$versionId/complete',
      body: body,
      retryKey: retryKey,
    );
    expect(response.statusCode, 200);
    completedFileId = fileId;
    completedVersionId = versionId;
    return _jsonMap(response.body);
  }

  @override
  Future<Map<String, dynamic>> abortFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    String retryKey,
  ) async {
    final response = await _signedRequest(
      client: client,
      signingKey: signingKey,
      baseUrl: baseUrl,
      vaultToken: vaultToken,
      method: 'POST',
      path: '/vaults/$vaultId/files/$fileId/versions/$versionId/abort',
      retryKey: retryKey,
    );
    expect(response.statusCode, 200);
    return _jsonMap(response.body);
  }
}

void main() {
  test(
    'encrypts, uploads and finalizes CU08 ciphertext over FastAPI and MinIO',
    skip: _configPath.isEmpty
        ? 'Requires the disposable CU08 E2E configuration.'
        : false,
    () async {
      final configFile = File(_configPath);
      final config = _jsonMap(await configFile.readAsString());
      final baseUrl = _requiredString(config, 'base_url');
      final vaultToken = _requiredString(config, 'vault_token');
      final deviceId = _requiredString(config, 'device_id');
      final password = _requiredString(config, 'master_password');
      final vaultName = _requiredString(config, 'vault_name');
      final vaultDescription = _requiredString(config, 'vault_description');
      final marker = _requiredString(config, 'plaintext_marker');
      final signingSeed = Uint8List.fromList(
        base64Decode(_requiredString(config, 'vault_signing_seed')),
      );
      final deviceKey = Uint8List.fromList(
        base64Decode(_requiredString(config, 'device_key')),
      );
      final signingKey =
          await Ed25519().newKeyPairFromSeed(Uint8List.fromList(signingSeed));
      final client = http.Client();
      final crypto = VaultCryptoService();
      final session = VaultUnlockSession();
      final uploader = _RecordingUploader();
      VaultFileUploadController? controller;
      VaultUnlockResult? unlockResult;
      Uint8List? plaintext;
      Uint8List? replacement;

      try {
        final createdBody = await crypto.prepare(
          name: vaultName,
          description: vaultDescription,
          password: password,
          deviceId: deviceId,
          deviceKey: deviceKey,
        );
        final created = await _signedRequest(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
          method: 'POST',
          path: '/vaults',
          body: createdBody,
          retryKey: 'cu08-e2e-create-vault-retry-0001',
        );
        expect(created.statusCode, 201);
        final vault = _jsonMap(created.body);
        final vaultId = _requiredString(vault, 'id_boveda');
        expect(vaultId, createdBody['id_boveda']);

        unlockResult = await crypto.unlock(
          vault: vault,
          password: password,
          deviceKey: deviceKey,
          expectedDeviceId: deviceId,
        );
        session.activate(
          vaultId: unlockResult.vaultId,
          cryptoVersion: unlockResult.cryptoVersion,
          vaultKey: unlockResult.takeVaultKey(),
        );
        final api = _SignedUploadApi(
          client: client,
          signingKey: signingKey,
          baseUrl: baseUrl,
          vaultToken: vaultToken,
        );
        plaintext = Uint8List.fromList(utf8.encode(marker));
        controller = VaultFileUploadController(
          vaultId: vaultId,
          api: api,
          session: session,
          picker: _E2EPicker('cu08-secret.txt', plaintext),
          uploader: uploader,
          crypto: crypto,
        );
        expect(await controller.selectFile(), isTrue);
        await controller.confirmSelectedFile();
        expect(controller.state, VaultFileUploadState.completed);

        final uploaded = uploader.ciphertext;
        final uploadUrl = uploader.uploadUrl;
        final fileId = api.completedFileId;
        final versionId = api.completedVersionId;
        expect(uploaded, isNotNull);
        expect(uploadUrl, isNotNull);
        expect(fileId, isNotNull);
        expect(versionId, isNotNull);
        final ciphertextSize = uploaded!.length;
        final ciphertextSha256 = hashes.sha256.convert(uploaded).toString();
        expect(utf8.decode(uploaded, allowMalformed: true), isNot(marker));

        // The pre-complete capability remains valid briefly, but only targets staging.
        replacement =
            Uint8List.fromList(List<int>.filled(ciphertextSize, 0x5a));
        final stagingRewrite = await _putBytes(client, uploadUrl!, replacement);
        expect(stagingRewrite.statusCode, inInclusiveRange(200, 299));

        final oversizedIntent = await api.createFileUploadIntent(
          vaultId,
          3,
          'cu08-e2e-oversized-intent-retry-0001',
        );
        final oversizedUrl = _requiredString(oversizedIntent, 'upload_url');
        final rejected = await _putBytes(
          client,
          oversizedUrl,
          Uint8List.fromList(<int>[1, 2, 3, 4]),
        );
        expect(rejected.statusCode < 200 || rejected.statusCode >= 300, isTrue);
        final oversizedFileId = _requiredString(oversizedIntent, 'id_archivo');
        final oversizedVersionId =
            _requiredString(oversizedIntent, 'id_version');
        final aborted = await api.abortFileUpload(
          vaultId,
          oversizedFileId,
          oversizedVersionId,
          'cu08-e2e-oversized-abort-retry-0001',
        );
        expect(aborted['estado'], 'ABORTED');

        config['vault_id'] = vaultId;
        config['file_id'] = fileId;
        config['version_id'] = versionId;
        config['ciphertext_size'] = ciphertextSize;
        config['ciphertext_sha256'] = ciphertextSha256;
        config['oversized_version_id'] = oversizedVersionId;
        config['cu08_flutter_complete'] = true;
        await configFile.writeAsString(jsonEncode(config));
      } finally {
        replacement?.fillRange(0, replacement.length, 0);
        plaintext?.fillRange(0, plaintext.length, 0);
        controller?.dispose();
        uploader.dispose();
        session.dispose();
        unlockResult?.dispose();
        signingSeed.fillRange(0, signingSeed.length, 0);
        deviceKey.fillRange(0, deviceKey.length, 0);
        signingKey.destroy();
        client.close();
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

Future<http.Response> _putBytes(
  http.Client client,
  String uploadUrl,
  Uint8List bytes,
) async {
  final request = http.StreamedRequest('PUT', Uri.parse(uploadUrl))
    ..contentLength = bytes.length
    ..followRedirects = false
    ..maxRedirects = 0
    ..headers['Content-Type'] = 'application/octet-stream';
  final responseFuture = client.send(request);
  request.sink.add(bytes);
  await request.sink.close();
  return http.Response.fromStream(await responseFuture);
}

Future<http.Response> _signedRequest({
  required http.Client client,
  required SimpleKeyPair signingKey,
  required String baseUrl,
  required String vaultToken,
  required String method,
  required String path,
  Map<String, dynamic>? body,
  String? retryKey,
}) async {
  final text = body == null ? '' : jsonEncode(body);
  final uri = Uri.parse('$baseUrl$path');
  final payload = _jsonMap(
    utf8.decode(
        base64Url.decode(base64Url.normalize(vaultToken.split('.')[1]))),
  );
  final timestamp = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
  final message = <String>[
    _requiredString(payload, 'jti'),
    timestamp,
    method,
    uri.path,
    retryKey ?? '',
    hashes.sha256.convert(utf8.encode(text)).toString(),
  ].join('\n');
  final signature =
      await Ed25519().sign(utf8.encode(message), keyPair: signingKey);
  final request = http.Request(method, uri)
    ..headers.addAll(<String, String>{
      'Authorization': 'Bearer $vaultToken',
      'Content-Type': 'application/json',
      'X-Vault-Timestamp': timestamp,
      'X-Vault-Signature': base64Encode(signature.bytes),
      if (retryKey != null) 'Idempotency-Key': retryKey,
    })
    ..body = text;
  return http.Response.fromStream(
    await client.send(request).timeout(const Duration(seconds: 20)),
  );
}

Map<String, dynamic> _jsonMap(String value) {
  final decoded = jsonDecode(value);
  if (decoded is! Map) {
    throw const FormatException('Expected a JSON object.');
  }
  return Map<String, dynamic>.from(decoded);
}

String _requiredString(Map<String, dynamic> values, String key) {
  final value = values[key];
  if (value is! String || value.isEmpty) {
    throw StateError('Missing $key in the E2E configuration.');
  }
  return value;
}
