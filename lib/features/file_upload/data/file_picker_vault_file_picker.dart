import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';

import '../domain/vault_file_picker.dart';

class FilePickerVaultFilePicker implements VaultFilePicker {
  @override
  Future<VaultPickedFile?> pickSingleFile() async {
    final result = await FilePicker.pickFiles(
      allowMultiple: false,
      withData: false,
      withReadStream: false,
    );
    if (result == null || result.files.isEmpty) {
      return null;
    }
    final selected = result.files.single;
    final source = selected.xFile;
    return VaultPickedFile(
      name: selected.name,
      length: () async => selected.size > 0 ? selected.size : await source.length(),
      readBytes: () async {
        try {
          return Uint8List.fromList(await source.readAsBytes());
        } finally {
          await _clearPluginTemporaryFiles();
        }
      },
      dispose: _clearPluginTemporaryFiles,
    );
  }

  Future<void> _clearPluginTemporaryFiles() async {
    try {
      await FilePicker.clearTemporaryFiles();
    } catch (_) {
      // Selection caches are best-effort cleanup and never block local wiping.
    }
  }
}
