import 'dart:typed_data';

abstract interface class VaultFilePicker {
  Future<VaultPickedFile?> pickSingleFile();
}

class VaultPickedFile {
  VaultPickedFile({
    required this.name,
    required Future<int> Function() length,
    required Future<Uint8List> Function() readBytes,
    required Future<void> Function() dispose,
  })  : _length = length,
        _readBytes = readBytes,
        _dispose = dispose;

  final String name;
  final Future<int> Function() _length;
  final Future<Uint8List> Function() _readBytes;
  final Future<void> Function() _dispose;
  bool _disposed = false;

  Future<int> length() => _length();

  Future<Uint8List> readBytes() => _readBytes();

  Future<void> dispose() async {
    if (_disposed) {
      return;
    }
    _disposed = true;
    await _dispose();
  }
}
