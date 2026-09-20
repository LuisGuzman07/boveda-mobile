import 'package:boveda_mobile/config/app_config.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('allows only explicit local HTTP endpoints in debug', () {
    expect(
      AppConfig.validateApiUrl(
        'http://10.0.2.2:8000/api/v1',
        debugMode: true,
        releaseMode: false,
      ),
      'http://10.0.2.2:8000/api/v1',
    );
    expect(
      () => AppConfig.validateApiUrl(
        'http://192.168.1.10:8000/api/v1',
        debugMode: true,
        releaseMode: false,
      ),
      throwsStateError,
    );
  });

  test('requires HTTPS outside debug', () {
    expect(
      () => AppConfig.validateApiUrl(
        'http://localhost:8000/api/v1',
        debugMode: false,
        releaseMode: true,
      ),
      throwsStateError,
    );
    expect(
      AppConfig.validateApiUrl(
        'https://api.example.test/api/v1',
        debugMode: false,
        releaseMode: true,
      ),
      'https://api.example.test/api/v1',
    );
  });

  test('accepts direct upload capabilities only over trusted transport', () {
    expect(
      AppConfig.validateObjectStorageUploadUrl(
        'https://storage.example.test/bucket/opaque?signature=temporary',
        debugMode: false,
        releaseMode: true,
      ).host,
      'storage.example.test',
    );
    expect(
      AppConfig.validateObjectStorageUploadUrl(
        'http://10.0.2.2:9000/bucket/opaque?signature=temporary',
        debugMode: true,
        releaseMode: false,
      ).host,
      '10.0.2.2',
    );
    expect(
      () => AppConfig.validateObjectStorageUploadUrl(
        'http://storage.example.test/bucket/opaque?signature=temporary',
        debugMode: true,
        releaseMode: false,
      ),
      throwsStateError,
    );
    expect(
      () => AppConfig.validateObjectStorageUploadUrl(
        'https://user:secret@storage.example.test/bucket/opaque',
        debugMode: false,
        releaseMode: true,
      ),
      throwsStateError,
    );
  });
}
