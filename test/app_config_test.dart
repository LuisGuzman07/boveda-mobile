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
}
