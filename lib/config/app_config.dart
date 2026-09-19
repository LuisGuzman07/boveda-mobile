import 'package:flutter/foundation.dart';

class AppConfig {
  static const String appName = 'Bóveda Híbrida Mobile';
  static const String configuredApiUrl =
      String.fromEnvironment('BOVEDA_API_URL');
  static const Set<String> _debugHttpHosts = {
    'localhost',
    '127.0.0.1',
    '10.0.2.2',
  };

  static String get baseUrl => resolveApiUrl(
        configuredUrl: configuredApiUrl,
        port: 8000,
      );

  static String get healthEndpoint => '$baseUrl/health';
  static String get databaseHealthEndpoint => '$baseUrl/health/database';

  static String resolveApiUrl({
    String? configuredUrl,
    required int port,
    bool? debugMode,
    bool? releaseMode,
    bool? web,
    TargetPlatform? platform,
  }) {
    final isWeb = web ?? kIsWeb;
    final targetPlatform = platform ?? defaultTargetPlatform;
    final candidate = configuredUrl?.trim().isNotEmpty == true
        ? configuredUrl!.trim()
        : _developmentUrl(
            port: port,
            web: isWeb,
            platform: targetPlatform,
          );
    return validateApiUrl(
      candidate,
      debugMode: debugMode,
      releaseMode: releaseMode,
    );
  }

  static String validateApiUrl(
    String value, {
    bool? debugMode,
    bool? releaseMode,
  }) {
    final isDebug = debugMode ?? kDebugMode;
    final isRelease = releaseMode ?? kReleaseMode;
    late Uri uri;
    try {
      uri = Uri.parse(value);
    } on FormatException {
      throw StateError('La URL de la API debe ser absoluta y válida.');
    }

    if (!uri.hasScheme || !uri.hasAuthority || uri.userInfo.isNotEmpty) {
      throw StateError(
          'La URL de la API debe ser absoluta y no incluir credenciales.');
    }
    if (uri.scheme == 'https') {
      return uri.toString().replaceFirst(RegExp(r'/$'), '');
    }
    if (uri.scheme == 'http' && isDebug && !isRelease) {
      if (_debugHttpHosts.contains(uri.host.toLowerCase())) {
        return uri.toString().replaceFirst(RegExp(r'/$'), '');
      }
    }

    throw StateError(
      'HTTP solo está permitido para localhost, 127.0.0.1 o 10.0.2.2 en debug.',
    );
  }

  static String _developmentUrl({
    required int port,
    required bool web,
    required TargetPlatform platform,
  }) {
    final host =
        !web && platform == TargetPlatform.android ? '10.0.2.2' : 'localhost';
    return 'http://$host:$port/api/v1';
  }
}
