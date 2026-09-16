import 'package:flutter/foundation.dart';

class AppConfig {
  static const String appName = 'Bóveda Híbrida Mobile';

  // Base URLs según el entorno de ejecución
  static const String _emulatorUrl = 'http://10.0.2.2:8000/api/v1';
  static const String _desktopOrWebUrl = 'http://localhost:8000/api/v1';
  
  // Si usas dispositivo físico conectado por Wi-Fi, reemplaza por la IP local de tu PC:
  static const String _customLanIpUrl = 'http://192.168.1.10:8000/api/v1';

  /// Obtiene la URL base adecuada según la plataforma
  static String get baseUrl {
    if (kIsWeb) {
      return _desktopOrWebUrl;
    }
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        // En emulador Android estándar se usa 10.0.2.2 para acceder al localhost de la máquina host
        return _emulatorUrl;
      case TargetPlatform.iOS:
      case TargetPlatform.windows:
      case TargetPlatform.macOS:
      case TargetPlatform.linux:
        return _desktopOrWebUrl;
      default:
        return _desktopOrWebUrl;
    }
  }

  static String get healthEndpoint => '$baseUrl/health';
  static String get databaseHealthEndpoint => '$baseUrl/health/database';
}
