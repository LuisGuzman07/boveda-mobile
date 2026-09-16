import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';

class ApiService {
  /// Verifica el estado de salud del servicio FastAPI
  static Future<Map<String, dynamic>> checkHealth() async {
    final uri = Uri.parse(AppConfig.healthEndpoint);
    final response = await http.get(uri).timeout(const Duration(seconds: 8));

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Error del servidor: código ${response.statusCode}');
    }
  }

  /// Verifica el estado de conexión de la base de datos PostgreSQL
  static Future<Map<String, dynamic>> checkDatabaseHealth() async {
    final uri = Uri.parse(AppConfig.databaseHealthEndpoint);
    final response = await http.get(uri).timeout(const Duration(seconds: 8));

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Error de base de datos: código ${response.statusCode}');
    }
  }
}
