import 'package:flutter/material.dart';
import '../config/app_config.dart';
import '../services/api_service.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  bool _isLoading = false;
  bool _backendOk = false;
  bool _dbOk = false;
  String _backendMessage = 'Sin verificar';
  String _dbMessage = 'Sin verificar';

  @override
  void initState() {
    super.initState();
    _checkStatus();
  }

  Future<void> _checkStatus() async {
    setState(() {
      _isLoading = true;
    });

    // 1. Backend Health Check
    try {
      final backendRes = await ApiService.checkHealth();
      if (backendRes['status'] == 'ok') {
        _backendOk = true;
        _backendMessage = 'Backend conectado correctamente';
      } else {
        _backendOk = false;
        _backendMessage = 'Respuesta inesperada del backend';
      }
    } catch (e) {
      _backendOk = false;
      _backendMessage = 'No se pudo conectar con el backend ($e)';
    }

    // 2. Database Health Check
    try {
      final dbRes = await ApiService.checkDatabaseHealth();
      if (dbRes['status'] == 'ok' && dbRes['database'] == 'connected') {
        _dbOk = true;
        _dbMessage = 'Base de datos conectada (PostgreSQL OK)';
      } else {
        _dbOk = false;
        _dbMessage = 'Base de datos desconectada';
      }
    } catch (e) {
      _dbOk = false;
      _dbMessage = 'Error en conexión a base de datos';
    }

    if (mounted) {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        title: const Text(
          'Bóveda Híbrida',
          style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
        ),
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Header card
            Container(
              padding: const EdgeInsets.all(16.0),
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF334155)),
              ),
              child: Column(
                children: [
                  const Icon(
                    Icons.security_rounded,
                    size: 48,
                    color: Color(0xFF3B82F6),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Estado de Conexión del Sistema',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'URL Base: ${AppConfig.baseUrl}',
                    style: const TextStyle(
                      fontSize: 12,
                      color: Color(0xFF94A3B8),
                      fontFamily: 'monospace',
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Backend Status Card
            _buildStatusCard(
              title: 'FastAPI Backend',
              subtitle: _backendMessage,
              isOk: _backendOk,
              isLoading: _isLoading,
              icon: Icons.api_rounded,
            ),
            const SizedBox(height: 14),

            // Database Status Card
            _buildStatusCard(
              title: 'PostgreSQL Database',
              subtitle: _dbMessage,
              isOk: _dbOk,
              isLoading: _isLoading,
              icon: Icons.storage_rounded,
            ),
            const SizedBox(height: 28),

            // Refresh button
            ElevatedButton.icon(
              onPressed: _isLoading ? null : _checkStatus,
              icon: _isLoading
                  ? const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : const Icon(Icons.refresh_rounded),
              label: Text(
                _isLoading ? 'Comprobando...' : 'Reintentar Conexión',
                style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusCard({
    required String title,
    required String subtitle,
    required bool isOk,
    required bool isLoading,
    required IconData icon,
  }) {
    Color cardBorder;
    Color cardBg;
    Color statusColor;
    String statusText;

    if (isLoading) {
      cardBorder = const Color(0xFFF59E0B).withOpacity(0.4);
      cardBg = const Color(0xFFF59E0B).withOpacity(0.1);
      statusColor = const Color(0xFFF59E0B);
      statusText = 'Verificando';
    } else if (isOk) {
      cardBorder = const Color(0xFF10B981).withOpacity(0.4);
      cardBg = const Color(0xFF10B981).withOpacity(0.1);
      statusColor = const Color(0xFF10B981);
      statusText = 'Online';
    } else {
      cardBorder = const Color(0xFFEF4444).withOpacity(0.4);
      cardBg = const Color(0xFFEF4444).withOpacity(0.1);
      statusColor = const Color(0xFFEF4444);
      statusText = 'Desconectado';
    }

    return Container(
      padding: const EdgeInsets.all(16.0),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: cardBorder),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Icon(icon, size: 36, color: statusColor),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      title,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                    const Spacer(),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: statusColor.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        statusText,
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                          color: statusColor,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  subtitle,
                  style: const TextStyle(
                    fontSize: 13,
                    color: Color(0xFFCBD5E1),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
