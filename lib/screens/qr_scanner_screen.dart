import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../services/app_lock_service.dart';
import '../widgets/app_lock_gate.dart';

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  final MobileScannerController _controller = MobileScannerController(
    detectionSpeed: DetectionSpeed.noDuplicates,
  );
  bool _isScanned = false;
  AppLockService? _lockService;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final lockService = AppLockScope.maybeOf(context);
    if (identical(lockService, _lockService)) {
      return;
    }
    _lockService?.removeListener(_onLockChanged);
    _lockService = lockService;
    _lockService?.addListener(_onLockChanged);
    if (!_canUseSensitiveFeatures) {
      _isScanned = true;
      unawaited(_controller.stop());
    }
  }

  @override
  void dispose() {
    _lockService?.removeListener(_onLockChanged);
    _controller.dispose();
    super.dispose();
  }

  bool get _canUseSensitiveFeatures =>
      _lockService == null || _lockService!.allowsSensitiveActions;

  void _onLockChanged() {
    if (!mounted) {
      return;
    }
    if (_canUseSensitiveFeatures) {
      _isScanned = false;
      unawaited(_controller.start());
      return;
    }
    _isScanned = true;
    unawaited(_controller.stop());
  }

  void _onDetect(BarcodeCapture capture) {
    if (_isScanned || !_canUseSensitiveFeatures || !mounted) return;
    final List<Barcode> barcodes = capture.barcodes;
    for (final barcode in barcodes) {
      final String? rawValue = barcode.rawValue;
      if (rawValue != null && rawValue.isNotEmpty) {
        _isScanned = true;
        _parseAndReturn(rawValue);
        break;
      }
    }
  }

  void _parseAndReturn(String raw) {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    String accountName = 'Bóveda';
    String secret = raw.trim();

    if (raw.startsWith('otpauth://')) {
      try {
        final uri = Uri.parse(raw);
        secret = uri.queryParameters['secret'] ?? secret;
        final issuer = uri.queryParameters['issuer'];

        String path = uri.path;
        if (path.startsWith('/totp/')) {
          path = path.substring(6);
        } else if (path.startsWith('/')) {
          path = path.substring(1);
        }
        path = Uri.decodeComponent(path);

        if (path.contains(':')) {
          final parts = path.split(':');
          accountName = parts.length > 1 ? parts[1].trim() : parts[0].trim();
        } else if (path.isNotEmpty) {
          accountName = path;
        } else if (issuer != null && issuer.isNotEmpty) {
          accountName = issuer;
        }
      } catch (_) {
        // Fallback
      }
    }

    Navigator.pop(context, {
      'accountName': accountName,
      'secret': secret.replaceAll(' ', '').toUpperCase(),
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Escanear Código QR',
            style: TextStyle(color: Colors.white, fontSize: 17)),
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
        actions: [
          IconButton(
            icon: const Icon(Icons.flash_on, color: Colors.white70),
            onPressed: _canUseSensitiveFeatures
                ? () => _controller.toggleTorch()
                : null,
          ),
          IconButton(
            icon: const Icon(Icons.flip_camera_android, color: Colors.white70),
            onPressed: _canUseSensitiveFeatures
                ? () => _controller.switchCamera()
                : null,
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
          ),
          // Cuadro visual guía
          Center(
            child: Container(
              width: 250,
              height: 250,
              decoration: BoxDecoration(
                border: Border.all(color: const Color(0xFF3B82F6), width: 3),
                borderRadius: BorderRadius.circular(16),
                boxShadow: [
                  BoxShadow(
                    color: const Color(0xFF3B82F6).withValues(alpha: 0.3),
                    blurRadius: 20,
                    spreadRadius: 2,
                  ),
                ],
              ),
            ),
          ),
          Positioned(
            bottom: 40,
            left: 20,
            right: 20,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B).withValues(alpha: 0.9),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white12),
              ),
              child: const Text(
                'Apunta la cámara hacia el código QR mostrado en la web de Bóveda',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white70, fontSize: 13),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
