import 'package:flutter/material.dart';
import '../models/authenticator_account.dart';
import '../services/account_storage_service.dart';
import '../services/app_lock_service.dart';
import '../widgets/app_lock_gate.dart';
import 'qr_scanner_screen.dart';

class AddAccountScreen extends StatefulWidget {
  final String? initialAccountName;
  final String? initialSecret;

  const AddAccountScreen({
    super.key,
    this.initialAccountName,
    this.initialSecret,
  });

  @override
  State<AddAccountScreen> createState() => _AddAccountScreenState();
}

class _AddAccountScreenState extends State<AddAccountScreen> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _nameController;
  late final TextEditingController _secretController;
  final _issuerController = TextEditingController(text: 'Bóveda Híbrida');
  bool _isLoading = false;
  AppLockService? _lockService;
  int _operation = 0;

  @override
  void initState() {
    super.initState();
    _nameController =
        TextEditingController(text: widget.initialAccountName ?? '');
    _secretController = TextEditingController(text: widget.initialSecret ?? '');
  }

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
      _operation++;
      _secretController.clear();
    }
  }

  @override
  void dispose() {
    _lockService?.removeListener(_onLockChanged);
    _nameController.dispose();
    _secretController.dispose();
    _issuerController.dispose();
    super.dispose();
  }

  bool get _canUseSensitiveFeatures =>
      _lockService == null || _lockService!.allowsSensitiveActions;

  bool _isCurrentOperation(int operation) =>
      mounted && _canUseSensitiveFeatures && operation == _operation;

  void _onLockChanged() {
    if (!mounted || _canUseSensitiveFeatures) {
      return;
    }
    _operation++;
    _secretController.clear();
    if (mounted) {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _scanQrCode() async {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    final result = await Navigator.push<Map<String, String>>(
      context,
      MaterialPageRoute(builder: (_) => const QrScannerScreen()),
    );

    if (result != null && mounted && _canUseSensitiveFeatures) {
      setState(() {
        _nameController.text = result['accountName'] ?? _nameController.text;
        _secretController.text = result['secret'] ?? _secretController.text;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Código QR escaneado con éxito'),
          backgroundColor: Color(0xFF10B981),
          duration: Duration(seconds: 2),
        ),
      );
    }
  }

  Future<void> _save() async {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    if (!_formKey.currentState!.validate()) return;

    final operation = ++_operation;
    setState(() => _isLoading = true);

    final cleanSecret =
        _secretController.text.trim().replaceAll(' ', '').toUpperCase();
    final account = AuthenticatorAccount(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      issuer: _issuerController.text.trim().isEmpty
          ? 'Bóveda Híbrida'
          : _issuerController.text.trim(),
      accountName: _nameController.text.trim(),
      secret: cleanSecret,
      createdAt: DateTime.now(),
    );

    try {
      await AccountStorageService.saveAccount(account);
    } on AccountStorageException catch (error) {
      if (_isCurrentOperation(operation)) {
        setState(() => _isLoading = false);
        if (!mounted) {
          return;
        }
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(error.message)),
        );
      }
      return;
    } catch (_) {
      if (_isCurrentOperation(operation)) {
        setState(() => _isLoading = false);
        if (!mounted) {
          return;
        }
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
              content: Text('No se pudo guardar la cuenta protegida.')),
        );
      }
      return;
    }

    if (_isCurrentOperation(operation)) {
      if (!mounted) {
        return;
      }
      Navigator.pop(context, true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        title: const Text(
          'Vincular Cuenta',
          style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
        ),
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20.0),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Botón principal: Escanear QR
              OutlinedButton.icon(
                onPressed: _canUseSensitiveFeatures ? _scanQrCode : null,
                icon: const Icon(Icons.qr_code_scanner_rounded, size: 24),
                label: const Text(
                  'Escanear Código QR de la Web',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                ),
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFF60A5FA),
                  side: const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  backgroundColor: const Color(0xFF1E293B),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10)),
                ),
              ),
              const SizedBox(height: 18),

              Row(
                children: [
                  const Expanded(child: Divider(color: Color(0xFF334155))),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 12),
                    child: Text(
                      'o ingresa los datos manualmente',
                      style: TextStyle(color: Colors.grey[400], fontSize: 12),
                    ),
                  ),
                  const Expanded(child: Divider(color: Color(0xFF334155))),
                ],
              ),
              const SizedBox(height: 18),

              TextFormField(
                controller: _nameController,
                enabled: _canUseSensitiveFeatures && !_isLoading,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Correo o Nombre de Cuenta',
                  labelStyle: TextStyle(color: Colors.grey[400]),
                  hintText: 'ej. admin@boveda.com',
                  hintStyle: TextStyle(color: Colors.grey[600]),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide:
                        const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
                  ),
                ),
                validator: (val) {
                  if (val == null || val.trim().isEmpty) {
                    return 'Ingresa el nombre de la cuenta o correo';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 16),
              TextFormField(
                controller: _secretController,
                enabled: _canUseSensitiveFeatures && !_isLoading,
                style: const TextStyle(
                  color: Colors.white,
                  fontFamily: 'monospace',
                  letterSpacing: 1.5,
                  fontWeight: FontWeight.bold,
                ),
                textCapitalization: TextCapitalization.characters,
                decoration: InputDecoration(
                  labelText: 'Clave Secreta (Base32)',
                  labelStyle: TextStyle(color: Colors.grey[400]),
                  hintText: 'ej. JBSWY3DPEHPK3PXP',
                  hintStyle:
                      TextStyle(color: Colors.grey[600], letterSpacing: 0),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide:
                        const BorderSide(color: Color(0xFF3B82F6), width: 1.5),
                  ),
                ),
                validator: (val) {
                  if (val == null || val.trim().isEmpty) {
                    return 'Ingresa la clave secreta';
                  }
                  final clean = val.trim().replaceAll(' ', '').toUpperCase();
                  if (RegExp(r'[^A-Z2-7]').hasMatch(clean)) {
                    return 'La clave solo debe contener letras A-Z y números 2-7';
                  }
                  if (clean.length < 8) {
                    return 'La clave secreta es demasiado corta';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 28),
              ElevatedButton.icon(
                onPressed:
                    _isLoading || !_canUseSensitiveFeatures ? null : _save,
                icon: const Icon(Icons.check_circle_rounded),
                label: Text(
                  _isLoading ? 'Guardando...' : 'Guardar y Generar Códigos',
                  style: const TextStyle(
                      fontSize: 16, fontWeight: FontWeight.bold),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF2563EB),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
