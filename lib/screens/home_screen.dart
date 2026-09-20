import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/authenticator_account.dart';
import '../services/account_storage_service.dart';
import '../services/app_lock_service.dart';
import '../services/installation_identity_service.dart';
import '../services/totp_service.dart';
import '../widgets/app_lock_gate.dart';
import 'add_account_screen.dart';
import 'qr_scanner_screen.dart';
import 'vault_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, this.installationIdentity});

  final InstallationIdentityProvider? installationIdentity;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<AuthenticatorAccount> _accounts = [];
  bool _isLoading = true;
  Timer? _timer;
  int _remainingSeconds = 30;
  double _progress = 1.0;
  AppLockService? _lockService;
  String? _storageError;

  @override
  void initState() {
    super.initState();
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
    if (_canUseSensitiveFeatures) {
      _loadAccounts();
      _startTimer();
    }
  }

  @override
  void dispose() {
    _lockService?.removeListener(_onLockChanged);
    _timer?.cancel();
    super.dispose();
  }

  bool get _canUseSensitiveFeatures =>
      _lockService == null || _lockService!.allowsSensitiveActions;

  void _onLockChanged() {
    if (!mounted) {
      return;
    }
    if (!_canUseSensitiveFeatures) {
      _timer?.cancel();
      _timer = null;
      setState(() {
        _accounts = <AuthenticatorAccount>[];
        _isLoading = false;
        _storageError = null;
      });
      return;
    }
    _loadAccounts();
    _startTimer();
  }

  void _startTimer() {
    _timer?.cancel();
    if (!_canUseSensitiveFeatures) {
      return;
    }
    _updateProgress();
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted && _canUseSensitiveFeatures) {
        setState(() {
          _updateProgress();
        });
      }
    });
  }

  void _updateProgress() {
    _remainingSeconds = TotpService.getRemainingSeconds();
    _progress = TotpService.getProgress();
  }

  Future<void> _loadAccounts() async {
    if (!_canUseSensitiveFeatures) {
      return;
    }
    if (mounted && !_isLoading) {
      setState(() {
        _isLoading = true;
        _storageError = null;
      });
    }
    try {
      final accounts = await AccountStorageService.getAccounts();
      if (!mounted || !_canUseSensitiveFeatures) {
        return;
      }
      setState(() {
        _accounts = accounts;
        _isLoading = false;
      });
    } on AccountStorageException catch (error) {
      if (!mounted || !_canUseSensitiveFeatures) {
        return;
      }
      setState(() {
        _accounts = <AuthenticatorAccount>[];
        _isLoading = false;
        _storageError = error.message;
      });
    } catch (_) {
      if (!mounted || !_canUseSensitiveFeatures) {
        return;
      }
      setState(() {
        _accounts = <AuthenticatorAccount>[];
        _isLoading = false;
        _storageError = 'No se pudieron cargar las cuentas protegidas.';
      });
    }
  }

  void _copyToClipboard(String code, String accountName) {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    Clipboard.setData(ClipboardData(text: code));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Código copiado: $code ($accountName)'),
        duration: const Duration(seconds: 2),
        backgroundColor: const Color(0xFF2563EB),
      ),
    );
  }

  Future<void> _scanQrDirectly() async {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    final result = await Navigator.push<Map<String, String>>(
      context,
      MaterialPageRoute(builder: (_) => const QrScannerScreen()),
    );

    if (result != null && mounted && _canUseSensitiveFeatures) {
      final account = AuthenticatorAccount(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        issuer: 'Bóveda Híbrida',
        accountName: result['accountName'] ?? 'Bóveda',
        secret: result['secret'] ?? '',
        createdAt: DateTime.now(),
      );
      try {
        await AccountStorageService.saveAccount(account);
      } on AccountStorageException catch (error) {
        if (mounted && _canUseSensitiveFeatures) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(error.message)),
          );
        }
        return;
      }
      if (!mounted || !_canUseSensitiveFeatures) {
        return;
      }
      await _loadAccounts();
      if (mounted && _canUseSensitiveFeatures) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content:
                Text('Cuenta "${account.accountName}" vinculada exitosamente'),
            backgroundColor: const Color(0xFF10B981),
          ),
        );
      }
    }
  }

  Future<void> _deleteAccount(AuthenticatorAccount account) async {
    if (!_canUseSensitiveFeatures || !mounted) {
      return;
    }
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: const Text('Eliminar Cuenta',
            style: TextStyle(color: Colors.white)),
        content: Text(
          '¿Estás seguro de desvincular "${account.accountName}" de este autenticador?',
          style: const TextStyle(color: Color(0xFFCBD5E1)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancelar', style: TextStyle(color: Colors.grey)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFEF4444),
              foregroundColor: Colors.white,
            ),
            child: const Text('Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true && mounted && _canUseSensitiveFeatures) {
      try {
        await AccountStorageService.deleteAccount(account.id);
      } on AccountStorageException catch (error) {
        if (mounted && _canUseSensitiveFeatures) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(error.message)),
          );
        }
        return;
      }
      if (!mounted || !_canUseSensitiveFeatures) {
        return;
      }
      await _loadAccounts();
    }
  }

  @override
  Widget build(BuildContext context) {
    Color timerColor;
    if (_remainingSeconds > 10) {
      timerColor = const Color(0xFF10B981); // Verde
    } else if (_remainingSeconds > 5) {
      timerColor = const Color(0xFFF59E0B); // Ámbar
    } else {
      timerColor = const Color(0xFFEF4444); // Rojo
    }

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        title: Row(
          children: [
            const Icon(Icons.shield_rounded,
                color: Color(0xFF3B82F6), size: 26),
            const SizedBox(width: 8),
            const Text(
              'Bóveda Authenticator',
              style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                  fontSize: 18),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.folder_special),
            tooltip: 'Bóvedas cifradas',
            onPressed: _canUseSensitiveFeatures
                ? () => Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => VaultScreen(
                          installationIdentity: widget.installationIdentity,
                        ),
                      ),
                    )
                : null,
          ),
          IconButton(
            icon: const Icon(Icons.qr_code_scanner_rounded,
                color: Color(0xFF60A5FA)),
            tooltip: 'Escanear QR',
            onPressed: _canUseSensitiveFeatures ? _scanQrDirectly : null,
          ),
          // Indicador circular de tiempo en AppBar
          Container(
            margin: const EdgeInsets.only(right: 16),
            child: Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 28,
                  height: 28,
                  child: CircularProgressIndicator(
                    value: _progress,
                    strokeWidth: 3,
                    backgroundColor: const Color(0xFF334155),
                    valueColor: AlwaysStoppedAnimation<Color>(timerColor),
                  ),
                ),
                Text(
                  '$_remainingSeconds',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: timerColor,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _storageError != null
              ? _buildStorageError()
              : _accounts.isEmpty
                  ? _buildEmptyState()
                  : _buildAccountsList(timerColor),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _canUseSensitiveFeatures
            ? () async {
                final result = await Navigator.push<bool>(
                  context,
                  MaterialPageRoute(builder: (_) => const AddAccountScreen()),
                );
                if (result == true && mounted && _canUseSensitiveFeatures) {
                  await _loadAccounts();
                }
              }
            : null,
        backgroundColor: const Color(0xFF2563EB),
        foregroundColor: Colors.white,
        icon: const Icon(Icons.add_rounded),
        label: const Text('Vincular Cuenta',
            style: TextStyle(fontWeight: FontWeight.bold)),
      ),
    );
  }

  Widget _buildStorageError() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            const Icon(Icons.error_outline, color: Color(0xFFFCA5A5), size: 42),
            const SizedBox(height: 12),
            Text(
              _storageError!,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Color(0xFFFCA5A5)),
            ),
            const SizedBox(height: 16),
            OutlinedButton(
              onPressed: _canUseSensitiveFeatures ? _loadAccounts : null,
              child: const Text('Reintentar'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B),
                shape: BoxShape.circle,
                border: Border.all(color: const Color(0xFF334155), width: 1.5),
              ),
              child: const Icon(Icons.lock_clock_rounded,
                  size: 40, color: Color(0xFF3B82F6)),
            ),
            const SizedBox(height: 20),
            const Text(
              'No hay cuentas vinculadas',
              style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: Colors.white),
            ),
            const SizedBox(height: 8),
            Text(
              'Escanea el código QR en la web de Bóveda Híbrida para vincular tu cuenta al instante.',
              textAlign: TextAlign.center,
              style:
                  TextStyle(color: Colors.grey[400], fontSize: 13, height: 1.5),
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _canUseSensitiveFeatures ? _scanQrDirectly : null,
              icon: const Icon(Icons.qr_code_scanner_rounded),
              label: const Text('Escanear Código QR'),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                foregroundColor: Colors.white,
                padding:
                    const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAccountsList(Color timerColor) {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 80),
      itemCount: _accounts.length,
      itemBuilder: (context, index) {
        final account = _accounts[index];
        final rawCode = TotpService.generateCode(account.secret);
        final formattedCode =
            '${rawCode.substring(0, 3)} ${rawCode.substring(3)}';

        return Container(
          margin: const EdgeInsets.only(bottom: 12),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF334155)),
          ),
          child: Material(
            color: Colors.transparent,
            child: InkWell(
              borderRadius: BorderRadius.circular(12),
              onTap: _canUseSensitiveFeatures
                  ? () => _copyToClipboard(rawCode, account.accountName)
                  : null,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: const Color(0xFF3B82F6)
                                    .withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: Text(
                                account.issuer,
                                style: const TextStyle(
                                  color: Color(0xFF93C5FD),
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete_outline_rounded,
                              color: Colors.grey, size: 20),
                          onPressed: _canUseSensitiveFeatures
                              ? () => _deleteAccount(account)
                              : null,
                          tooltip: 'Desvincular',
                          constraints: const BoxConstraints(),
                          padding: EdgeInsets.zero,
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      account.accountName,
                      style: TextStyle(color: Colors.grey[300], fontSize: 13),
                    ),
                    const SizedBox(height: 12),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Text(
                          formattedCode,
                          style: TextStyle(
                            color: timerColor,
                            fontSize: 32,
                            fontWeight: FontWeight.w800,
                            fontFamily: 'monospace',
                            letterSpacing: 2,
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.copy_rounded,
                              color: Color(0xFF60A5FA), size: 22),
                          onPressed: _canUseSensitiveFeatures
                              ? () =>
                                  _copyToClipboard(rawCode, account.accountName)
                              : null,
                          tooltip: 'Copiar código',
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}
