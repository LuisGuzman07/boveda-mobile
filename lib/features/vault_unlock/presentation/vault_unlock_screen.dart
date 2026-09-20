import 'package:flutter/material.dart';

import '../../../services/app_lock_service.dart';
import '../../../services/vault_api_service.dart';
import '../../../widgets/app_lock_gate.dart';
import '../data/vault_envelope_repository.dart';
import 'vault_unlock_controller.dart';

class VaultUnlockScreen extends StatefulWidget {
  const VaultUnlockScreen({
    super.key,
    required this.api,
    required this.vaultId,
    this.controller,
  });

  final VaultApiService api;
  final String vaultId;
  final VaultUnlockController? controller;

  @override
  State<VaultUnlockScreen> createState() => _VaultUnlockScreenState();
}

class _VaultUnlockScreenState extends State<VaultUnlockScreen>
    with WidgetsBindingObserver {
  late final VaultUnlockController _controller;
  late final bool _ownsController;
  final _password = TextEditingController();
  final _passwordFocus = FocusNode();
  AppLockService? _appLock;
  bool _showPassword = false;

  @override
  void initState() {
    super.initState();
    _ownsController = widget.controller == null;
    _controller = widget.controller ??
        VaultUnlockController(
          repository: VaultApiEnvelopeRepository(widget.api),
        );
    _controller.selectVault(widget.vaultId);
    _controller.addListener(_onControllerChanged);
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final appLock = AppLockScope.maybeOf(context);
    if (identical(appLock, _appLock)) {
      return;
    }
    _appLock = appLock;
    _controller.attachAppLockService(appLock);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) {
      _clearPassword();
    }
    _controller.handleAppLifecycleState(state);
  }

  bool get _canUseSensitiveFeatures =>
      _appLock == null || _appLock!.allowsSensitiveActions;

  void _onControllerChanged() {
    _clearPassword();
    if (mounted) {
      setState(() {});
    }
  }

  void _clearPassword() {
    if (_password.text.isNotEmpty) {
      _password.clear();
    }
  }

  Future<void> _unlock() async {
    if (!_canUseSensitiveFeatures || _controller.isBusy) {
      return;
    }
    final password = _password.text;
    if (password.isEmpty) {
      return;
    }
    _clearPassword();
    try {
      await _controller.unlock(password);
    } finally {
      _clearPassword();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _clearPassword();
    _password.dispose();
    _passwordFocus.dispose();
    _controller.removeListener(_onControllerChanged);
    _controller.lock();
    if (_ownsController) {
      _controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final unlocked = _controller.isUnlocked;
    final failure = _controller.failure;
    return Scaffold(
      appBar: AppBar(title: const Text('Desbloquear bóveda')),
      body: Listener(
        onPointerDown: (_) => _controller.recordActivity(),
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) => SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Center(
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    maxWidth: 520,
                    minHeight: constraints.maxHeight - 40,
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: <Widget>[
                      Icon(
                        unlocked ? Icons.lock_open_rounded : Icons.lock_rounded,
                        size: 52,
                        color: Theme.of(context).colorScheme.primary,
                        semanticLabel: unlocked
                            ? 'Bóveda desbloqueada'
                            : 'Bóveda bloqueada',
                      ),
                      const SizedBox(height: 16),
                      Semantics(
                        liveRegion: true,
                        child: Text(
                          unlocked ? 'Bóveda desbloqueada' : 'Bóveda bloqueada',
                          textAlign: TextAlign.center,
                          style: Theme.of(context).textTheme.headlineSmall,
                        ),
                      ),
                      const SizedBox(height: 10),
                      if (unlocked)
                        _buildUnlocked(context)
                      else
                        _buildLocked(context),
                      if (failure != null) ...<Widget>[
                        const SizedBox(height: 16),
                        Semantics(
                          liveRegion: true,
                          child: Text(
                            failure.userMessage,
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: Theme.of(context).colorScheme.error,
                              height: 1.4,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLocked(BuildContext context) {
    final blockedByBackoff = _controller.remainingBackoff > Duration.zero;
    final disabled = !_canUseSensitiveFeatures ||
        _controller.isBusy ||
        !_controller.canAttempt ||
        _password.text.isEmpty;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        const Text(
          'La contraseña maestra se procesa solamente en este dispositivo.',
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 20),
        TextField(
          key: const ValueKey('vault-unlock-password'),
          controller: _password,
          focusNode: _passwordFocus,
          autofocus: true,
          obscureText: !_showPassword,
          autocorrect: false,
          enableSuggestions: false,
          enableIMEPersonalizedLearning: false,
          autofillHints: const <String>[],
          keyboardType: TextInputType.visiblePassword,
          textInputAction: TextInputAction.done,
          enabled: !_controller.isBusy && _canUseSensitiveFeatures,
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _unlock(),
          decoration: InputDecoration(
            labelText: 'Contraseña maestra',
            border: const OutlineInputBorder(),
            suffixIcon: IconButton(
              tooltip:
                  _showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña',
              onPressed: _controller.isBusy
                  ? null
                  : () => setState(() => _showPassword = !_showPassword),
              icon: Icon(
                _showPassword ? Icons.visibility_off : Icons.visibility,
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: disabled ? null : _unlock,
          icon: _controller.isBusy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.lock_open_rounded),
          label: Text(_controller.isBusy
              ? 'Desbloqueando...'
              : blockedByBackoff
                  ? 'Espera para intentar'
                  : 'Desbloquear'),
        ),
        const SizedBox(height: 12),
        const Text(
          'No se guardará la contraseña ni la clave descifrada.',
          textAlign: TextAlign.center,
        ),
      ],
    );
  }

  Widget _buildUnlocked(BuildContext context) {
    final description = _controller.vaultDescription;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text(
          _controller.vaultName ?? 'Bóveda abierta',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.titleLarge,
        ),
        if (description != null && description.isNotEmpty) ...<Widget>[
          const SizedBox(height: 8),
          Text(description, textAlign: TextAlign.center),
        ],
        const SizedBox(height: 16),
        const Text(
          'La bóveda permanece abierta solo en memoria. Las operaciones de archivos estarán disponibles en CU08.',
          textAlign: TextAlign.center,
        ),
        if (_controller.expiresAt != null) ...<Widget>[
          const SizedBox(height: 12),
          const Text(
            'Se bloqueará por inactividad.',
            textAlign: TextAlign.center,
          ),
        ],
        const SizedBox(height: 20),
        FilledButton.icon(
          onPressed: _controller.isBusy ? null : _controller.lock,
          icon: const Icon(Icons.lock_rounded),
          label: const Text('Bloquear'),
        ),
      ],
    );
  }
}
