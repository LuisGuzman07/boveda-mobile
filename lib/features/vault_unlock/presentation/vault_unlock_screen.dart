import 'dart:async';

import 'package:flutter/material.dart';

import '../../file_upload/data/file_picker_vault_file_picker.dart';
import '../../file_upload/data/presigned_ciphertext_uploader.dart';
import '../../file_upload/presentation/vault_file_upload_controller.dart';
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
    this.fileUploadController,
  });

  final VaultApiService api;
  final String vaultId;
  final VaultUnlockController? controller;
  final VaultFileUploadController? fileUploadController;

  @override
  State<VaultUnlockScreen> createState() => _VaultUnlockScreenState();
}

class _VaultUnlockScreenState extends State<VaultUnlockScreen>
    with WidgetsBindingObserver {
  late final VaultUnlockController _controller;
  late final bool _ownsController;
  late final VaultFileUploadController _fileUploadController;
  late final bool _ownsFileUploadController;
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
    _ownsFileUploadController = widget.fileUploadController == null;
    _fileUploadController = widget.fileUploadController ??
        VaultFileUploadController(
          vaultId: widget.vaultId,
          api: widget.api,
          session: _controller.session,
          picker: FilePickerVaultFilePicker(),
          uploader: HttpPresignedCiphertextUploader(),
        );
    _controller.addListener(_onControllerChanged);
    _fileUploadController.addListener(_onFileUploadChanged);
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

  void _onFileUploadChanged() {
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

  Future<void> _selectAndConfirmFile() async {
    if (!_canUseSensitiveFeatures || !_fileUploadController.canSelectFile) {
      return;
    }
    final selected = await _fileUploadController.selectFile();
    if (!selected || !mounted) {
      return;
    }
    final name = _fileUploadController.pendingName ?? 'Archivo seleccionado';
    final bytes = _fileUploadController.pendingLength ?? 0;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Cifrar y cargar archivo'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(name, maxLines: 2, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 8),
            Text(_formatFileSize(bytes)),
            const SizedBox(height: 16),
            const Text(
              'El contenido, nombre y metadatos se cifrarán en este dispositivo antes de la carga.',
            ),
          ],
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancelar'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Cifrar y cargar'),
          ),
        ],
      ),
    );
    if (!mounted) {
      return;
    }
    if (confirmed == true && _fileUploadController.hasPendingFile) {
      await _fileUploadController.confirmSelectedFile();
      return;
    }
    await _fileUploadController.discardSelectedFile();
  }

  Future<void> _lockVault() async {
    await _fileUploadController.cancel();
    _controller.lock();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _clearPassword();
    _password.dispose();
    _passwordFocus.dispose();
    _controller.removeListener(_onControllerChanged);
    _fileUploadController.removeListener(_onFileUploadChanged);
    if (_ownsFileUploadController) {
      _fileUploadController.dispose();
    } else {
      unawaited(_fileUploadController.cancel());
    }
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
    final uploadState = _fileUploadController.state;
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
          'La bóveda permanece abierta solo en memoria. Los archivos se cifran antes de salir del dispositivo.',
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
          key: const ValueKey('vault-add-file'),
          onPressed: _fileUploadController.canSelectFile
              ? _selectAndConfirmFile
              : null,
          icon: const Icon(Icons.upload_file_rounded),
          label: const Text('Agregar archivo'),
        ),
        if (uploadState == VaultFileUploadState.preparing ||
            uploadState == VaultFileUploadState.uploading ||
            uploadState == VaultFileUploadState.completing) ...<Widget>[
          const SizedBox(height: 16),
          LinearProgressIndicator(
            value: uploadState == VaultFileUploadState.uploading &&
                    _fileUploadController.totalBytes > 0
                ? _fileUploadController.sentBytes /
                    _fileUploadController.totalBytes
                : null,
          ),
          const SizedBox(height: 8),
          Text(
            switch (uploadState) {
              VaultFileUploadState.preparing =>
                'Cifrando el archivo en este dispositivo...',
              VaultFileUploadState.completing =>
                'Verificando el ciphertext almacenado...',
              _ => 'Cargando ciphertext cifrado...',
            },
            textAlign: TextAlign.center,
          ),
        ],
        if (uploadState == VaultFileUploadState.completed) ...<Widget>[
          const SizedBox(height: 16),
          Semantics(
            liveRegion: true,
            child: Text(
              'Archivo cifrado y confirmado.',
              textAlign: TextAlign.center,
            ),
          ),
        ],
        if (uploadState == VaultFileUploadState.cancelled) ...<Widget>[
          const SizedBox(height: 16),
          const Text(
            'La carga fue cancelada y el material local fue descartado.',
            textAlign: TextAlign.center,
          ),
        ],
        if (uploadState == VaultFileUploadState.failed) ...<Widget>[
          const SizedBox(height: 16),
          Semantics(
            liveRegion: true,
            child: Text(
              _fileUploadController.errorMessage ??
                  'No se pudo completar la carga cifrada.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
          if (_fileUploadController.canRetry) ...<Widget>[
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _fileUploadController.retry,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Reintentar carga'),
            ),
          ],
        ],
        if (_fileUploadController.canCancel) ...<Widget>[
          const SizedBox(height: 12),
          TextButton(
            onPressed: _fileUploadController.cancel,
            child: const Text('Cancelar carga'),
          ),
        ],
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: _controller.isBusy ? null : _lockVault,
          icon: const Icon(Icons.lock_rounded),
          label: const Text('Bloquear'),
        ),
      ],
    );
  }

  static String _formatFileSize(int bytes) {
    if (bytes < 1024 * 1024) {
      return '${(bytes / 1024).toStringAsFixed(1)} KiB';
    }
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MiB';
  }
}
