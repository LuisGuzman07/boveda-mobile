import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import '../services/vault_api_service.dart';
import '../services/vault_crypto_service.dart';

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key});
  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> with WidgetsBindingObserver {
  final _api = VaultApiService();
  final _crypto = VaultCryptoService();
  final _email = TextEditingController();
  final _accountPassword = TextEditingController();
  final _totp = TextEditingController();
  final _name = TextEditingController();
  final _description = TextEditingController();
  final _master = TextEditingController();
  final _confirmation = TextEditingController();
  bool _busy = false;
  String? _error;
  List<Map<String, dynamic>> _vaults = [];
  final Map<String, List<Map<String, dynamic>>> _filesByVault = {};
  Map<String, dynamic>? _pending;
  String? _retryKey;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _clearPasswords();
      _crypto.clearSessionKey();
    }
  }

  void _clearPasswords() {
    _accountPassword.clear();
    _totp.clear();
    _master.clear();
    _confirmation.clear();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _api.logout();
    _crypto.clearSessionKey();
    for (final controller in [
      _email,
      _accountPassword,
      _totp,
      _name,
      _description,
      _master,
      _confirmation
    ]) {
      controller.dispose();
    }
    super.dispose();
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (error) {
      _crypto.clearSessionKey();
      if (mounted) {
        setState(() => _error = error is VaultApiException
            ? error.message
            : 'No se pudo completar la operación. Verifica la conexión y tus credenciales.');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _login() => _run(() async {
        if (_email.text.trim().isEmpty ||
            _accountPassword.text.isEmpty ||
            !RegExp(r'^\d{6}$').hasMatch(_totp.text.trim())) {
          throw VaultApiException(
              'Completa correo, contraseña y código TOTP de seis dígitos.');
        }
        try {
          await _api.login(_email.text, _accountPassword.text, _totp.text);
          final pending = await _api.pendingCreation();
          _pending = pending == null
              ? null
              : Map<String, dynamic>.from(pending['body'] as Map);
          _retryKey = pending?['retry_key'] as String?;
           _vaults = await _api.listVaults();
           await _loadFileMetadata();
        } finally {
          _accountPassword.clear();
          _totp.clear();
        }
      });

  Future<void> _create() => _run(() async {
        if (_pending == null) {
          if (_name.text.trim().isEmpty ||
              _name.text.trim().length > 150 ||
              _description.text.trim().length > 500) {
            throw VaultApiException(
                'Nombre obligatorio de hasta 150 caracteres y descripción de hasta 500.');
          }
          if (_master.text.length < 12 || _master.text != _confirmation.text) {
            throw VaultApiException(
                'Usa una contraseña maestra de al menos 12 caracteres y confirma que coincide.');
          }
          final deviceKey = await _api.deviceKey();
          try {
            _pending = await _crypto.prepare(
                name: _name.text,
                description: _description.text,
                password: _master.text,
                deviceId: _api.deviceId,
                deviceKey: deviceKey);
            _retryKey = VaultCryptoService.newId();
            await _api.savePending(_pending!, _retryKey!);
          } finally {
            deviceKey.fillRange(0, deviceKey.length, 0);
            _master.clear();
            _confirmation.clear();
          }
        }
        await _api.createVault(_pending!, _retryKey!);
        await _api.clearPending();
        _pending = null;
        _retryKey = null;
        _name.clear();
        _description.clear();
        _vaults = await _api.listVaults();
        await _loadFileMetadata();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
              content: Text(
                  'Bóveda creada. Conserva tu contraseña maestra y este dispositivo.')));
        }
      });

  Future<void> _loadFileMetadata() async {
    _filesByVault.clear();
    for (final vault in _vaults) {
      final id = vault['id_boveda'] as String;
      final data = await _api.listVaultFiles(id);
      _filesByVault[id] = (data['items'] as List)
          .map((item) => Map<String, dynamic>.from(item as Map))
          .toList();
    }
  }

  Future<void> _download(String vaultId, Map<String, dynamic> file) =>
      _run(() async {
        final response = await _api.downloadFile(
            vaultId, file['id_version_archivo'] as String);
        final plaintext = await _crypto.decryptDownloadedFile(response, vaultId);
        try {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(
                    'Archivo verificado y descifrado localmente (${plaintext.length} bytes).')));
          }
        } finally {
          plaintext.fillRange(0, plaintext.length, 0);
        }
      });

  Future<void> _deleteFile(String vaultId, Map<String, dynamic> file) async {
    final accepted = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
                title: const Text('Eliminar archivo cifrado'),
                content: const Text(
                    'El archivo dejará de estar disponible. Las copias cifradas quedarán en retención para preservar la auditoría.'),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(dialogContext, false),
                      child: const Text('Cancelar')),
                  FilledButton(
                      onPressed: () => Navigator.pop(dialogContext, true),
                      child: const Text('Eliminar')),
                ]));
    if (accepted != true || !mounted) return;
    await _run(() async {
      await _api.deleteFile(
          vaultId, file['id_archivo'] as String, VaultCryptoService.newId());
      await _loadFileMetadata();
    });
  }

  Future<void> _reopen(String id) async {
    final password = TextEditingController();
    final accepted = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
                title: const Text('Verificar bóveda'),
                content: TextField(
                    controller: password,
                    obscureText: true,
                    decoration:
                        const InputDecoration(labelText: 'Contraseña maestra')),
                actions: [
                  TextButton(
                      onPressed: () => Navigator.pop(dialogContext, false),
                      child: const Text('Cancelar')),
                  FilledButton(
                      onPressed: () => Navigator.pop(dialogContext, true),
                      child: const Text('Verificar'))
                ]));
    if (accepted == true && mounted) {
      await _run(() async {
        final deviceKey = await _api.deviceKey();
        try {
          final vault = await _api.getVault(id);
          final metadata =
              await _crypto.reopen(vault, password.text, deviceKey);
          if (mounted) {
            await showDialog<void>(
                context: context,
                builder: (dialogContext) => AlertDialog(
                        title: Text(metadata['nombre']!),
                        content: Text(metadata['descripcion']!.isEmpty
                            ? 'Clave recuperada y metadatos verificados localmente.'
                            : metadata['descripcion']!),
                        actions: [
                          TextButton(
                              onPressed: () => Navigator.pop(dialogContext),
                              child: const Text('Cerrar'))
                        ]));
          }
        } catch (error) {
          if (error is VaultApiException) rethrow;
          throw VaultApiException(
              'Contraseña incorrecta, clave local diferente o datos alterados.');
        } finally {
          deviceKey.fillRange(0, deviceKey.length, 0);
          password.clear();
        }
      });
    }
    password.dispose();
  }

  Future<void> _emergencyKit(String id) async {
    final password = TextEditingController();
    final kitJson = TextEditingController();
    final accepted = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
                title: const Text('Emergency Kit'),
                content: SingleChildScrollView(child: Column(children: [
                  TextField(controller: password, obscureText: true,
                      decoration: const InputDecoration(labelText: 'Contraseña del kit (12+ caracteres)')),
                  TextField(controller: kitJson, maxLines: 5,
                      decoration: const InputDecoration(labelText: 'JSON del kit para importar (opcional)')),
                ])),
                actions: [
                  TextButton(onPressed: () => Navigator.pop(dialogContext, false), child: const Text('Cancelar')),
                  FilledButton(onPressed: () => Navigator.pop(dialogContext, true), child: const Text('Continuar'))
                ]));
    if (accepted != true || !mounted) {
      password.dispose();
      kitJson.dispose();
      return;
    }
    await _run(() async {
      if (password.text.length < 12) throw const FormatException('La contraseña del kit debe tener al menos 12 caracteres.');
      final deviceKey = await _api.deviceKey();
      try {
        if (kitJson.text.trim().isEmpty) {
          if (id.isEmpty) throw const FormatException('Selecciona una bóveda para crear un kit.');
          final vault = await _api.getVault(id);
          final kit = await _crypto.createEmergencyKit(id, vault['kdf_salt'] as String, password.text);
          await _api.createEmergencyKit(id, kit);
          if (mounted) {
            await showDialog<void>(context: context, builder: (dialogContext) => AlertDialog(
              title: const Text('Kit creado'),
              content: SelectableText(jsonEncode(kit)),
              actions: [TextButton(onPressed: () => Navigator.pop(dialogContext), child: const Text('Cerrar'))],
            ));
          }
        } else {
          final kit = Map<String, dynamic>.from(jsonDecode(kitJson.text) as Map);
          final targetId = id.isEmpty ? kit['id_boveda'] as String : id;
          if (kit['id_boveda'] != targetId) throw const FormatException('El kit no corresponde a esta bóveda.');
          final vault = <String, dynamic>{
            'id_boveda': targetId,
            'kdf_salt': kit['kdf_salt_boveda'],
          };
          final payload = await _crypto.prepareEmergencyRecovery(kit, vault, password.text, _api.deviceId, deviceKey);
          await _api.recoverEmergencyKit(targetId, payload);
          final recoveredVault = await _api.getVault(targetId);
          await _crypto.reopen(recoveredVault, password.text, deviceKey);
        }
      } finally {
        deviceKey.fillRange(0, deviceKey.length, 0);
        password.clear();
        kitJson.clear();
      }
    });
    password.dispose();
    kitJson.dispose();
  }

  Widget _field(TextEditingController controller, String label,
          {bool secret = false, int? maxLength, bool enabled = true}) =>
      Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextField(
              controller: controller,
              obscureText: secret,
              enabled: !_busy && enabled,
              maxLength: maxLength,
              autocorrect: !secret,
              enableSuggestions: !secret,
              decoration: InputDecoration(
                  labelText: label, border: const OutlineInputBorder())));

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(title: const Text('Bóvedas cifradas'), actions: [
          if (_api.authenticated)
            IconButton(
                tooltip: 'Cerrar sesión de bóvedas',
                onPressed: _busy
                    ? null
                    : () => setState(() {
                          _api.logout();
                          _crypto.clearSessionKey();
                           _vaults = [];
                           _filesByVault.clear();
                          _pending = null;
                          _retryKey = null;
                          _clearPasswords();
                        }),
                icon: const Icon(Icons.logout))
        ]),
        body: ListView(padding: const EdgeInsets.all(20), children: [
          if (_error != null)
            Padding(
                padding: const EdgeInsets.only(bottom: 16),
                child: Text(_error!,
                    style:
                        TextStyle(color: Theme.of(context).colorScheme.error))),
          if (_busy) const LinearProgressIndicator(),
          if (!_api.authenticated) ...[
            const Text(
                'Inicia sesión con tu cuenta y TOTP. Al ingresar autorizas este dispositivo para tus bóvedas.'),
            const SizedBox(height: 16),
            _field(_email, 'Correo'),
            _field(_accountPassword, 'Contraseña de la cuenta', secret: true),
            _field(_totp, 'Código TOTP', maxLength: 6),
            FilledButton(
                onPressed: _busy ? null : _login,
                child: const Text('Ingresar')),
          ] else ...[
            const Text('Crear una bóveda vacía',
                style: TextStyle(fontSize: 22)),
            const SizedBox(height: 12),
           const Text(
                 'La contraseña maestra es independiente de tu cuenta. Emergency Kit permite recuperar la bóveda localmente en otro dispositivo confiable.'),
             const SizedBox(height: 8),
             OutlinedButton.icon(
                 onPressed: _busy ? null : () => _emergencyKit(''),
                 icon: const Icon(Icons.upload_file),
                 label: const Text('Importar Emergency Kit en este dispositivo')),
            const SizedBox(height: 16),
            _field(_name, 'Nombre', maxLength: 150, enabled: _pending == null),
            _field(_description, 'Descripción opcional',
                maxLength: 500, enabled: _pending == null),
            if (_pending == null) ...[
              _field(_master, 'Contraseña maestra (mínimo 12 caracteres)',
                  secret: true),
              _field(_confirmation, 'Confirmar contraseña maestra',
                  secret: true)
            ],
            FilledButton(
                onPressed: _busy ? null : _create,
                child: Text(_pending == null
                    ? 'Crear bóveda'
                    : 'Reintentar la misma creación')),
            if (_pending != null)
              TextButton(
                  onPressed: _busy
                      ? null
                      : () => _run(() async {
                            await _api.clearPending();
                            _pending = null;
                            _retryKey = null;
                          }),
                  child: const Text('Descartar solicitud pendiente')),
            const SizedBox(height: 24),
            Row(children: [
              const Expanded(
                  child: Text('Mis bóvedas', style: TextStyle(fontSize: 20))),
              IconButton(
                  onPressed: _busy
                      ? null
                      : () => _run(() async {
                             _vaults = await _api.listVaults();
                             await _loadFileMetadata();
                          }),
                  icon: const Icon(Icons.refresh))
            ]),
            if (_vaults.isEmpty)
              const Text(
                  'Todavía no hay bóvedas disponibles para este dispositivo.'),
            ..._vaults.map((vault) {
              final id = vault['id_boveda'] as String;
              final files = _filesByVault[id] ?? const [];
              return ExpansionTile(
                  leading: const Icon(Icons.lock),
                  title: Text('Bóveda ${id.substring(0, 8)}'),
                  subtitle: Text('Nombre protegido · ${files.length} versiones'),
                    trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                      IconButton(
                          tooltip: 'Emergency Kit',
                          onPressed: _busy ? null : () => _emergencyKit(id),
                          icon: const Icon(Icons.emergency)),
                      IconButton(
                          tooltip: 'Verificar bóveda',
                          onPressed: _busy ? null : () => _reopen(id),
                          icon: const Icon(Icons.verified_user)),
                    ]),
                       children: files
                      .map((file) => ListTile(
                            dense: true,
                            title: Text(
                                'Archivo ${file['id_archivo'].toString().substring(0, 8)} · v${file['numero_version']}'),
                            subtitle: Text(
                                '${file['tamano_cifrado']} bytes · ${file['estado_replica'] ?? 'Sin réplica'}'),
                             leading: const Icon(Icons.description_outlined),
                              trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                                IconButton(
                                    tooltip: 'Verificar y descifrar localmente',
                                    onPressed: _busy ? null : () => _download(id, file),
                                    icon: const Icon(Icons.download)),
                                IconButton(
                                    tooltip: 'Eliminar archivo',
                                    onPressed: _busy ? null : () => _deleteFile(id, file),
                                    icon: const Icon(Icons.delete_outline)),
                              ]),
                           ))
                      .toList());
            }),
          ],
        ]));
  }
}
