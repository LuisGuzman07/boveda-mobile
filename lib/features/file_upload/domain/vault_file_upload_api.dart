abstract interface class VaultFileUploadApi {
  Future<Map<String, dynamic>> createFileUploadIntent(
    String vaultId,
    int ciphertextLength,
    String retryKey,
  );

  Future<Map<String, dynamic>> completeFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    Map<String, dynamic> body,
    String retryKey,
  );

  Future<Map<String, dynamic>> abortFileUpload(
    String vaultId,
    String fileId,
    String versionId,
    String retryKey,
  );
}
