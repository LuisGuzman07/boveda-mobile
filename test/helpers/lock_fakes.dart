import 'package:boveda_mobile/services/app_lock_service.dart';
import 'package:boveda_mobile/services/installation_identity_service.dart';

class FakeLocalAuthenticationGateway implements LocalAuthenticationGateway {
  bool supported;
  bool authenticationResult;
  int authenticationCalls = 0;
  bool? biometricOnly;
  bool? persistAcrossBackgrounding;

  FakeLocalAuthenticationGateway({
    this.supported = true,
    this.authenticationResult = true,
  });

  @override
  Future<bool> authenticate({
    required String localizedReason,
    required bool biometricOnly,
    required bool persistAcrossBackgrounding,
  }) async {
    authenticationCalls++;
    this.biometricOnly = biometricOnly;
    this.persistAcrossBackgrounding = persistAcrossBackgrounding;
    return authenticationResult;
  }

  @override
  Future<bool> isDeviceSupported() async => supported;
}

class FakeInstallationIdentityProvider implements InstallationIdentityProvider {
  FakeInstallationIdentityProvider({
    this.identity = const InstallationIdentity(
      installationId: '11111111-1111-4111-8111-111111111111',
      publicKey: 'test-public-key',
    ),
  });

  InstallationIdentity identity;
  InstallationIdentityException? loadError;
  bool Function()? isLocked;
  bool? wasLockedOnLoad;
  int loadCalls = 0;
  int recoverCalls = 0;
  Map<String, Object?>? signedChallenge;
  final signedChallenges = <Map<String, Object?>>[];

  @override
  Future<InstallationIdentity> loadOrCreate() async {
    loadCalls++;
    wasLockedOnLoad = isLocked?.call();
    final error = loadError;
    if (error != null) {
      throw error;
    }
    return identity;
  }

  @override
  Future<InstallationIdentity> recover() async {
    recoverCalls++;
    loadError = null;
    return identity;
  }

  @override
  Future<String> signChallenge({
    required String challengeId,
    required String purpose,
    required String userId,
    required String deviceId,
    required String nonce,
    required DateTime expiresAt,
  }) async {
    signedChallenge = <String, Object?>{
      'challengeId': challengeId,
      'purpose': purpose,
      'userId': userId,
      'deviceId': deviceId,
      'nonce': nonce,
      'expiresAt': expiresAt,
    };
    signedChallenges.add(signedChallenge!);
    return 'test-signature';
  }
}
