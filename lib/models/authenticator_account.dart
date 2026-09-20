class AuthenticatorAccount {
  final String id;
  final String issuer;
  final String accountName;
  final String secret;
  final DateTime createdAt;

  AuthenticatorAccount({
    required this.id,
    required this.issuer,
    required this.accountName,
    required this.secret,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'issuer': issuer,
        'accountName': accountName,
        'secret': secret,
        'createdAt': createdAt.toIso8601String(),
      };

  factory AuthenticatorAccount.fromJson(Map<String, dynamic> json) =>
      AuthenticatorAccount(
        id: json['id'] as String,
        issuer: json['issuer'] as String? ?? 'Bóveda Híbrida',
        accountName: json['accountName'] as String,
        secret: json['secret'] as String,
        createdAt: DateTime.parse(json['createdAt'] as String),
      );
}
