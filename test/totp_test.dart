import 'package:flutter_test/flutter_test.dart';
import 'package:boveda_mobile/services/totp_service.dart';

void main() {
  group('TotpService Tests', () {
    const testSecret = 'JBSWY3DPEHPK3PXP'; // Base32 for "Hello!\xde\xad\xbe\xef"

    test('Generates 6-digit numeric string', () {
      final code = TotpService.generateCode(testSecret);
      expect(code.length, 6);
      expect(int.tryParse(code), isNotNull);
    });

    test('Generates deterministic code for fixed timestamp', () {
      final fixedTime = DateTime.fromMillisecondsSinceEpoch(1700000000 * 1000);
      final code1 = TotpService.generateCode(testSecret, time: fixedTime);
      final code2 = TotpService.generateCode(testSecret, time: fixedTime);
      expect(code1, code2);
    });

    test('Remaining seconds is between 1 and 30', () {
      final remaining = TotpService.getRemainingSeconds();
      expect(remaining, greaterThanOrEqualTo(1));
      expect(remaining, lessThanOrEqualTo(30));
    });
  });
}
