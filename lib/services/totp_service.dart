import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class TotpService {
  static const int timeStepSeconds = 30;
  static const int codeDigits = 6;

  /// Genera el código TOTP de 6 dígitos para un secreto Base32 dado en un instante determinado.
  static String generateCode(String base32Secret, {DateTime? time}) {
    final now = time ?? DateTime.now();
    final timeInSeconds = now.millisecondsSinceEpoch ~/ 1000;
    final counter = timeInSeconds ~/ timeStepSeconds;

    final secretBytes = _decodeBase32(base32Secret);
    final counterBytes = _intToBytes(counter);

    final hmac = Hmac(sha1, secretBytes);
    final hmacResult = hmac.convert(counterBytes).bytes;

    final offset = hmacResult[hmacResult.length - 1] & 0x0f;
    final binaryCode = ((hmacResult[offset] & 0x7f) << 24) |
        ((hmacResult[offset + 1] & 0xff) << 16) |
        ((hmacResult[offset + 2] & 0xff) << 8) |
        (hmacResult[offset + 3] & 0xff);

    final otp = (binaryCode % 1000000).toString().padLeft(codeDigits, '0');
    return otp;
  }

  /// Calcula los segundos restantes en la ventana actual de 30 segundos.
  static int getRemainingSeconds({DateTime? time}) {
    final now = time ?? DateTime.now();
    final currentSeconds = now.millisecondsSinceEpoch ~/ 1000;
    final elapsedInWindow = currentSeconds % timeStepSeconds;
    return timeStepSeconds - elapsedInWindow;
  }

  /// Calcula el progreso normalizado (0.0 a 1.0) para la barra/círculo del temporizador.
  static double getProgress({DateTime? time}) {
    final remaining = getRemainingSeconds(time: time);
    return remaining / timeStepSeconds;
  }

  /// Decodifica una clave Base32 (RFC 4648) a bytes binarios.
  static Uint8List _decodeBase32(String input) {
    const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final cleaned = input.toUpperCase().replaceAll(RegExp(r'[^A-Z2-7]'), '');

    if (cleaned.isEmpty) {
      return Uint8List(0);
    }

    final output = <int>[];
    int buffer = 0;
    int bitsLeft = 0;

    for (int i = 0; i < cleaned.length; i++) {
      final char = cleaned[i];
      final val = base32Alphabet.indexOf(char);
      if (val < 0) continue;

      buffer = (buffer << 5) | val;
      bitsLeft += 5;

      if (bitsLeft >= 8) {
        output.add((buffer >> (bitsLeft - 8)) & 0xff);
        bitsLeft -= 8;
      }
    }

    return Uint8List.fromList(output);
  }

  /// Convierte un entero de 64 bits en un arreglo de 8 bytes en Big Endian.
  static Uint8List _intToBytes(int value) {
    final bytes = Uint8List(8);
    for (int i = 7; i >= 0; i--) {
      bytes[i] = value & 0xff;
      value = value >> 8;
    }
    return bytes;
  }
}
