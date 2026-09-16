import 'package:flutter/material.dart';
import 'screens/home_screen.dart';

void main() {
  runApp(const BovedaApp());
}

class BovedaApp extends StatelessWidget {
  const BovedaApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Bóveda Híbrida',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF2563EB),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const HomeScreen(),
    );
  }
}
