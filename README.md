# Bóveda Mobile — Aplicación Móvil (Flutter)

Aplicación móvil para el sistema **Bóveda híbrida de archivos cifrados para equipos académicos y pequeñas organizaciones**, construida con **Flutter** y **Dart**.

---

## 1. Requisitos Previos

- [Flutter SDK](https://flutter.dev/docs/get-started/install) (versión 3.24+ / 3.47+)
- [Android Studio](https://developer.android.com/studio) o [VS Code](https://code.visualstudio.com/) con plugins de Flutter y Dart.
- Backend FastAPI levantado con HTTPS para dispositivos físicos.

---

## 2. Instalación de Dependencias

```bash
flutter pub get
```

---

## 3. Configuración de Red según Entorno

La URL base del backend se encuentra centralizada en:
`lib/config/app_config.dart`

- **Debug local web / desktop:** `http://localhost:8000/api/v1`
- **Emulador Android en debug:** `http://10.0.2.2:8000/api/v1`
- **Dispositivo físico y release:** HTTPS mediante proxy TLS o certificado confiable.

HTTP se rechaza fuera de debug y nunca se permite hacia direcciones LAN. Configura
`BOVEDA_API_URL` únicamente con una URL HTTPS para un teléfono físico o release.

La firma release se lee desde `android/key.properties`, que permanece fuera de
versionamiento. Sin esas propiedades, los builds release fallan de forma explícita;
el build debug continúa disponible. El `applicationId` actual se conserva durante
esta versión para que las instalaciones existentes puedan migrar sus cuentas TOTP
desde SharedPreferences a almacenamiento seguro antes de un cambio de identidad.

---

## 4. Ejecución del Proyecto

Para ejecutar en el dispositivo o emulador disponible:

```bash
flutter run
```

Para listar los dispositivos detectados:

```bash
flutter devices
```

Para ejecutar específicamente en Chrome / Web:

```bash
flutter run -d chrome
```

Para ejecutar en Windows Desktop:

```bash
flutter run -d windows
```

---

## 5. Pruebas Automatizadas

```bash
flutter test
```

---

## 6. Estructura del Proyecto

```text
boveda-mobile/
│
├── lib/
│   ├── config/
│   │   └── app_config.dart
│   ├── services/
│   │   └── api_service.dart
│   ├── screens/
│   │   └── home_screen.dart
│   ├── models/
│   ├── widgets/
│   ├── utils/
│   └── main.dart
│
├── test/
│   └── widget_test.dart
├── android/
├── ios/
├── .gitignore
├── pubspec.yaml
└── README.md
```
