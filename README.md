# Sidebox

**Sidebox** — iOS-приложение на Rust + UIKit для подписи, установки и продления provisioning-профилей IPA-приложений прямо на iPhone через локальный VPN-туннель (LocalDevVPN / StosVPN) и pairing-файл без подключения к ПК во время продления.

## Скачать

Готовые сборки доступны в [GitHub Releases](https://github.com/bromhobit/Sidebox/releases).

- **`Sidebox-1.0.0.ipa`** — универсальный ARM64 IPA без приватных entitlements (ad-hoc подпись; готов к переподписи и установке через **Boxloader**, AltServer, iLoader или TrollStore).

В IPA не включаются pairing-файлы, сертификаты пользователя или сохранённые сессии Apple ID.

## Идентификаторы

- **Bundle ID:** `com.bromhobit.Sidebox` (при установке бесплатным Apple ID дополняется Team ID: `com.bromhobit.Sidebox.<TEAM_ID>`)
- **Исполняемый файл:** `Sidebox` (`Sidebox.app/Sidebox`)
- **Тип pairing-файла UTI:** `com.bromhobit.sidebox.mobiledevicepairing`

## LocalDevVPN

1. Включите LocalDevVPN на iPhone. При стандартных настройках **Tunnel IP** — `10.7.1.1/32`, а **Device IP** — `10.7.0.1/32`.
2. В Sidebox откройте **Настройки → VPN-туннель**. Для подключения нужен **Device IP** из настроек LocalDevVPN (по умолчанию `10.7.0.1`). Если адрес изменён, нажмите **Изменить IP…** и введите свой адрес (принимается и формат с `/32`) или выберите быстрый пресет `10.7.0.1` / `10.7.0.2`.
3. Импортируйте совместимый pairing-файл (`pairingFile.plist` / `.mobiledevicepairing`) вручную в Sidebox или передайте его по USB через **Boxloader**, затем нажмите **Проверить связь**.

> Адрес туннельного интерфейса `10.7.1.1/32` и Device IP — разные настройки. Не меняйте конфигурацию LocalDevVPN только потому, что они отличаются.

## Установка на iPhone

1. Выберите `Sidebox-1.0.0.ipa` в **Boxloader** (или другом совместимом установщике) и установите приложение на iPhone.
2. При установке с бесплатным Apple ID разрешите доверие разработчику в **Настройки → Основные → VPN и управление устройством** и при необходимости включите **Режим разработчика**.
3. Передайте pairing-файл и при необходимости сессию Apple ID через кнопку настройки Sidebox в **Boxloader** или авторизуйтесь прямо внутри Sidebox.

## Безопасность

Исходные коды и релизные `.ipa` не содержат Apple-токенов, pairing-файлов, приватных ключей или пользовательских provisioning-профилей. Сессия Apple ID (`apple-session.plist`) и состояние Anisette (`anisette_state`) хранятся локально в каталоге `Documents/` песочницы с правами `0600`.

## Сборка и проверки на Linux

Понадобятся Rust с целью `aarch64-apple-ios`, Clang/LLVM, `ld64.lld` и совместимый iPhoneOS SDK (`IPHONEOS_DEPLOYMENT_TARGET=15.0`, `-Wl,-platform_version,ios,15.0,16.4`).

После сборки бинарника `Sidebox` для `aarch64-apple-ios`:

```sh
python3 package/build_ipa.py \
  --binary build/ios-1.0.0/Sidebox \
  --output dist --version 1.0.0 --force
```

Запуск тестов:

```sh
cargo test --locked
python3 package/codesign.py --self-test
SIDEBOX_TEST_IOS_BINARY=/absolute/path/to/Sidebox python3 -m unittest discover -s package -v
```
