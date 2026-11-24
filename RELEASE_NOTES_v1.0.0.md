## Sidebox 1.0.0

Финальный релиз **Sidebox 1.0.0** с полным переименованием идентификаторов, исходников и упаковки без legacy-упоминаний `org.codex` и `DopamineLoader`.

### Что изменилось в 1.0.0
- **Новые идентификаторы и метаданные:**
  - Bundle ID приложения: `com.bromhobit.Sidebox` (ранее `org.codex.SideBox`).
  - Исполняемый файл: `Sidebox` (`Payload/Sidebox.app/Sidebox`).
  - UTI pairing-файла: `com.bromhobit.sidebox.mobiledevicepairing`.
  - Внутренние классы и структуры (`SideboxEngine`, `SideboxController`, `SideboxDelegate`) переименованы единообразно, строки интерфейса и документации обновлены на **Sidebox** / **Boxloader**.
- **Чистая упаковка `.ipa`:**
  - `Sidebox-1.0.0.ipa` подписан стандартной ad-hoc подписью без приватных/jailbreak entitlements (проверено через `codesign.py` и `Boxloader inspect-ipa`), готов к установке через **Boxloader v0.2.2+**, AltServer или TrollStore.
- **Совместимость экосистемы:**
  - Полная поддержка нового идентификатора `com.bromhobit.Sidebox*` добавляется в **Rebox v1.0.1+** (мост сессии Apple ID / Anisette) и **Boxloader v0.2.2+** (определение контейнера и передача pairing/сессии).

### Артефакты и SHA-256
- `Sidebox-1.0.0.ipa` — IPA для установки на iPhone (переподпись через Boxloader или установка через TrollStore).
- `SHA256SUMS` — контрольные суммы SHA-256 (сгенерированы при сборке релиза).

### Установка поверх старой версии
Если на iPhone установлена прежняя версия `org.codex.SideBox*`, при установке `Sidebox-1.0.0.ipa` система установит `com.bromhobit.Sidebox.<TEAM_ID>` как отдельное приложение. После переноса pairing-файла и входа в Apple ID (через **Boxloader v0.2.2** или внутри Sidebox) старую копию `SideBox` можно безопасно удалить; **Rebox 1.0.1+** автоматически переключится на новый контейнер **Sidebox**.
