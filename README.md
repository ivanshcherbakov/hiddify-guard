# Hiddify Guard

Помощник для Hiddify на Windows: ограничивает исходящие соединения, чтобы
приложения не переходили на обычный интернет при отключении VPN.

**0.1.0 — версия для проверки в Windows VM.** Сборка и unit-тесты не
подтверждают отсутствие утечек при загрузке, сбое VPN или работе другого
файрвола. До стабильного выпуска требуется [приёмка](docs/ACCEPTANCE.md).

Обнаружен вариант установки с HiddifyCoreEngine.exe и sing-tun/tun0,
который основной детектор пока не учитывает. До исправления не включайте
основное приложение с этим вариантом: [наблюдение](docs/KNOWN-ISSUES.md).

## Использование

1. После публикации скачайте установщик из
   [Releases](https://github.com/ivanshcherbakov/hiddify-guard/releases).
   До публикации соберите программу из исходников.
2. Установите Hiddify, включите в нём TUN. Установите Guard от администратора.
3. Guard найдёт Hiddify автоматически. Для portable-версии укажите папку
   в дополнительных настройках.
4. Нажмите «Включить защиту». Отключение — главный переключатель с подтверждением.

Зелёный щит — активная политика и обнаруженный Hiddify/TUN; жёлтый —
подключение не обнаружено или защита требует проверки; серый — выключена;
красный — Hiddify не найден. Обнаружение адаптера не проверяет доступность
VPN-сервера.

Крестик скрывает окно в трей. Выход из трея и завершение процесса не удаляют
защиту. В меню Пуск есть ярлык ручного отключения.
Удаление сначала снимает собственные фильтры и прекращается при ошибке очистки.

Домашняя сеть разрешена по умолчанию: RFC1918, IPv6 link-local и обнаруженные
локальные подсети. Это намеренное исключение для прямого локального трафика.
Снятие галочки применяется сразу. Если страница входа публичного Wi-Fi не
открывается, можно вручную выключить защиту для входа и затем включить снова.

### Диагностика

В «Дополнительно»: пересканирование Hiddify, ручная папка, язык, логи,
«Проверить защиту». Только по нажатию запускаются TCP-пробы
1.1.1.1:443 и [2606:4700:4700::1111]:443, DNS example.com на 8.8.8.8:53
и, при обнаруженном TUN, запрос https://api.ipify.org.
Прямые пробы закреплены за одним обнаруженным физическим адаптером.
Другие активные адаптеры требуют отдельного захвата.

Таймаут, отсутствие IPv6 и недоступный сервер дают неопределённый результат.
Запрет всех проб Windows не заменяет Wireshark/pktmon и проверку ребута.
Диагностика не отключает защиту и не добавляет исключений ради соединения.

### Автозапуск и данные

Установщик предлагает интерактивную задачу Планировщика с наивысшими правами
для текущего пользователя, без сохранения пароля.
Для бесшумного повышения учётная запись должна быть администратором.
Задача запускает трей; фильтры существуют независимо от неё.

Конфигурация: %ProgramData%\HiddifyGuard\config.json.
Логи: %ProgramData%\HiddifyGuard\logs\guard.log; ротация при 2 МБ,
одна резервная копия. История трафика и пользовательские DNS/URL не записываются.
Настройки защищены ACL Administrators/SYSTEM.

### CLI и аварийное отключение

Команды WFP, включая --status, выполняются от администратора.
Для WinExe в PowerShell дождитесь результата через Start-Process:

    $process = Start-Process 'C:\Program Files\Hiddify Guard\HiddifyGuard.exe' -ArgumentList '--uninstall-clean' -Verb RunAs -Wait -PassThru
    $process.ExitCode

--uninstall-clean удаляет только собственные фильтры, sublayer и provider,
в том числе при повреждённой конфигурации.

| Аргумент | Действие |
|---|---|
| --enable | Включить или восстановить защиту |
| --disable | Явно отключить защиту |
| --status | JSON: состояние, boot-time/persistent, разрешённые приложения |
| --uninstall-clean | Закрыть трей и снять собственную политику |
| --exit-tray | Закрыть трей, оставив защиту |
| --minimized | Запустить интерфейс в трее |
| --self-test / --diagnostics | ABI, пути, TUN/LAN без открытия WFP |
| --leak-test | Явно запустить сетевые пробы |
| --preview | Интерфейс без WFP и записи настроек |

Коды: 0 — успех; 1 — ошибка или возможная утечка; 2 — неверные аргументы;
3 — неопределённый leak test; 5 — нужны права.

## Сборка

Windows 10/11 x64, .NET 8 SDK, Inno Setup 6:

    dotnet build src/HiddifyGuard.sln -c Release
    dotnet test src/HiddifyGuard.sln -c Release
    ./scripts/build.ps1 -Version 0.1.0

Последняя команда проверяет тесты, публикует self-contained single-file win-x64,
собирает установщик, portable ZIP и dist/SHA256SUMS.txt.
dist/bin/obj не входят в репозиторий. Хэш проверяется Get-FileHash -Algorithm SHA256.
Хэш рядом с файлом проверяет целостность, но не заменяет подпись.
Сборки пока не подписаны. Не отключайте Defender или системную политику для запуска.
В управляемой организации действуют правила её администратора.

CI проверяет main и pull request. Тег vX.Y.Z собирает и публикует GitHub Release.
Ручной workflow создаёт артефакты без публикации. Версии 0.x — prerelease.

## Устройство

WPF/.NET 8, P/Invoke fwpuclnt.dll, стабильные provider/sublayer GUID,
sublayer weight=65535. На ALE_AUTH_CONNECT_V4/V6 используются отдельные
boot-time и persistent наборы; флаги не объединяются на одном фильтре.
Замена и очистка транзакционны.

Исключения: loopback, DHCP, локальные IP TUN, существующие
Hiddify.exe/HiddifyCli.exe/sing-box.exe только из выбранной установки и
опциональная LAN. DNS-службе Windows отдельного прямого исключения нет.
Обновление адресов выполняется по сетевым событиям и каждые 2 секунды;
после завершения GUI уже установленные правила сохраняются.

Нативные определения:
[Windows SDK](https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders).
Правила платформы:
[object management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
[filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).
Наличие фильтров не доказывает фактическое блокирование пакетов.
Установленные соединения, ответы на входящие потоки, конфликтующие allow-правила
и boot-time требуют живых проверок. Защита не является границей против
локального администратора.

Для передачи работы сотруднику с Codex: [HANDOFF](docs/HANDOFF.md),
[требования](docs/REQUIREMENTS.md), [карточки](docs/tasks/),
[приёмка](docs/ACCEPTANCE.md).
Готовое задание для независимой проверки WFP в Windows VM:
[WFP-VM-REVIEW.txt](docs/prompts/WFP-VM-REVIEW.txt).
Текущее задание коллеге без VM:
[CODE-REVIEW-NO-VM.txt](docs/prompts/CODE-REVIEW-NO-VM.txt).
Подготовка локальной VM: [VM-SETUP.md](docs/VM-SETUP.md).
Временный ручной режим Windows Firewall: [TEMPORARY-FIREWALL.md](docs/TEMPORARY-FIREWALL.md).
Подтверждённые проблемы совместимости: [KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md).

## English

Hiddify Guard is a Windows x64 companion for Hiddify TUN. It installs native
persistent WFP outbound rules and a separate boot-time policy. GUI close,
tray exit and process crashes never disable protection. Disabling requires
an explicit button confirmation, CLI command or uninstall.

0.1.0 is for Windows VM evaluation. Unit tests do not establish packet-level
containment, boot-time enforcement or compatibility with other firewalls.
Complete [acceptance testing](docs/ACCEPTANCE.md) before relying on it.
LAN/private-address exceptions are on by default and can be disabled.
The green shield indicates detection, not verified VPN connectivity.

The installer supports RU/EN, interactive elevated startup for the installing
administrator, manual recovery and uninstall cleanup. Uninstall stops before
file deletion if cleanup fails. Builds are unsigned; do not disable OS security.

Build with .NET 8 using the commands above. scripts/build.ps1 produces EXE,
installer, ZIP and SHA-256. --self-test is read-only; --preview does not access
WFP or write settings. Run policy commands elevated.

Optional diagnostics contact Cloudflare TCP endpoints, Google DNS and ipify.
Timeouts and missing IPv6 are inconclusive. Browsing history is never logged.
MIT licensed. Contributions follow [HANDOFF.md](docs/HANDOFF.md).
