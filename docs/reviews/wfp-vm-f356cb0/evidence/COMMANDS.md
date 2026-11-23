# Команды и коды возврата

Проверка от 23 ноября 2026 года. Исходный SHA
`f356cb0fdc943be0b821d400b81002cc5c9c111b`.
Среда сборки Windows x64 `10.0.26300.0`, SDK `8.0.428`, VSTest `17.11.2` x64.
В приложенных логах и TRX обезличены имена рабочей машины, пользователя и пути.

## Исходники и SDK

| Команда | Код |
|---|---:|
| `git clone --no-checkout -- https://github.com/ivanshcherbakov/hiddify-guard.git work/hiddify-guard` в ограниченной сети | 128 |
| Та же команда с разрешённым сетевым доступом | 0 |
| `git checkout --detach f356cb0` | 0 |
| `git rev-parse HEAD` | 0 |
| `git switch -c review/wfp-vm-f356cb0` | 0 |
| `dotnet --version` из распакованного SDK | 0 |

Win-x64 ZIP загружен по URL из [метаданных .NET 8](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json).
Результат `Get-FileHash -Algorithm SHA512` совпал с опубликованным SHA-512
`CCE1DC5CFB2C5B73DDD9D3658F6009DEB85BE3A58DBEC44A6DFE3910BB32B044AD2FC6BB28C77ADED70C73270A204D207FE790DCB82FFCA6C7B42C1335B51C21`.
SDK, кэш NuGet и временные данные тестов находились в рабочей папке.

## Сборка и тесты

Команды выполнялись в клоне. `dotnet` здесь обозначает исполняемый файл
распакованного SDK. Для тестов разрешён локальный транспорт VSTest.

```powershell
dotnet restore src/HiddifyGuard.sln --disable-build-servers --source https://api.nuget.org/v3/index.json
dotnet build src/HiddifyGuard.sln -c Release --no-restore --disable-build-servers -m:1 -p:UseSharedCompilation=false /nr:false
dotnet test src/HiddifyGuard.sln -c Release --no-build --no-restore --disable-build-servers --results-directory <каталог> --logger 'trx;LogFileName=baseline.trx'
```

| Проверка | Код | Файл |
|---|---:|---|
| Restore | 0 | baseline-restore.log |
| Исходник, Release build | 0 | baseline-build.log |
| Исходник, unit-тесты | 0 | baseline-test-retry.log, baseline.trx |
| Патч, Release build той же командой | 0 | patched-build.log |
| Патч, unit-тесты с `LogFileName=patched.trx` | 0 | patched-test.log, patched.trx |

Первая параллельная сборка была отменена (`MSB5021`, код 1).
Первый тестовый запуск в ограниченной среде оставался в ожидании раннера
и был остановлен (код 1). В архив входят журналы завершённых проверок.

## Проверка применимости патча

| Команда | Код |
|---|---:|
| `git diff --check f356cb0` | 0 |
| `git diff --cached --quiet HEAD` | 0 |
| `git apply --cached --check wfp-review-f356cb0.patch` | 0 |
| `git apply --reverse --check wfp-review-f356cb0.patch` | 0 |

SHA-256 патча
`43A7BCC53197ED704FBB08CD51F87D1A2095FA8287762C78AFDF5AF5E37B7A29`.

Живых команд в VM, снимков WFP и пакетных захватов нет.
