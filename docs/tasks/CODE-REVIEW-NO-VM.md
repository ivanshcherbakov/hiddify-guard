# Аудит кода и unit-тесты без VM

Текущее задание коллеге. Полный промпт:
[CODE-REVIEW-NO-VM.txt](../prompts/CODE-REVIEW-NO-VM.txt).

Границы: Core/Native, Policy, Storage, Diagnostics, GuardController и Core.Tests.
Изменения GUI, installer и scripts/vm принадлежат другому исполнителю.

Проверить ABI, управление памятью, отказы транзакций, ownership,
конфигурацию/ACL/логи и чистые диагностические вердикты.
Использовать FakeSession, локальные тестовые данные и собственные temp-каталоги.

Не нужны VM, elevation или запуск настоящих фильтров.
Запрещены live WFP, сетевые пробы, изменение ОС и работа с настоящим ProgramData.
Windows unit-тесты можно выполнить на обычном ПК либо в CI windows-latest.

Результат: независимый отчёт, подтверждённые дефекты, патч и тесты.
Packet-level и boot-time гарантии остаются неподтверждёнными до VM-приёмки.
