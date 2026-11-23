# Подготовка локальной Windows VM

Это отдельная работа оператора. Коллега пока выполняет
[аудит без VM](prompts/CODE-REVIEW-NO-VM.txt).
Наличие скрипта инспекции не означает, что VM создана или Hyper-V включён.

## Сначала ресурсы

Команда только читает параметры компьютера и дисков:

    ./scripts/vm/Inspect-Host.ps1 -AsJson
    ./scripts/vm/Inspect-Host.ps1 -LabDrive E: -AsJson

E: — пример; требуется реальная буква выбранного накопителя.
Проверяйте поля ResourceReady/ReadyForVmCreation и Blockers, а не только
успешный exit code команды инспекции.
Скрипт проверен в PowerShell 7. Если политика конкретной PowerShell-сессии
запрещает запуск файлов, покажите отказ оператору; настройки ExecutionPolicy
в ходе подготовки автоматически не изменяются.

Для этой лаборатории выбран консервативный стартовый бюджет:
90 GiB свободного места, 6 GiB доступной RAM и 15 GiB запаса на системном томе.
Это бюджет лаборатории, а не формулировка минимальных требований Microsoft.
План гостя: Generation 2, 2 vCPU, 4 GiB стартовой RAM с максимумом 6 GiB,
динамический VHDX 64 GiB. Рост checkpoints нужно контролировать отдельно.

microSD допустима только после проверки доступности тома, файловой системы,
свободного места, картридера и реального I/O. Высокая последовательная скорость
не доказывает достаточную скорость случайных операций.
Для лаборатории используется NTFS/ReFS. Любое форматирование требует отдельного
решения владельца с сохранением нужных данных. Скрипт не форматирует накопители.

## Порядок дальнейших действий

1. Выбрать и проверить накопитель, освободить RAM закрытием выбранных
   пользователем приложений. Чужие процессы автоматически не завершаются.
2. Включить только необходимые компоненты Hyper-V с правами администратора
   и параметром NoRestart. Перезагрузку хоста согласовать отдельно.
3. Повторно проверить доступность Hyper-V, выбранного тома и ресурсов.
4. Получить официальный Windows evaluation ISO, проверить происхождение
   и контрольную сумму. Большие загрузки начинаются после выбора хранилища.
5. Создать новую VM и отдельные VHDX/config/checkpoint-каталоги на выбранном
   накопителе вне репозитория. Не подключать физический системный диск хоста.
6. Использовать Secure Boot/vTPM для Windows 11. Автостарт VM выключен.
   Не создавать external bridge на рабочем адаптере пользователя.
7. Установить гостевую Windows, затем .NET SDK и Hiddify, создать исходный
   checkpoint. Сетевой доступ гостя настраивается отдельным контролируемым шагом.
8. Только после этого проводить активные WFP-тесты внутри гостя.

Настройки VPN, firewall и защиты хоста не являются частью настройки гостя.
Checkpoint на той же карте — средство отката гостя, а не резервная копия
на случай отказа или извлечения накопителя.

## Первичные источники

- [Hyper-V requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)
- [Enable Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v)
- [Create VM](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-machine-in-hyper-v)
- [Windows Enterprise evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
- [Storage I/O](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/hyper-v-server/storage-io-performance)
- [SD application performance](https://www.sdcard.org/developers/sd-standard-overview/application-performance-class/)
