# Первые шаги

## Что нужно

- ISO: `isos/ospab-os-v2-N.iso` из сборки (см. [Сборка](building.md)) или из релизов.
- VMware Workstation (основная платформа для тестов) или QEMU.

## VMware Workstation

Создайте новую виртуальную машину с такими настройками:

| Настройка | Значение | Зачем |
|---|---|---|
| Гостевая ОС | Other, версия Other 64-bit | Обычный «Other» (32-bit) запускает 32-битную прошивку UEFI, она не умеет загружать 64-битный загрузчик |
| Прошивка | BIOS или UEFI (Secure Boot выключен) | У ospab-boot есть BIOS- и UEFI-вариант. Загрузчик не подписан, поэтому Secure Boot должен быть выключен |
| USB-контроллер | USB 3.x | USB-клавиатуре и мыши нужен драйвер xHCI. USB 2 (EHCI/UHCI) пока не поддерживается |
| Жёсткий диск | NVMe, SATA или IDE, от 2 ГБ | Работают все три |
| Сеть | NAT | Работают e1000, vlance и vmxnet3 |
| Звуковая карта | по умолчанию | ES1371 |
| Guest isolation | копирование и вставка разрешены | Тогда Ctrl+V вставляет буфер обмена Windows |
| SCSI-контроллер | нет или LSI Logic | Контроллер BusLogic не работает с 64-битными гостями |

Подключите ISO к приводу CD/DVD и включите ВМ. В любом режиме прошивки ospab-boot 5 секунд
показывает меню:

- ospab.os Live: полная система, работает прямо с CD.
- ospab.os Desktop: сеанс с рабочим столом.
- ospab.os Installer: сразу запускает установщик.
- ospab.os (debug), Memory test, Reboot, Power off, а на UEFI ещё Firmware settings.

Режим установщика «Erase entire disk» делает диск, который грузится и в BIOS, и в UEFI. Режим
«Install alongside other systems» работает только в UEFI; если живая система запущена в BIOS,
установщик его не даёт.

## QEMU

```
qemu-system-x86_64 -cdrom isos/ospab-os-v2-N.iso -m 512M -serial stdio
```

Так запускается путь через BIOS (SeaBIOS). Чтобы грузиться с USB-флешки, а не с CD, используйте
`-drive file=isos/ospab-os-v2-N.iso,format=raw,if=none,id=u -device qemu-xhci -device usb-storage,drive=u`.

Что ещё может пригодиться: `-cpu max` (AVX, SMEP/SMAP, RDRAND), `-device intel-hda -device hda-duplex`
для звука, `-device qemu-xhci -device usb-kbd` для USB-клавиатуры и прошивка UEFI, например OVMF:
`-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd`.

## Лог загрузки

Каждый шаг загрузки печатает одну строку статуса на экран и в последовательный порт:

```
[  OK  ] Network: Intel e1000, 10.0.2.15 via DHCP
[  --  ] NVMe: no controller
[ WARN ] ...
[ FAIL ] ...
```

`--` значит, что необязательного устройства нет, и это нормально. Загрузка заканчивается строками
`[  OK  ] Ring 3 self-test: N checks passed` и `[  OK  ] Console: ready`.

## Первые команды

```
# help                 все команды; help <команда> — подробности
# tutor                короткая экскурсия
# uname -a             версия ядра и номер сборки
# date                 местное время; date -e — секунды с 2012-08-09
# ip addr              сетевой адрес
# curl ipinfo.io       настоящий HTTPS-запрос
# tomato update           синхронизировать репозиторий пакетов
# install              установить на диск
# shutdown             выключить через ACPI
```

Дальше: [Установка](installation.md), [Оболочка и утилиты](shell.md).
