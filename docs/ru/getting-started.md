# Первые шаги

## Что нужно

- ISO: `isos/ospab-os-v2-N.iso` из сборки (см. [Сборка](building.md)) или из релизов.
- VMware Workstation (основная платформа для тестов) или QEMU.

## VMware Workstation

Создайте новую виртуальную машину с такими настройками:

| Настройка | Значение | Зачем |
|---|---|---|
| Гостевая ОС | **Other**, версия **Other 64-bit** | при «Other» (32-bit) запускается 32-битная прошивка UEFI, которая не умеет загрузить 64-битный загрузчик |
| Прошивка | **UEFI**, Secure Boot **выключен** | установленная система грузится через UEFI; наш загрузчик не подписан |
| USB-контроллер | **USB 3.x** | USB-клавиатуре и мыши нужен драйвер xHCI; USB 2 (EHCI/UHCI) пока не поддерживается |
| Жёсткий диск | NVMe, SATA или IDE, от 2 ГБ | поддерживаются все три |
| Сеть | NAT | работают e1000, vlance и vmxnet3 |
| Звуковая карта | по умолчанию | ES1371 |
| Guest Isolation | копирование и вставка **разрешены** | тогда Ctrl+V вставляет буфер обмена Windows |
| SCSI-контроллер | нет или LSI Logic | контроллер BusLogic не работает с 64-битными гостями |

Подключите ISO к приводу CD/DVD и включите ВМ. Limine 5 секунд показывает меню:

- **ospab.os Live** — полная система, работающая с CD.
- **ospab.os Installer** — сразу запускает установщик.
- **ospab.os Live (ospab loader, test)** — та же система, запущенная нашим собственным загрузчиком.

## QEMU

```
qemu-system-x86_64 -cdrom isos/ospab-os-v2-N.iso -m 512M -serial stdio
```

Полезные добавки: `-cpu max` (AVX, SMEP/SMAP, RDRAND), `-device intel-hda -device hda-duplex` для
звука, `-device qemu-xhci -device usb-kbd` для USB-клавиатуры и прошивка UEFI, например OVMF:
`-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd`.

## Лог загрузки

Каждый шаг загрузки печатает одну строку статуса на экран и в последовательный порт:

```
[  OK  ] Network: Intel e1000, 10.0.2.15 via DHCP
[  --  ] NVMe: no controller
[ WARN ] ...
[ FAIL ] ...
```

`--` означает, что необязательного устройства нет, это нормально. Загрузка заканчивается строками
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
