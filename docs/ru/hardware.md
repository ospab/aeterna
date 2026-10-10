# Оборудование

ospab.os разрабатывается и тестируется в VMware Workstation и QEMU. На реальном железе не
проверялась.

| Класс | Поддерживается | Примечания |
|---|---|---|
| Прошивка | UEFI (x86-64), BIOS через Limine на ISO | установленная система грузится только через UEFI |
| Процессор | x86-64; использует SSE2, XSAVE/AVX, NX, SMEP/SMAP, RDRAND, если есть | одно ядро (SMP пока нет) |
| Диски | ATA PIO (IDE), AHCI (SATA), NVMe, virtio-blk | первый NVMe-контроллер, namespace 1; секторы 512 байт и 4 КБ |
| Сеть | Intel e1000, RTL8139, RTL8169/8111, virtio-net, AMD PCnet (vlance в VMware), VMware vmxnet3 | только IPv4 |
| Звук | Intel HDA, AC97, Ensoniq ES1371/ES1373/CT5880, ES1370 | 16 бит стерео, DMA с опросом |
| Ввод | клавиатура и мышь PS/2, USB-клавиатура и мышь через xHCI (включая хабы), абсолютная мышь VMware | нет EHCI/UHCI и горячего подключения |
| Видео | фреймбуфер UEFI GOP, VMware SVGA II | программная отрисовка |
| Платформа | ACPI (выключение, перезагрузка, кнопка питания), PCI, CMOS RTC, PIT, таймер local APIC | |
| Связь с хостом | backdoor VMware: буфер обмена, абсолютная мышь | |

## Рекомендуемые настройки VMware

См. таблицу в разделе [Первые шаги](getting-started.md#vmware-workstation). Главное: Other 64-bit,
UEFI без Secure Boot, USB 3.x, разрешённые копирование и вставка, без SCSI BusLogic.

## Диагностика

Каждый драйвер пишет в первый последовательный порт с меткой вроде `[AHCI]`, `[NVME]`, `[XHCI]`,
`[HDA]`, `[e1000]`. В VMware добавьте последовательный порт с выводом в файл, чтобы читать лог; в
QEMU используйте `-serial stdio` или `-serial file:boot.log`.
