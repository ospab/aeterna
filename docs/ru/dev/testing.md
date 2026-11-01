# Тестирование

ospab.os проверяется на четырёх уровнях: тесты `no_std`-крейтов на вашем ПК, безголовая загрузка
в QEMU с автотестом, самопроверки внутри ядра при загрузке и ручные запуски в QEMU и VMware.
Основная целевая платформа — VMware Workstation.

## Команды сборки

Из корня репозитория, в Git Bash, WSL или Linux:

```bash
./build.sh kernel   # только ядро, номер сборки «dev»: быстрая проверка компиляции
./build.sh image    # ядро + оба загрузчика + образ диска GPT isos/ospab-os-v2-N.img (без WSL)
./build.sh          # ядро + оба загрузчика + гибридный ISO isos/ospab-os-v2-N.iso (нужны xorriso, mtools, mkfs.vfat)
```

На Windows ISO собирается в WSL:

```
wsl.exe -d Debian -e bash -lc 'cd /mnt/d/ospab-projects/ospab.os-v2 && ./build.sh'
```

Подробности — в [Сборке](../building.md). Что важно при тестировании:

- `N` — следующий свободный номер среди `isos/ospab-os-v2-*.iso` и `*.img`. Каждая полная сборка
  занимает один номер. Для тестовой сборки, которая не должна занимать номер, задайте `ISO_PATH`
  вне `isos/`: `ISO_PATH=/tmp/test.iso ./build.sh`. Номер сборки тогда `dev`. `ISO_ROOT` —
  промежуточный каталог (параллельным сборкам давайте разные), `OSPAB_BUILD` задаёт номер
  принудительно, `NIGHTLY` выбирает набор инструментов (на Windows `build.sh` предпочитает GNU
  nightly, если он установлен), `TARGET` заменяет цель ядра.
- `./build.sh kernel` сначала собирает и программы в `user/`, потому что ядро встраивает их для
  своих самопроверок.
- `uname -a` в госте показывает номер сборки, короткий хеш коммита (`+` — есть незакоммиченные
  изменения) и дату. Проверяйте это, если поведение выглядит устаревшим. Сборки Windows и WSL с
  общим `target/` могут оставить старое ядро.
- `scripts/mkiso.sh [OUT.iso]` собирает ISO из уже готовых частей (переменные `KERNEL`, `LOADER`,
  `BIOS`, `CFG`, `ISO_ROOT`, `PKG_DIR`). Он кладёт в ISO для установщика файлы `.tmt` из
  `apps/dist/` (не больше 13). Старый `apps/dist/` попадёт в ваш ISO.
- `scripts/bios-image.sh [OUT]` собирает образ BIOS-загрузчика (по умолчанию
  `boot/bios/target/bios.img`). `scripts/checksum.sh <файл> [каталог]` пишет контрольные суммы
  SHA-256, SHA-512 и MD5.

## Запуск в QEMU

`scripts/run-qemu.ps1` (PowerShell 7) и `scripts/run-qemu.sh` запускают новейший ISO с полным
набором устройств. Журнал ядра идёт в `target/qemu/serial.log`, монитор QEMU слушает
`telnet 127.0.0.1 55555`.

```powershell
.\scripts\run-qemu.ps1                          # BIOS, e1000, звук HDA, диск AHCI, окно
.\scripts\run-qemu.ps1 -Uefi -VMware            # UEFI; видео vmware, pcnet, AC97, AHCI
.\scripts\run-qemu.ps1 -Nic pcnet -Audio ac97 -Disk nvme
.\scripts\run-qemu.ps1 -Headless                # без окна, последовательный порт в эту консоль
.\scripts\run-qemu.ps1 -Wav C:\temp\out.wav     # записать вывод звука
```

Параметры (в shell-скрипте они в виде `--имя значение`): `-Iso`, `-Uefi`,
`-Nic e1000|pcnet|rtl8139|rtl8169|virtio|vmxnet3|none`, `-Audio hda|ac97|es1370|none`,
`-AudioBackend dsound|sdl|none`, `-Wav ФАЙЛ`, `-Disk ahci|nvme|ide|none`, `-DiskSize 2G`,
`-Vga std|vmware|virtio`, `-VMware`, `-Mem 1G`, `-Smp N`, `-Whpx`, `-Headless`,
`-SerialToConsole`, `-NoUsb`, `-MonitorPort N`, `-QemuDir КАТАЛОГ` (или переменная `QEMU_DIR`);
остальные аргументы передаются в QEMU. Образ диска — `target/qemu/disk.qcow2`, создаётся при первом
использовании. Скрипты считают, что QEMU лежит в `D:\Toolz\qemu`, если не задан `-QemuDir`.

### Командные строки за этими скриптами

BIOS, журнал в терминал:

```
qemu-system-x86_64 -m 512M -cpu max -cdrom isos/ospab-os-v2-N.iso -boot d -serial stdio
```

UEFI: добавьте прошивку только для чтения. QEMU для Windows поставляет `share/edk2-x86_64-code.fd`,
в пакетах Linux она называется `OVMF_CODE.fd`:

```
-drive if=pflash,format=raw,readonly=on,file=edk2-x86_64-code.fd
```

Диск (один раз создайте командой `qemu-img create -f qcow2 disk.qcow2 2G`). Выберите один
контроллер:

```
-drive id=disk0,if=none,format=qcow2,file=disk.qcow2
-device ide-hd,drive=disk0                                  # IDE (ATA PIO)
-device ahci,id=ahci0 -device ide-hd,drive=disk0,bus=ahci0.0  # AHCI
-device nvme,drive=disk0,serial=ospab0001                   # NVMe
-device virtio-blk-pci,drive=disk0                          # virtio-blk
```

Сырой `.img` от `./build.sh image` загружается как диск: `-drive file=isos/ospab-os-v2-N.img,format=raw`.

Сеть (пользовательский режим; гость — 10.0.2.15, шлюз и ваш ПК — 10.0.2.2, DNS — 10.0.2.3):

```
-netdev user,id=n0 -device e1000,netdev=n0     # также pcnet, rtl8139, rtl8169, virtio-net-pci, vmxnet3
```

Звук (на Windows `dsound`, в других системах `sdl` или `pa`):

```
-audiodev dsound,id=a0 -device intel-hda -device hda-duplex,audiodev=a0
-audiodev dsound,id=a0 -device AC97,audiodev=a0
-audiodev dsound,id=a0 -device ES1370,audiodev=a0
```

Записать звук в WAV-файл вместо воспроизведения (затем проверьте в файле уровень и частоту, как для
`apps/tone`):

```
-audiodev wav,id=a0,path=out.wav -device intel-hda -device hda-duplex,audiodev=a0
```

USB-клавиатура и планшет, дисплей и монитор:

```
-device qemu-xhci,id=xhci -device usb-tablet,bus=xhci.0 -device usb-kbd
-vga std            # или: -vga vmware (смена режима на лету и автоподгонка)
-display none       # без окна
-monitor telnet:127.0.0.1:55555,server,nowait
```

Полезные команды монитора: `sendkey ctrl-c`, `screendump shot.png -f png`, `info registers`,
`quit`. Для `selftest=mem` ядру нужен второй последовательный порт:
`-serial file:com1.log -serial file:com2.log`.

Параметры ядра берутся из пункта меню загрузчика. Пункт «ospab.os (debug)» использует
`mode=live debug=1 selftest=ipc persist=ro`. В меню клавиша `e` правит командную строку выбранного
пункта на одну загрузку. Другие параметры: `selftest=mem|sched|all` и `session=desktop` (см.
[Загрузка](../boot.md)).

Скорость: `-accel tcg,tb-size=256` точный и медленный. `-accel whpx` (Windows) или `-accel kvm`
(Linux) быстрые. Игра, плавная в VMware, в TCG может тормозить.

## Автотест

`scripts/smoke-test.ps1` (PowerShell 7) безголово загружает ISO в QEMU, ждёт строку
`[  OK  ] Console: ready` на последовательном порту, набирает команды через `sendkey` монитора,
делает скриншот, при желании набирает `shutdown` и выносит вердикт PASS или FAIL. ISO он не
собирает. Код возврата 0 — PASS.

```powershell
& scripts\smoke-test.ps1                                     # новейший ISO, BIOS, без диска
& scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda
& scripts\smoke-test.ps1 -Commands "date -e","uname -a" -Shutdown
& scripts\smoke-test.ps1 -Iso isos\ospab-os-v2-179.iso -Nic virtio -TimeoutSec 180
```

| Параметр | Значения | По умолчанию | Смысл |
|---|---|---|---|
| `-Iso` | путь | новейший `isos\ospab-os-v2-N.iso` | образ для загрузки |
| `-Firmware` | `bios`, `uefi` | `bios` | для UEFI используется прошивка pflash только для чтения |
| `-Disk` | `none`, `ide`, `ahci`, `nvme` | `none` | временный qcow2 на 256 МБ, потом удаляется |
| `-Nic` | `e1000`, `pcnet`, `vmxnet3`, `virtio` | `e1000` | сеть в пользовательском режиме |
| `-Audio` | `none`, `hda`, `ac97`, `es1370` | `none` | пустой звуковой бэкенд |
| `-TimeoutSec` | от 10 до 3600 | 120 | сколько ждать строку готовности |
| `-Commands` | строки | нет | набираются после загрузки, каждая с Enter, с паузой 1,5 с |
| `-Shutdown` | ключ | выкл. | набрать `shutdown`; FAIL, если QEMU работает через 20 с |

Если в `-Commands` несколько значений, используйте `&` или интерактивный `pwsh`; `pwsh -File`
не привязывает массивы через запятую. QEMU запускается с 512 МБ и `-no-reboot`.

Вердикт FAIL, если строка готовности не появилась, если какая-либо строка последовательного порта
начинается с `[ FAIL ]`, если в строке есть `panic`, `PANIC` или `EXCEPTION`, если QEMU неожиданно
завершился или, с `-Shutdown`, не завершился. Скрипт печатает все строки состояния и записывает
`serial.log`, `screendump.png` и вывод QEMU в каталог с отметкой времени; путь он печатает.

Пути к QEMU, `qemu-img`, прошивке UEFI и каталогу вывода — переменные в начале скрипта
(`$QemuExe`, `$QemuImg`, `$PflashFw`, `$OutRoot`). Они заданы под одну машину. Поправьте их перед
использованием, особенно `$PflashFw` для `-Firmware uefi`.

Автотест проверяет загрузку, а не вашу функцию. Добавьте в `-Commands` строку, которая её
задействует, и прочитайте скриншот и журнал.

## Самопроверки при загрузке

Каждая загрузка выполняет проверки ring 3 и печатает
`[  OK  ] Ring 3 self-test: N checks passed`: круг через процесс, две задачи с блокирующими
вызовами, проверку пользовательских указателей, состояние AVX, ELF-программу и проверку, что
после завершения процессов не утекли страницы. Дополнительные группы включаются параметром ядра:

| Параметр | Что запускает |
|---|---|
| `selftest=ipc` | проверки IPC и дескрипторов (`user/ipcsrv`, `user/ipcclient`) |
| `selftest=mem` | общая память и драйвер COM2 в ring 3 (`user/memtest`, `user/uartdrv`); нужен второй последовательный порт |
| `selftest=sched` | правила блокировок и задачи со своими таблицами дескрипторов (`core/selftest.rs`) |
| `selftest=all` | все сразу; группы можно комбинировать: `selftest=ipc,mem` |

Команды оболочки, проверяющие работающую систему изнутри: `ring3test`, `testmode` (показывает
экраны паники и сбоя, не роняя систему), `verify_mem`, `verify_sched`, `verify_net`,
`verify_audio`, `soundtest`, `bench`.

Когда вы добавляете возможность, доступную программам ring 3, добавьте случай в самопроверки или
небольшую тестовую программу в `apps/` (см. [Работа с ядром](kernel-hacking.md)).

## Чтение последовательного журнала

Всё, что делает ядро, попадает в первый последовательный порт (COM1). В QEMU: `-serial stdio` или
`-serial file:serial.log`. В VMware: добавьте последовательный порт, «Use output file», и
читайте файл, пока ВМ работает. Журнал — это и первое, что нужно приложить к отчёту об ошибке.

```
[ .... ] Network                          шаг начался
[  OK  ] Network: Intel e1000, 10.0.2.15 via DHCP
[  --  ] NVMe: no controller              необязательного оборудования нет: это нормально
[ WARN ] ... / [ FAIL ] ...               проблема; FAIL проваливает автотест
[DRV] Audio: probing / active             реестр драйверов
[NET] / [AUDIO] / [ES1371] / [e1000]      подробные строки одной подсистемы
[RING3] ...                               подробности самопроверок
[SYSCALL] exit(0)                         процесс ring 3 завершился с этим кодом
[CRITICAL] Process 7 name at 0x...        процесс ring 3 упал и был убит
[FATAL] CPU Exception: ...                сбой ядра; дальше идёт Fault RIP
```

То, что программа печатает через `println!`, тоже попадает в последовательный порт. С `debug=1`
подробные строки идут ещё и на экран. В сохранённом журнале ищите
`grep -n "FAIL\|CRITICAL\|FATAL"`.

## Тесты на хосте для no_std-крейтов

Ядра больших программ и файловая система — обычные крейты `no_std` с обычными наборами
`cargo test`, которые идут на вашем ПК. Это самый быстрый способ найти логические ошибки.

`.cargo/config.toml` репозитория выбирает цель ядра, а `apps/.cargo/config.toml` — цель ring 3.
Обойти это можно двумя способами:

- запускайте cargo из каталога вне репозитория и передавайте `--manifest-path`, либо
- оставайтесь в репозитории, берите **stable** и передавайте `--target <ваша хостовая цель>`.

На Windows без C++ Build Tools берите GNU-хост:

```
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/beeb-core/Cargo.toml --target x86_64-pc-windows-gnu --release
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/drift-core/Cargo.toml --target x86_64-pc-windows-gnu --release
cargo +stable-x86_64-pc-windows-gnu test --manifest-path fs/aeternafs/Cargo.toml --target x86_64-pc-windows-gnu --release
```

На Linux берите `--target x86_64-unknown-linux-gnu` или опустите `--target` и запускайте вне
репозитория. Не берите nightly внутри репозитория: его настройка `build-std` ломает сборку для
хоста ошибкой «duplicate lang item». `RUSTFLAGS` задавать не нужно.

| Крейт | Тесты |
|---|---|
| `apps/beeb-core` | модульные тесты процессора, видео, VIA, клавиатуры, диска и звукового чипа (около 20) |
| `apps/drift-core` | модульные тесты и `tests/harness.rs`: сценарная игра по меню, взлёту, стыковке, торговле, бою, сохранению, смерти и концовке. Пишет скриншоты в формате PPM в `$DRIFT_SHOTS` (по умолчанию `target/drift-shots` относительно текущего каталога на момент запуска теста, то есть каталога крейта) |
| `fs/aeternafs` | `model` (случайные операции против модели в памяти), `crash` (отключение питания после каждой записи блока), `corrupt` (искажение битов), `perf` (игнорируется) |

### Игнорируемые тесты и их переменные окружения

Им нужны файлы, которых нет в репозитории, либо они долгие. Запускайте с `-- --ignored
--nocapture` и заданными переменными.

**Загрузочный тест beeb**, `apps/beeb-core/tests/boot.rs`, тест `boot_and_shoot`. Загружает машину и
сохраняет скриншоты в PNG. ROM MOS ваш; никогда не добавляйте его в репозиторий.

```powershell
$env:BEEB_MOS = 'C:\roms\os12.rom'
$env:BEEB_OUT = 'C:\temp\beeb'
$env:BEEB_SHOTS = '60,300'
cargo +stable-x86_64-pc-windows-gnu test --manifest-path apps/beeb-core/Cargo.toml --target x86_64-pc-windows-gnu --release --test boot -- --ignored --nocapture
```

| Переменная | Смысл |
|---|---|
| `BEEB_MOS` | путь к ROM MOS на 16 КиБ. Обязательна: без неё тест сразу возвращается |
| `BEEB_OUT` | каталог для `beeb_NNNNN.png` (по умолчанию текущий) |
| `BEEB_FRAMES` | сколько кадров выполнить (по умолчанию 300) |
| `BEEB_SHOTS` | номера кадров для сохранения через запятую; последний кадр сохраняется всегда |
| `BEEB_KEYS` | сценарий клавиш: `кадр:ИмяКлавиши:d` — нажать, `кадр:ИмяКлавиши:u` — отпустить, через запятую |
| `BEEB_BASIC` | ROM языка, вставляется в слот 15 |
| `BEEB_SSD` | образ диска |
| `BEEB_SHIFT_BREAK` | задайте (любое значение), чтобы сброс шёл с зажатым Shift, это грузит диск |
| `BEEB_FAKE_LOADER` | `echo` или любое другое значение: крошечный тестовый ROM вместо языка |
| `BEEB_TRACE`, `BEEB_TRACEFRAME`, `BEEB_JITTER` | отладочные трассы |

**Звуковой тест beeb**, `apps/beeb-core/tests/sound.rs`, тест `boot_audio` (`--test sound`). Те же
`BEEB_MOS`, `BEEB_FRAMES` (по умолчанию 600), `BEEB_KEYS`, `BEEB_BASIC`, `BEEB_SSD`,
`BEEB_SHIFT_BREAK`; `BEEB_WIN` — окно анализа в кадрах (по умолчанию 25), `BEEB_WAV` — файл, куда
записать звук. Тест печатает уровень и частоту переходов через ноль для каждого окна.

**Проверка 6502**, в `apps/beeb-core/src/cpu.rs`: `klaus_functional` требует `KLAUS_BIN` (путь к
двоичному файлу функционального теста, при желании `KLAUS_SUCCESS` — шестнадцатеричный адрес, по
умолчанию 3469), `klaus_decimal` требует `KLAUS_DEC_BIN` (при желании `KLAUS_DEC_DONE`). Запуск:
`--lib -- --ignored klaus`. Эти двоичные файлы сторонние, в репозиторий они не попадают.

**Скриншоты drift**: задайте `DRIFT_SHOTS`, чтобы выбрать, куда набор тестов пишет `*.ppm` и
`*.wav`. Игнорируемых тестов у drift нет.

**Производительность AeternaFS**:
`cargo test --release --test perf -- --ignored --nocapture --test-threads=1` в `fs/aeternafs`
(100 000 мелких файлов, затем файл на 1 ГиБ). `AETERNA_PERF_DIR` задаёт каталог для образа на
1 ГиБ.

## Утилиты для хоста

**tmt**, утилита пакетов (`tools/tmt`). Соберите её `bash tools/tmt/build.sh`, она запишет
`tools/tmt/bin/tmt` (на Windows `.exe`). Используется stable.

```
tmt keygen [--force] [--key FILE] [--pub FILE]
tmt pack <manifest.toml> [-o OUTDIR] [--set KEY=VALUE]
tmt list <file.tmt>
tmt verify <file.tmt>
tmt repo add <repo-dir> <file.tmt>...
tmt repo index <repo-dir>
tmt repo sign <repo-dir> [--key FILE]
tmt repo verify <repo-dir> [--pub FILE]
```

Ключ подписи по умолчанию — `%USERPROFILE%\.ospab\tmt.key` (`$HOME/.ospab/tmt.key`). Это ключ
выпуска: не копируйте, не печатайте и не коммитьте его и не запускайте `keygen --force` поверх
него. Для проверок используйте `--key` со своим ключом. `tools/tmt/e2e-qemu.ps1` — сквозной тест
`tomato` на исправном и подделанных репозиториях в QEMU; как подготовить, написано в его заголовке.

**oosfs**, образы AeternaFS (`tools/oosfs`). Сборка:

```
cd tools/oosfs
cargo +stable-x86_64-pc-windows-gnu build --release --target x86_64-pc-windows-gnu
```

(`--target` внутри репозитория нужен; см. выше.) Использование:

```
oosfs mkfs <image> --size 2G [--label L]
oosfs ls|cat|get|put|rm|mkdir|mv|stat|info <image> ...
oosfs put <image> <src> <dest> [-r]
oosfs snap create|list|delete|rollback <image> [name]
oosfs fsck <image> [--deep]
```

`--offset <байты>` или `--part N` (GPT, секторы по 512 байтов) работает с разделом внутри образа
диска. В Git Bash пути, начинающиеся с `/`, переписываются MSYS; задайте `MSYS_NO_PATHCONV=1`
или используйте PowerShell. См. [AeternaFS](../aeternafs.md).

**mkimage** (`tools/mkimage.rs`) собирается и вызывается командой `./build.sh image`.

## Заметки по VMware

- Создайте ВМ как в [Первых шагах](../getting-started.md): Other 64-bit, BIOS или UEFI с
  выключенным Secure Boot, USB 3.x, диск NVMe или SATA, NAT, звуковая карта, без SCSI BusLogic.
- Подключите ISO. Чтобы проверить образ диска, преобразуйте его:
  `qemu-img convert -O vmdk isos/ospab-os-v2-N.img disk.vmdk`.
- Добавьте последовательный порт с выводом в файл для журнала. Файл `.vmx` правьте, пока ВМ
  выключена.
- Графика — адаптер VMware SVGA II. Смена режима на лету и автоподгонка работают только на нём.
  Программа, которая рисует, должна вызывать `screen::flush()`.
- Звук по умолчанию — Ensoniq ES1371. HDA и AC97 проверяйте в QEMU.
- Копирование и вставка с хостом (Ctrl+V) требует включённой «guest isolation: copy and paste».
- Каждое изменение, затрагивающее загрузку, дисплей, ввод или звук, проверяйте в VMware. QEMU —
  хороший первый фильтр, но не замена.
