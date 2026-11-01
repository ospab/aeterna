# Сборка

## Что нужно

- Rust nightly с компонентом `rust-src` (ядро и пользовательские программы используют
  `build-std` и JSON-описания целей).
- Стабильный Rust для хост-утилит (`tools/tmt`). Его выбирает `rust-toolchain.toml`.
- Для ISO: `xorriso`, `mtools` и `mkfs.vfat`. На Windows их даёт WSL. Ядро, пользовательские
  программы, оба загрузчика и образ диска собираются прямо в Git Bash.
- Ассемблер не нужен. Код реального режима в BIOS-загрузчике написан как `global_asm!` в Rust
  (см. [Загрузка](boot.md)). Только `dd` кладёт второй этап BIOS в `bios.img`.
- Для DOOM нужен компилятор C в WSL/Linux. `target/doom/libdoom.a` после первой сборки
  переиспользуется.

## Цели сборки

```bash
./build.sh kernel   # только ядро: быстрая проверка компиляции (номер сборки «dev»)
./build.sh          # ядро + оба загрузчика + гибридный ISO для BIOS и UEFI: isos/ospab-os-v2-N.iso
./build.sh image    # ядро + оба загрузчика + образ диска GPT (раздел BIOS boot + FAT32 ESP): isos/ospab-os-v2-N.img (без WSL)
```

На Windows ISO собирается через WSL:

```
wsl.exe -d Debian -e bash -lc 'cd /mnt/d/ospab-projects/ospab.os-v2 && ./build.sh'
```

`build.sh` делает по порядку:

1. Собирает программы ring 3 в `user/` без `RUSTFLAGS`, иначе они перебьют скрипт компоновщика.
2. Собирает ядро для `x86_64-ospab.json`.
3. Собирает UEFI-загрузчик ospab-boot в `boot/uefi` и BIOS-загрузчик в `boot/bios`
   (`scripts/bios-image.sh`).
4. Собирает гибридный ISO через `scripts/mkiso.sh` (xorriso: El Torito для BIOS и UEFI, MBR и GPT
   для USB-флешек) или образ диска через `tools/mkimage.rs`.

ISO грузится на машинах с BIOS и с UEFI, с CD и с USB-флешки
(`dd if=ospab-os-v2-N.iso of=/dev/sdX bs=4M`).

## Номер сборки

`N` — следующий свободный номер среди `isos/ospab-os-v2-*.iso` и `*.img`. Он вшивается в ядро
вместе с коротким хешем коммита (`+` значит, что есть незакоммиченные изменения) и датой по UTC:

```
# uname -a
AETERNA ospab 1.1.0 #181 e8f4f4f+ 2026-10-09 x86_64 ospab.os
```

Переменные окружения:

| Переменная | Действие |
|---|---|
| `ISO_PATH` | записать ISO по этому пути вместо нумерованного имени (номер сборки станет `dev`) |
| `ISO_ROOT` | папка, где собирается дерево ISO; параллельным сборкам нужны разные |
| `OSPAB_BUILD` | задать номер сборки вручную |

## Другие части

| Часть | Команда |
|---|---|
| UEFI-загрузчик ospab-boot | `cd boot/uefi && cargo build --release` |
| BIOS-загрузчик ospab-boot | `scripts/bios-image.sh` (пишет `boot/bios/target/bios.img`) |
| ISO из готовых частей | `scripts/mkiso.sh [OUT.iso]` (в WSL/Linux; переменные `KERNEL`, `LOADER`, `BIOS`, `CFG`, `ISO_ROOT`) |
| Программы для пакетов и репозиторий | `bash apps/build.sh [repo DIR]` или `.\apps\build.ps1 [-Repo DIR]` |
| Хост-утилита tmt | `bash tools/tmt/build.sh` |
| Макеты графики (на хосте) | см. `gui/` |

## Автотест

`scripts/smoke-test.ps1` грузит ISO в QEMU без окна и ждёт `Console: ready`. Потом вводит команды,
делает снимок экрана и проваливает тест при любом `[ FAIL ]`, панике или исключении:

```powershell
& scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda -Commands "uname -a","date -e" -Shutdown
```

Параметры: `-Iso`, `-Firmware bios|uefi`, `-Disk none|ide|ahci|nvme`,
`-Nic e1000|pcnet|vmxnet3|virtio`, `-Audio none|hda|ac97|es1370`, `-TimeoutSec`, `-Commands`,
`-Shutdown`.

## Самопроверка при загрузке

Каждая загрузка выполняет проверки ring 3: переход туда и обратно, две задачи с блокирующими
системными вызовами, проверку указателей, состояние AVX, ELF-программу и утечки кадров. Проверки
IPC медленнее, они идут только с параметром командной строки ядра `selftest=ipc`.

## Советы

- Если сборки из Windows и из WSL делят `target/`, WSL может взять устаревшее ядро. Сверяйте номер
  сборки в логе загрузки.
- Часть исходников использует окончания строк CRLF. `sed` и `grep` из Git Bash отбрасывают символ
  возврата каретки, поэтому для правок скриптами берите редактор или `perl`.
