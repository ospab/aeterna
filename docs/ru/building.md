# Сборка

## Что нужно

- Rust **nightly** с компонентом `rust-src` (ядро и пользовательские программы используют
  `build-std` и JSON-описания целей).
- Стабильный Rust для хост-утилит (`tools/tmt`); его автоматически выбирает `rust-toolchain.toml`.
- Для ISO: `xorriso`, `mtools` и `mkfs.vfat`. На Windows их даёт WSL; ядро, пользовательские
  программы, загрузчик и образ диска собираются прямо в Git Bash.
- Для DOOM: компилятор C в WSL/Linux (`target/doom/libdoom.a` после первой сборки переиспользуется).

## Цели сборки

```bash
./build.sh kernel   # только ядро: быстрая проверка компиляции (номер сборки «dev»)
./build.sh          # ядро + загрузчик + гибридный ISO для BIOS/UEFI: isos/ospab-os-v2-N.iso
./build.sh image    # ядро + загрузчик + образ диска GPT/FAT32: isos/ospab-os-v2-N.img (без WSL)
```

На Windows ISO собирается через WSL:

```
wsl.exe -d Debian -e bash -lc 'cd /mnt/d/ospab-projects/ospab.os-v2 && ./build.sh'
```

Что делает `build.sh`, по порядку: собирает программы ring 3 в `user/` (без `RUSTFLAGS`, иначе они
перебьют скрипт компоновщика), собирает ядро для `x86_64-ospab.json`, собирает загрузчик ospab-boot
в `boot/uefi`, затем собирает ISO с Limine и нашим загрузчиком как дополнительным пунктом меню или
образ диска с помощью `tools/mkimage.rs`.

## Номер сборки

`N` — следующий свободный номер среди `isos/ospab-os-v2-*.iso` и `*.img`. Он вшивается в ядро
вместе с коротким хешем коммита (`+` означает незакоммиченные изменения) и датой по UTC:

```
# uname -a
AETERNA ospab 1.1.0 #181 e8f4f4f+ 2026-10-09 x86_64 ospab.os
```

Переменные окружения:

| Переменная | Действие |
|---|---|
| `ISO_PATH` | записать ISO по этому пути вместо нумерованного имени (номер сборки становится `dev`) |
| `ISO_ROOT` | папка для сборки дерева ISO; параллельным сборкам нужны разные |
| `OSPAB_BUILD` | задать номер сборки вручную |
| `LIMINE_BIN_DIR`, `LIMINE_CONF_SRC` | файлы и конфиг Limine |

## Другие части

| Часть | Команда |
|---|---|
| Загрузчик ospab-boot | `cd boot/uefi && cargo build --release` |
| Программы для пакетов и репозиторий | `bash apps/build.sh [repo DIR]` или `.\apps\build.ps1 [-Repo DIR]` |
| Хост-утилита tmt | `bash tools/tmt/build.sh` |
| Макеты графики (на хосте) | см. `gui/` |

## Автотест

`scripts/smoke-test.ps1` загружает ISO в QEMU без окна, ждёт `Console: ready`, вводит команды,
делает снимок экрана и проваливает тест при любом `[ FAIL ]`, панике или исключении:

```powershell
& scripts\smoke-test.ps1 -Firmware uefi -Disk ide -Audio hda -Commands "uname -a","date -e" -Shutdown
```

Параметры: `-Iso`, `-Firmware bios|uefi`, `-Disk none|ide|ahci|nvme`,
`-Nic e1000|pcnet|vmxnet3|virtio`, `-Audio none|hda|ac97|es1370`, `-TimeoutSec`, `-Commands`,
`-Shutdown`.

## Самопроверка при загрузке

Каждая загрузка выполняет проверки ring 3 (переход туда и обратно, две задачи с блокирующими
системными вызовами, проверка указателей, состояние AVX, ELF-программа, утечки кадров). Проверки
IPC медленнее и выполняются только с параметром командной строки ядра `selftest=ipc`.

## Советы

- Если сборки из Windows и из WSL делят `target/`, WSL может взять устаревшее ядро; сверяйте номер
  сборки в логе загрузки.
- Часть исходников использует окончания строк CRLF. `sed` и `grep` из Git Bash отбрасывают символ
  возврата каретки, поэтому для правок скриптами лучше редактор или `perl`.
