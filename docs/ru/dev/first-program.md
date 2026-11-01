# Первая программа

На этой странице программа проходит путь от пустого каталога до работающего процесса в ВМ.
Пример, `wordcount`, читает файл и печатает число строк, слов и байтов. Каждый шаг проверен по
репозиторию.

## Что нужно

- Rust nightly с компонентом `rust-src`. Программы собираются с `build-std` для своей цели
  `x86_64-unknown-oos` (`user/x86_64-unknown-oos.json`).

  ```
  rustup toolchain install nightly --component rust-src
  ```

- На Windows без C++ Build Tools от Visual Studio берите GNU nightly. Сборка `compiler_builtins`
  запускает build-скрипт на вашем ПК, а набор MSVC его не слинкует:

  ```
  rustup toolchain install nightly-x86_64-pc-windows-gnu --component rust-src
  ```

  Тогда везде, где на этой странице написано `cargo +nightly`, пишите
  `cargo +nightly-x86_64-pc-windows-gnu`. Кросс-компиляции не нужен компилятор C: программа
  линкуется через `rust-lld`.
- ISO ospab.os и ВМ ([Первые шаги](../getting-started.md)).
- Переменная `RUSTFLAGS` не должна быть задана. Она заменяет флаги из `apps/.cargo/config.toml`,
  а там лежит скрипт компоновщика, и программа не слинкуется.

## 1. Создайте крейт

Программы живут в рабочей области `apps/`. Создайте каталог и два файла:

`apps/wordcount/Cargo.toml`

```toml
[package]
name = "wordcount"
description = "Counts lines, words and bytes of a file"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
liboos = { path = "../../user/liboos" }
```

`apps/wordcount/src/main.rs`

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Your Name
//! wordcount: counts lines, words and bytes of a file.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use liboos::println;

liboos::entry!(main);

fn main(args: liboos::Args) -> i32 {
    let Some(path) = args.get(1) else {
        println!("usage: wordcount <file>");
        return 2;
    };
    let fd = liboos::open(path, 0);
    if fd < 0 {
        println!("wordcount: cannot open {} (error {})", path, fd);
        return 1;
    }
    let fd = fd as u64;
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = liboos::read(fd, &mut buf);
        if n < 0 {
            println!("wordcount: read error {}", n);
            liboos::close(fd);
            return 1;
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    liboos::close(fd);

    let lines = data.iter().filter(|&&b| b == b'\n').count();
    let words = data.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty()).count();
    println!("{} lines, {} words, {} bytes", lines, words, data.len());
    0
}
```

Затем добавьте крейт в `members` в `apps/Cargo.toml`:

```toml
members = ["hello-tmt", "cowsay", "calc", ..., "wordcount"]
```

Что здесь что:

- `#![no_std]` и `#![no_main]`: стандартной библиотеки и Rust-овского `main` нет. liboos даёт
  `_start`, который готовит кучу и вызывает вашу функцию.
- `liboos::entry!(main)` регистрирует `fn main(args: liboos::Args) -> i32`. Возвращаемое значение —
  код завершения. Оболочка показывает его в `$?`.
- `extern crate alloc;` даёт `Vec`, `String`, `Box`, `format!`. Куча готова до `main` и растёт
  по мере надобности.
- `println!` пишет в стандартный вывод. Паника печатает `panic: ...` и завершает процесс с
  кодом 101.
- `Args::get(0)` — имя программы, как оно набрано в оболочке, `get(1)` — первый аргумент.

В профиле рабочей области стоят `panic = "abort"` и `opt-level = "s"`. `panic` не меняйте:
раскрутки стека нет.

## 2. Соберите

```
cd apps
cargo +nightly build --release -p wordcount
```

Бинарник — `apps/target/x86_64-unknown-oos/release/wordcount`, статический ELF с адресом
загрузки 4 МиБ. Первая сборка заодно собирает `core` и `alloc` для цели, это минута-две.

## 3. Напишите манифест пакета

`apps/pkg/wordcount.toml`

```toml
name = "wordcount"
version = "0.1.0"
description = "Counts lines, words and bytes of a file"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/wordcount"
dest = "/usr/bin/wordcount"
```

- `src` отсчитывается от манифеста, то есть `../target/...` — это `apps/target/...`.
- `dest` — абсолютный путь без `..`. `/usr/bin` входит в `$PATH` оболочки (`/bin:/sbin:/usr/bin`).
- Имя пакета: буквы, цифры, `-`, `_` и `.`, до 63 символов.
- `version` — версия пакета, она не связана с версией крейта. Поднимайте её при каждом
  выпускаемом изменении.

Всё остальное в манифесте отвергается: `tmt` знает только `name`, `version`, `description`,
`arch` (`any`, `x86_64`, `aarch64`), `depends`, `kind` и `[[files]]` с `src` и `dest`.

## 4. Упакуйте

PowerShell 7, из корня репозитория:

```
.\apps\build.ps1 -Only wordcount
```

Скрипт при необходимости соберёт хост-утилиту `tmt`, соберёт крейт и упакует
`apps\pkg\wordcount.toml` в `apps\dist\wordcount-0.1.0.tmt`. Имя пакета cargo и имя манифеста
должны совпадать: `-Only` выбирает по ним обоим.

Git Bash, WSL или Linux:

```
bash apps/build.sh
```

В `build.sh` нет `-Only`: он собирает все крейты в `apps/` и упаковывает все манифесты. Чтобы
упаковать один, соберите его как на шаге 2 и вызовите упаковщик сами:

```
bash tools/tmt/build.sh                       # один раз, собирает tools/tmt/bin/tmt
cd apps && ../tools/tmt/bin/tmt pack pkg/wordcount.toml -o dist
```

Полезные проверки: `tmt list apps/dist/wordcount-0.1.0.tmt` показывает файлы, `tmt verify`
проверяет контрольную сумму.

`build.sh` и `build.ps1` вызывают `cargo +nightly`. На Windows без C++ Build Tools `nightly` —
это набор MSVC, и сборка останавливается в `compiler_builtins`. Сделайте так, чтобы `nightly`
означал GNU-набор: `rustup set default-host x86_64-pc-windows-gnu` (и поставьте GNU nightly),
либо соберите вручную GNU-набором, как на шаге 2, и запустите `tmt pack` сами. `./build.sh`
в корне на Windows уже предпочитает GNU nightly; скрипты в `apps/` пока нет.

## 5. Доставьте в ВМ

В ВМ нужна сеть (работают и пользовательская сеть QEMU, и NAT в VMware). Раздайте `apps/dist` со
своего ПК любым статическим файловым сервером. Например, на Python:

```
cd apps/dist
python -m http.server 8000
```

В ВМ скачайте пакет и установите его. В пользовательской сети QEMU ПК — это `10.0.2.2`. В NAT
VMware это адрес ПК в сети NAT (VMnet8). Брандмауэр должен пропускать порт.

```
# curl -o /tmp/wordcount.tmt http://10.0.2.2:8000/wordcount-0.1.0.tmt
# tomato install /tmp/wordcount.tmt
# echo "one two three" > /tmp/t.txt
# wordcount /tmp/t.txt
1 lines, 3 words, 14 bytes
# echo $?
0
```

(`curl -o ФАЙЛ URL` работает, хотя в справке `curl` ключа `-o` нет.)

`tomato install` считает локальным файлом цель, которая оканчивается на `.tmt` или содержит `/`.
Он проверяет контрольную сумму, записанную в файле. Подпись не проверяется: локальному файлу
доверяют, потому что вы сами его положили.

`tomato list` показывает установленные пакеты, `tomato files wordcount` — его файлы,
`tomato remove wordcount` удаляет пакет.

### Быстрый цикл: запустить ELF напрямую

Пока вы правите код, пакет можно не делать. Любой ELF-файл запускается по пути, бит исполнения
не нужен:

```
# curl -o /tmp/wc http://10.0.2.2:8000/wordcount
# /tmp/wc /tmp/t.txt
```

Для этого раздавайте каталог `apps/target/x86_64-unknown-oos/release/`. Файловая система в ОЗУ
пропадает при перезагрузке, а сохранённый слой пишется с задержкой, так что после перезапуска
скачайте файл заново.

### Свой репозиторий

Чтобы ставить по имени (`tomato install wordcount`), нужен репозиторий: `tmt repo add`,
`tmt repo index` и `tmt repo sign` (см. [Пакеты](../packages.md)). Индекс должен быть подписан
ключом, открытая половина которого вшита в систему (`userland/tomato/repo_key.pub`). Закрытого
ключа мейнтейнеров в репозитории нет. Для своих проверок создайте ключ командой `tmt keygen`,
положите открытый ключ в `userland/tomato/repo_key.pub` и соберите свой образ. Адрес по умолчанию —
`https://tmt.ospab.org/x86_64/`; строки `repo=<url>` в `/etc/tomato.conf` добавляют другие, а
простой `http://` допустим для локальных проверок. Чтобы пакет попал в официальный репозиторий,
обратитесь к мейнтейнерам (см. [Как внести изменения](../../../CONTRIBUTIONS_ru.md)).

## 6. Отладка

- **Последовательный порт.** Журнал ядра и всё, что программа печатает в stdout и stderr, идёт
  ещё и в последовательный порт (COM1). В QEMU: `-serial stdio` или `-serial file:serial.log`. В
  VMware добавьте последовательный порт с выводом в файл. Смотрите сначала сюда. См.
  [Тестирование](testing.md).
- **`println!`.** Самый простой отладчик. Вывод идёт на экран и в журнал. Для stderr вызовите
  `liboos::write(2, b"text\n")`; `eprintln!` в liboos нет.
- **Код завершения.** Оболочка кладёт его в `$?`:

  | Код | Значение |
  |---|---|
  | 0 | успех или то, что вернул ваш `main` |
  | 101 | паника Rust. Перед выходом печатается `panic: ...` |
  | 130 | Ctrl+C |
  | 139 | ядро убило процесс после сбоя. Оболочка пишет `terminated by the kernel (fault)`, а в журнале строка `[CRITICAL] Process N name at 0x.... Terminating.` с адресом сбоя. |
  | 126 | файл не является загружаемой программой; оболочка объясняет почему |
  | 127 | команда не найдена |

  Оболочка хранит только младшие 8 бит кода.
- **Сбои.** Плохой указатель в системном вызове даёт ошибку (-10) и не убивает программу. Плохое
  обращение в вашем собственном коде (нулевой указатель, переполнение стека, запись в память
  только для чтения) — это страничная ошибка, процесс завершается. Стек пользователя — 64 КиБ:
  не кладите на него большие массивы, берите `Vec` или `Box`.
- **Зависания.** Ctrl+C останавливает программу, которая заблокирована в вызове или в цикле
  ожидания оболочки. Программу, владеющую экраном или сырой клавиатурой, останавливают при её
  следующем `key_event`, `flush` или `sleep_ms`. Цикл, который не вызывает ничего из этого, нельзя
  прервать Ctrl+C, если программа владеет экраном, поэтому вызывайте что-то из этого в главном
  цикле.
- **`ps`** показывает процессы; `dmesg` — журнал ядра.

## Дальше

[Справочник liboos](liboos.md) описывает, что умеет программа. Если пишете игру, прочитайте
[Игры](games.md).
