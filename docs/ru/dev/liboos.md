# Справочник liboos

`liboos` (`user/liboos`) — среда выполнения программ ring 3: точка входа, обёртки системных
вызовов, куча, `print!` и обработчик паники. Это крейт `no_std` для цели `x86_64-unknown-oos`.
Программам доступны `core` и `alloc`, но не `std`.

Все примеры на этой странице скомпилированы с текущими исходниками. Номера системных вызовов и
регистры — в [Системные вызовы](../syscall-abi.md).

## Обзор

```rust
#![no_std]
#![no_main]
extern crate alloc;           // только если нужны Vec, String, Box, format!

liboos::entry!(main);

fn main(args: liboos::Args) -> i32 {
    liboos::println!("hello");
    0                          // код завершения
}
```

| Что | Где |
|---|---|
| `entry!`, `print!`, `println!` | корень крейта (макросы) |
| `Args` | `liboos::Args` |
| `write`, `open`, `read`, `close`, `seek` | корень крейта, файлы и стандартные потоки |
| `exit`, `getpid`, `yield_now`, `uptime_ticks` | корень крейта, процесс |
| `mmap`, `munmap` | корень крейта, память |
| `screen` | кадровый буфер, сырая клавиатура, `clock_ns`, `sleep_ms` |
| `audio` | вывод звука |
| `ipc` | дескрипторы, права, каналы, уведомления, процессы |
| `mem` | регионы общей памяти |
| `hw` | прерывания, порты ввода-вывода, DMA (только для драйверов) |
| `sys` | сырые `syscall0`..`syscall3`, номера вызовов (`sys::nr`), коды ошибок (`sys::err`) |

На что обратить внимание: `sleep_ms` и `clock_ns` лежат в `liboos::screen`, а не в корне крейта,
и нет ни `std::thread`, ни `std::time`, ни `std::env`.

## Обработка ошибок

В API два стиля.

- **Простые вызовы** (корень крейта, `screen`, `audio`) возвращают `i64` ядра. Отрицательное
  значение — ошибка, неотрицательное — результат (дескриптор, число байтов, смещение).
  `screen::acquire` и `mmap` возвращают `Result<_, i64>` с отрицательным кодом.
- **Вызовы объектов** (`ipc`, `mem`, `hw`) возвращают `liboos::ipc::Result<T>` с `ipc::Error`.

Коды ошибок (ядро отдаёт их со знаком минус):

| Код | Имя в ядре | `sys::err` | `ipc::Error` | Типичная причина |
|---|---|---|---|---|
| -1 | InvalidSyscall | `INVALID_SYSCALL` | `Other(-1)` | Нет такого вызова. Файловые вызовы возвращают -1 и при любой другой неудаче (нет файла, плохой дескриптор, таблица заполнена). |
| -2 | PermissionDenied | `PERMISSION_DENIED` | `PermissionDenied` | Нет нужной привилегии (capability) или у дескриптора нет нужного права. |
| -3 | InvalidArgument | `INVALID_ARGUMENT` | `InvalidArgument` | Неверный флаг, размер или формат. Также `seek` на отрицательное смещение. |
| -4 | NotFound | `NOT_FOUND` | `Other(-4)` | Определён в ядре; текущие вызовы возвращают его редко. |
| -5 | Busy | `BUSY` | `Busy` | Очередь канала полна; экран или сырая клавиатура уже заняты. |
| -6 | OutOfMemory | `OUT_OF_MEMORY` | `OutOfMemory` | Нет страниц, нет свободного диапазона адресов. |
| -7 | NotSupported | `NOT_SUPPORTED` | `NotSupported` | Нет кадрового буфера, нет звукового устройства, либо объект так не умеет (`phys` анонимной памяти). |
| -8 | IoError | нет | `Other(-8)` | Определён в ядре. |
| -9 | NoSuchProcess | нет | `Other(-9)` | Определён в ядре. |
| -10 | BadAddress | `BAD_ADDRESS` | `BadAddress` | Указатель вне процесса. |
| -11 | BadHandle | `BAD_HANDLE` | `BadHandle` | Закрытый, устаревший или не выданный дескриптор; неизвестный номер звукового потока. |
| -12 | WrongType | `WRONG_TYPE` | `WrongType` | Дескриптор объекта другого вида. |
| -13 | PeerClosed | `PEER_CLOSED` | `PeerClosed` | Другой стороны больше нет. |
| -14 | TableFull | `TABLE_FULL` | `TableFull` | Таблица дескрипторов (256) или звуковые потоки (4) заполнены. |
| -15 | Timeout | `TIMEOUT` | `Timeout` | Ожидание с таймаутом истекло. |

## Процесс

```rust
pub struct Args { /* argc, argv */ }
impl Args {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn get(&self, i: usize) -> Option<&'static str>;
    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_;
}

pub fn exit(code: i32) -> !;
pub fn getpid() -> u32;
pub fn yield_now();
pub fn uptime_ticks() -> u64;
```

- `args.get(0)` — имя, как оно набрано в оболочке. `args.len()` его учитывает.
- `get` возвращает `None` для отсутствующего аргумента и для аргумента, который не является
  корректным UTF-8. `iter` такие пропускает, поэтому позиции могут сдвинуться. Если позиции
  важны, используйте `get`.
- Возврат из `main` равносилен `exit(code)`. Оболочка показывает младшие 8 бит как `$?`. Паника
  печатает `panic: <сообщение>` в stdout и завершает процесс с кодом 101.
- Когда процесс заканчивается, как бы это ни произошло, ядро освобождает его память,
  дескрипторы файлов, дескрипторы объектов, экран, сырую клавиатуру и звуковые потоки.
- `yield_now` отдаёт остаток кванта времени. Это не сон: цикл вокруг него занимает процессор
  целиком. Для ожидания используйте `screen::sleep_ms`.
- `uptime_ticks` считает такты по 100 Гц с момента загрузки (разрешение 10 мс). Для более точного
  времени есть `screen::clock_ns`.

Недоступно: переменные окружения (ядро передаёт пустой `envp`), текущий каталог, запуск других
программ (нет `spawn`, `exec`, `fork`; `sys::nr::WAITPID` есть, но обёртки нет, да и ждать
нечего), потоки, сигналы. Программа, запущенная из оболочки, получает привилегии Serial, FsRead,
FsWrite и Framebuf. Привилегии Net у неё нет, поэтому сокетов нет.

## Вывод и ввод консоли

```rust
macro_rules! print   { ($($arg:tt)*) => ... }
macro_rules! println { () => ...; ($($arg:tt)*) => ... }
pub fn write(fd: u64, bytes: &[u8]) -> i64;
pub fn read(fd: u64, buf: &mut [u8]) -> i64;
```

- `print!` и `println!` пишут в fd 1. Макроса `eprint!` нет; для stderr вызовите
  `liboos::write(2, b"message\n")`.
- Вывод всегда идёт в последовательный порт, а когда консоль запущена — ещё и туда, куда сейчас
  направлен stdout оболочки: на экран, в конвейер или в перенаправление (`prog > file`).
  Стандартная ошибка идёт в stderr оболочки.
- Один вызов `write` передаёт не больше 64 КиБ и возвращает, сколько байтов принято. `print!` в
  цикле не повторяет. Если пишете большие блоки, повторяйте по возвращённому значению.
- `read(0, buf)` читает стандартный ввод. Если оболочка дала программе конвейер или
  перенаправление (`echo hi | prog`, `prog < file`), данные приходят оттуда, а 0 означает конец
  ввода. На консоли ядро применяет построчный режим: вызов спит, пока строка не закончится, и
  возвращает из неё не больше `buf.len()` байтов. Остаток ждёт следующего вызова, поэтому можно
  читать по одному байту. Клавиши редактирования: Enter завершает строку (перевод строки входит в
  данные), Backspace стирает символ, Ctrl+U — всю строку, Ctrl+D на пустой строке — конец ввода
  (0 байтов). Принимаются только печатные символы ASCII, строка — не более 1024 байтов. Набранные
  символы выводит само ядро. Ctrl+C заставляет оболочку убить программу (код 130).
  Подробности: [Внутреннее устройство ядра](../../en/kernel.md), «Console input» (на английском).
- Пока программа владеет сырой клавиатурой (`screen::kbd_raw(true)`), `read(0)` не используется.

```rust
fn read_line() -> Option<String> {
    let mut line = alloc::vec::Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = liboos::read(0, &mut b);
        if n <= 0 {
            return if line.is_empty() { None } else { Some(String::from_utf8_lossy(&line).into_owned()) };
        }
        if b[0] == b'\n' {
            return Some(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(b[0]);
    }
}
```

## Файлы

```rust
pub fn open(path: &str, flags: u64) -> i64;
pub fn read(fd: u64, buf: &mut [u8]) -> i64;
pub fn write(fd: u64, bytes: &[u8]) -> i64;
pub fn seek(fd: u64, offset: i64, whence: u64) -> i64;
pub fn close(fd: u64) -> i64;
```

`open` возвращает дескриптор от 3 и выше или отрицательное число. Вызовы работают с той же
виртуальной файловой системой, что и оболочка (`/`, `/tmp`, `/home`, сохранённый верхний слой,
смонтированные диски).

| `flags` | Значение |
|---|---|
| 0 | чтение |
| 1 | запись; создаёт файл, если его нет. Существующий файл не усекается: запись идёт с нулевого смещения и перезаписывает данные. |
| 2 | задумано как чтение и запись. **Сейчас дескриптор получается только для чтения** (см. ниже). |

Любое другое значение отвергается кодом -3. Для флага 2 нужны обе привилегии, FsRead и FsWrite.
Это ошибка ядра: `sys_open` в `vfs/mod.rs` проверяет биты 1 и 2 по отдельности, поэтому флаг 2
даёт дескриптор, из которого можно читать, но нельзя писать. Пока это не исправлено, пишите с
флагом 1, читайте с флагом 0, на разных дескрипторах.

- `whence` у `seek`: 0 — от начала, 1 — от текущего смещения, 2 — от конца. Возвращается новое
  смещение или -3. Именованных констант нет.
- Пути абсолютные. У процесса нет текущего каталога, и относительные пути не разбираются
  относительно каталога оболочки.
- Не больше 64 дескрипторов на процесс, три из них (0, 1, 2) заняты стандартными потоками, и 0, 1, 2
  закрыть нельзя. Таблица принадлежит процессу и освобождается при выходе.
- `read` и `write` передают не больше 64 КиБ за вызов. `read` возвращает 0 в конце файла. Оба
  возвращают -1 для плохого дескриптора или дескриптора не того режима.
- У каждого дескриптора своё смещение.
- Файлы, записанные в слой ОЗУ, попадают на диск с задержкой (около 10 секунд) или по `sync`.
  Программа этого форсировать не может.
- Прочитать каталог, узнать размер файла иначе чем через `seek(fd, 0, 2)`, создать каталог,
  переименовать или удалить из ring 3 нельзя. Этих вызовов пока нет.

```rust
fn write_all(fd: u64, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let n = liboos::write(fd, data);
        if n <= 0 { return false; }
        data = &data[n as usize..];
    }
    true
}

let fd = liboos::open("/tmp/demo.txt", 1);       // создать / перезаписать
write_all(fd as u64, b"first line\nsecond line\n");
liboos::close(fd as u64);

let fd = liboos::open("/tmp/demo.txt", 0) as u64;
let size = liboos::seek(fd, 0, 2);                // размер в байтах
liboos::seek(fd, 6, 0);                           // назад к смещению 6
let mut word = [0u8; 4];
liboos::read(fd, &mut word);
liboos::close(fd);
```

## Память

```rust
pub fn mmap(size: usize) -> Result<*mut u8, i64>;
pub fn munmap(ptr: *mut u8, size: usize) -> i64;
```

- `mmap` отображает `size` байтов свежей обнулённой памяти для чтения и записи без права
  исполнения, с округлением до целых страниц. За один вызов — не больше 64 МиБ. Адрес выбирает
  ядро.
- `munmap` принимает адрес, выровненный по странице, и размер, и освобождает эти страницы.
  Неотображённые страницы пропускаются.
- Объём памяти ограничен свободной ОЗУ машины.

### Куча

`alloc` работает как обычно (`Vec`, `String`, `Box`). Распределитель лежит в
`user/liboos/src/heap.rs`:

- До `main` отображается один регион размером 4 МиБ.
- Когда выделение не помещается, отображается новый регион: не меньше 8 МиБ, а если запрос
  больше — размером с запрос плюс небольшие накладные расходы. Регионы перебираются по порядку,
  берётся первый подходящий.
- Регионов не больше 16. Одно выделение — до 64 МиБ минус несколько КиБ (предел одного `mmap`).
  Сумма ограничена 16 регионами и ОЗУ.
- Регионы никогда не возвращаются системе, поэтому память, освобождённая через `drop`, остаётся в
  процессе (её используют следующие выделения) и возвращается только при выходе.
- Если отобразить память не удалось, выделение возвращает null и программа завершается обычной
  ошибкой выделения. Чтобы узнать заранее, резервируйте: `Vec::try_reserve_exact(n)` возвращает
  ошибку вместо аварийного завершения. `drift` использует это, чтобы выбрать размер экрана,
  который поместится.
- Распределитель защищён спин-блокировкой, которая страхует только от повторного входа. У
  программ один поток.

## Время

```rust
pub fn liboos::uptime_ticks() -> u64;     // такты по 100 Гц с загрузки
pub fn liboos::screen::clock_ns() -> u64;  // монотонные наносекунды с загрузки
pub fn liboos::screen::sleep_ms(ms: u64);
```

- `clock_ns` монотонен. Он берётся из TSC, если тот откалиброван, иначе из такта 100 Гц. Это не
  календарное время: программа ring 3 не может узнать дату.
- `sleep_ms` действительно спит: другие задачи и оболочка работают. Просыпается по такту 100 Гц,
  поэтому спит не меньше `ms` и опаздывает до 10 мс; запрос ограничен 60 000 мс на вызов. Для
  задержек меньше 12 мс крутитесь на `clock_ns` с `core::hint::spin_loop()`.
- `sleep_ms` ещё и проверяет Ctrl+C, если программа владеет экраном или сырой клавиатурой.

```rust
let t0 = liboos::screen::clock_ns();
liboos::screen::sleep_ms(250);
let elapsed_ms = (liboos::screen::clock_ns() - t0) / 1_000_000;
```

Цикл с постоянным темпом кадров — в разделе [Игры](games.md).

## Экран

```rust
pub struct Framebuffer {
    pub addr: *mut u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,       // байтов в строке
    pub bpp: u32,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}
impl Framebuffer {
    pub fn stride(&self) -> usize;                       // пикселей в строке (pitch / 4)
    pub unsafe fn pixels(&self) -> &'static mut [u32];   // stride() * height пикселей
    pub fn rgb(&self, r: u8, g: u8, b: u8) -> u32;       // упаковать 8-битные каналы
}

pub fn acquire() -> Result<Framebuffer, i64>;
pub fn release() -> i64;
pub fn flush() -> i64;
```

- `acquire` отображает загрузочный кадровый буфер в программу и останавливает отрисовку консоли
  ядра. Консоль хранит свой текст, поэтому `release` (или выход) перерисует её. Экраном может
  владеть только один процесс. Ошибки: -2 нет привилегии Framebuf, -5 экран занят другим, -7 нет
  кадрового буфера.
- Пиксели 32-битные. Положение каналов — в `red_shift`, `green_shift`, `blue_shift`; в обычной
  раскладке BGRA это 16, 8 и 0, то есть `0x00RRGGBB`. Не полагайтесь на это: используйте `rgb()`
  или преобразуйте цвет.
- `pitch` может быть больше `width * 4`. Индексируйте как `y * stride() + x`.
- `pixels()` объявлена `unsafe`, потому что выдаёт срез `&'static mut`. Берите его один раз и
  держите.
- Отображение — некэшируемая память устройства. Писать в неё нормально, а читать из неё медленно.
  Рисуйте в буфер в обычной памяти и копируйте на экран по строкам через `copy_from_slice`.
- Разрешение — то, которое выставлено при загрузке (его меняет команда `display`). Читайте
  `width` и `height`, не прибивайте размеры гвоздями.
- `flush` сообщает дисплею, что пиксели изменились. На VMware SVGA II он обязателен, в других
  местах безвреден. Вызывайте один раз за кадр. Если вызывающий не владеет экраном, вернёт -2.
- После `release` не трогайте пиксели: отображение остаётся до выхода, но консоль рисует там.

```rust
let fb = liboos::screen::acquire()?;            // Err(i64), если отказано
let px = unsafe { fb.pixels() };
px.fill(fb.rgb(0, 0, 0));
px[10 * fb.stride() + 20] = fb.rgb(255, 160, 0);
liboos::screen::flush();
// ...
liboos::screen::release();
```

## Сырая клавиатура

```rust
pub fn kbd_raw(on: bool) -> i64;
pub fn key_event() -> Option<KeyEvent>;

pub struct KeyEvent {
    pub code: u8,        // скан-код без бита отпускания, 1..=0x7F
    pub extended: bool,  // клавиша прислала префикс 0xE0
    pub pressed: bool,   // false = отпущена
}
```

- `kbd_raw(true)` переключает с построчного режима консоли на сырые события нажатия и
  отпускания. Возвращает 0, либо -5, если сырой режим уже занят другим процессом, либо -2 без
  привилегии. `kbd_raw(false)` возвращает обратно. Ядро возвращает обычный режим и само, когда
  программа заканчивается, и сбрасывает очередь, чтобы клавиши не попали в оболочку.
- `key_event()` возвращает следующее событие или `None`, если очередь пуста. Вызывайте в цикле
  каждый кадр, пока не придёт `None`. Очередь — кольцо в 256 байтов, общее с вводом оболочки,
  поэтому опрашивайте её хотя бы раз в несколько кадров. Без сырого режима вернёт `None`.
- Коды — скан-коды PC набора 1. У клавиш расширенного блока (стрелки, Home, End, Insert, Delete,
  PgUp, PgDn, правые Ctrl и Alt, Enter и `/` цифровой клавиатуры) `extended = true`. Те же коды
  без флага — это цифры цифровой клавиатуры и клавиши левой части.

  | Клавиша | Код | Клавиша | Код | Клавиша | Код |
  |---|---|---|---|---|---|
  | Esc | 01 | A..L | 1E..26 | F1..F10 | 3B..44 |
  | 1..9, 0 | 02..0B | Z..M | 2C..32 | F11, F12 | 57, 58 |
  | Backspace | 0E | Enter | 1C | Вверх (ext) | 48 |
  | Tab | 0F | Левый Ctrl | 1D | Влево (ext) | 4B |
  | Q..P | 10..19 | Левый Shift | 2A | Вправо (ext) | 4D |
  | Пробел | 39 | Правый Shift | 36 | Вниз (ext) | 50 |
  | Левый Alt | 38 | Caps Lock | 3A | Home, End (ext) | 47, 4F |
  | PgUp, PgDn (ext) | 49, 51 | Insert, Delete (ext) | 52, 53 | | |

- События описывают положение клавиш американской раскладки, а не символы. Обработки повтора
  нет: ведите собственную таблицу нажатых клавиш и не рассчитывайте на события автоповтора.
- Вставка текста (Ctrl+V) и ввод с последовательного порта в сыром режиме не приходят.
- **Ctrl+C продолжает работать.** Прерывание клавиатуры поднимает флаг до того, как клавиша
  попадёт в очередь. Программу, которая владеет экраном или сырой клавиатурой, ядро завершает при
  её следующем вызове `key_event`, `flush` или `sleep_ms` с кодом 130. Перехватить это нельзя,
  и использовать Ctrl+C как игровую клавишу нельзя. Экран, клавиатуру и звук ядро освободит
  само.
- Программу, которая не вызывает `key_event`, `flush` и `sleep_ms`, Ctrl+C остановить не может.
  Вызывайте хотя бы один из них в главном цикле.

```rust
liboos::screen::kbd_raw(true);
let mut quit = false;
while !quit {
    while let Some(ev) = liboos::screen::key_event() {
        if ev.pressed && ev.code == 0x01 { quit = true; }   // Esc
    }
    // ... обновить и нарисовать ...
    liboos::screen::sleep_ms(16);
}
liboos::screen::kbd_raw(false);
```

## Звук

```rust
impl Audio {
    pub fn open(rate: u32, channels: u32) -> Result<Audio, i64>;
    pub fn write(&self, samples: &[i16]) -> usize;
    pub fn queued(&self) -> usize;
    pub fn set_volume(&self, percent: u32) -> i64;
    pub fn rate(&self) -> u32;
    pub fn channels(&self) -> u32;
    pub fn drain(&self);
}
```

`Audio` закрывает свой поток при удалении. Ядро закрывает потоки и тогда, когда программа
заканчивается.

- Формат: знаковые 16-битные отсчёты, с чередованием каналов, little endian. `rate` — 48000,
  44100 или 22050; `channels` — 1 или 2. Ядро пересчитывает частоту (линейная интерполяция) в
  частоту устройства и превращает моно в стерео.
- Ошибки `open`: -7 нет звукового устройства (продолжайте молча), -14 заняты все 4 потока, общие
  для всех процессов, -3 неверный формат, -2 нет привилегии Framebuf.
- `write(samples)` копирует столько целых кадров, сколько помещается, и возвращает число принятых
  значений `i16`, кратное `channels`. Никогда не блокируется. 0 значит, что буфер полон;
  предложите остаток позже.
- У каждого потока буфер на 200 мс (`rate / 5` кадров). `queued()` возвращает число кадров,
  оставшихся в нём, на частоте самого потока.
- Устройство держит ещё до 60 мс после того, как кадр покинул поток, а ядро кормит его по такту
  100 Гц, так что задержка от `write` до звука — это очередь плюс около 60 мс.
- Держите `queued()` выше примерно 50 мс (`rate / 20`), иначе будут провалы. Хорошая цель — от 60
  до 100 мс: в каждом кадре, если `queued()` ниже, подмешайте недостающие кадры и запишите их.
  Отсчёты, которые не приняты, сохраните и отправьте первыми в следующий раз. Так делают `drift` и
  `beeb`.
- `set_volume(0..=100)` — усиление потока с квадратичной кривой. Общая громкость системы
  (`vol`, `mute` в оболочке) действует поверх.
- `drain()` спит, пока поток не опустеет и не доиграет хвост. Вызывайте перед выходом, иначе конец
  обрежется.
- Несколько потоков ядро суммирует с мягким ограничителем. С DOOM и командой `soundtest` оболочки
  они не смешиваются: если одна из них держит очередь устройства полной, потоки ring 3 ждут.

```rust
let Ok(a) = liboos::audio::Audio::open(48000, 1) else { return 0; };   // нет карты: молчим
let tone: Vec<i16> = (0..48000).map(|i| if (i / 50) % 2 == 0 { 6000 } else { -6000 }).collect();
let mut sent = 0;
while sent < tone.len() {
    let n = a.write(&tone[sent..]);
    sent += n;
    if n == 0 { liboos::screen::sleep_ms(20); }
}
a.drain();
```

## Дескрипторы, права и объекты (`ipc`)

Дескриптор — это число, которое указывает на объект ядра. Обладание дескриптором и есть
разрешение пользоваться объектом; права определяют, как именно. Модель описана в
[Архитектуре](../architecture.md) и [Системных вызовах](../syscall-abi.md).

```rust
pub struct Handle(/* u32 */);
impl Handle {
    pub const fn from_raw(raw: u32) -> Handle;
    pub const fn raw(&self) -> u32;
    pub fn into_raw(self) -> u32;                  // отказаться от владения, не закрывая
    pub const fn bootstrap(n: u32) -> Handle;      // дескриптор n, выданный до запуска программы
    pub fn duplicate(&self, rights: Rights) -> Result<Handle>;   // нужно DUP, права только сужаются
    pub fn info(&self) -> Result<(ObjectType, Rights)>;
    pub fn close(self) -> Result<()>;
}

pub struct Rights(pub u32);
// READ=1 WRITE=2 DUP=4 TRANSFER=8 ALL=15, память: MAP=16 EXEC=32 PHYS=64
impl Rights { pub fn contains(self, other: Rights) -> bool; }   // и `|`

pub enum ObjectType { Process, Thread, Channel, Notification, Reply, MemoryRegion,
                      MmioRegion, Interrupt, IoPortRange, Resource, Unknown(u8) }
```

`Handle` закрывается сам при удалении.

Каналы и сообщения:

```rust
pub const MSG_DATA_MAX: usize = 128;
pub const MSG_HANDLES_MAX: usize = 4;

// у структуры Message есть публичное поле `tag: u64`
impl Message {
    pub const fn new(tag: u64) -> Message;
    pub fn with_data(tag: u64, data: &[u8]) -> Message;        // данные обрезаются до 128 байтов
    pub fn set_data(&mut self, data: &[u8]);
    pub fn data(&self) -> &[u8];
    pub fn push_handle(&mut self, h: Handle) -> core::result::Result<(), Handle>;
    pub fn handle_count(&self) -> usize;
    pub fn take_handle(&mut self, i: usize) -> Option<Handle>;
}

impl Channel {
    pub fn create() -> Result<Channel>;
    pub fn duplicate(&self, rights: Rights) -> Result<Channel>;
    pub fn call(&self, msg: &mut Message) -> Result<Message>;  // отправить, спать до ответа
    pub fn send(&self, msg: &mut Message) -> Result<()>;       // в одну сторону, не блокируется; Busy, если полно
    pub fn recv(&self, timeout_ticks: u64) -> Result<(Message, Option<Reply>)>;
}
impl Reply { pub fn reply(self, msg: Message) -> Result<()>; }
```

- Дескрипторы в сообщении переносятся, а не копируются, и для этого нужно право TRANSFER.
- Серверы держат канал с READ (`recv`), клиенты — с WRITE (`call`, `send`).
- `Reply`, удалённый без ответа, заставляет `call` у вызывающего вернуть `PeerClosed`.
- Таймауты в тактах по 10 мс; 0 — ждать вечно. `recv`, `Notification::wait` или
  `Process::wait`, у которых истёк таймаут, возвращают `Timeout`. У `Channel::call` таймаута
  нет.

Уведомления и процессы:

```rust
impl Notification {
    pub fn create() -> Result<Notification>;
    pub fn duplicate(&self, rights: Rights) -> Result<Notification>;
    pub fn signal(&self, bits: u32) -> Result<()>;             // добавить биты по ИЛИ; нужно WRITE
    pub fn wait(&self, timeout_ticks: u64) -> Result<u32>;     // возвращает и сбрасывает биты; нужно READ
}
impl Process {
    pub fn current() -> Result<Process>;
    pub fn current_thread() -> Result<Process>;
    pub fn wait(&self, timeout_ticks: u64) -> Result<i64>;     // код завершения; нужно READ
    pub fn kill(&self) -> Result<()>;                          // нужно WRITE; себя нельзя
}
```

**Что можно использовать сегодня.** У программы, запущенной из оболочки, нет начальных
дескрипторов, она не может запустить другой процесс или передать ему дескриптор. Службы имён тоже
нет. Поэтому канал между двумя программами пока не создать. Эти API сегодня работают внутри
одного процесса (пример ниже), в самопроверках ядра при загрузке (`user/ipcsrv`,
`user/ipcclient`, `user/memtest`, `user/uartdrv`, запуск с `selftest=ipc` или `selftest=mem`) и
в том, что `seed` будет запускать на этапе 3 [дорожной карты](../../../ROADMAP.md).

## Общая память (`mem`)

```rust
pub const PAGE: usize = 4096;

pub struct Prot(pub u32);   // READ=1 WRITE=2 EXEC=4 RW=3, комбинируется через |; WRITE|EXEC отвергается

impl MemoryRegion {
    pub fn create(size: usize) -> Result<MemoryRegion>;                  // обнулён, <= 64 МиБ
    pub fn create_contig(dma: &hw::Resource, size: usize) -> Result<MemoryRegion>;   // <= 4 МиБ, DMA
    pub fn duplicate(&self, rights: Rights) -> Result<MemoryRegion>;
    pub fn size(&self) -> Result<usize>;
    pub fn phys(&self) -> Result<u64>;                                   // нужно PHYS
    pub fn map(&self, prot: Prot) -> Result<Mapping>;                    // отображает весь регион
}

impl Mapping {
    pub fn addr(&self) -> usize;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn writable(&self) -> bool;
    pub fn read<T: Copy>(&self, off: usize) -> T;                // volatile, с выравниванием, с проверкой границ
    pub fn write<T: Copy>(&self, off: usize, v: T);              // volatile; паникует, если только для чтения
    pub fn read_bytes(&self, off: usize, dst: &mut [u8]);
    pub fn write_bytes(&self, off: usize, src: &[u8]);
    pub fn as_ptr(&self) -> *mut u8;
    pub fn unmap(self) -> Result<()>;                            // удаление тоже отменяет отображение
}
pub fn unmap_raw(addr: usize) -> Result<()>;
pub fn map_raw(h: &Handle, prot: u32) -> core::result::Result<usize, Error>;   // для проверок прав в тестах
```

Страницы без права исполнения: ни один вызов не выдаёт EXEC. Отображение остаётся действительным
и после закрытия дескриптора; страницы освобождаются, когда пропали последний дескриптор и
последнее отображение.

```rust
use liboos::ipc::{Channel, Message, Notification, Rights};
use liboos::mem::{MemoryRegion, Prot};

let ch = Channel::create().unwrap();
let mut m = Message::with_data(7, b"ping");
ch.send(&mut m).unwrap();
let (got, reply) = ch.recv(0).unwrap();          // reply == None для одностороннего send

let n = Notification::create().unwrap();
n.signal(0b101).unwrap();
let bits = n.wait(0).unwrap();                   // 0b101

let region = MemoryRegion::create(8192).unwrap();
let map = region.map(Prot::RW).unwrap();
map.write::<u32>(0, 0xC0FFEE);
let ro = region.duplicate(Rights::READ | Rights::MAP).unwrap();   // то, что отправили бы другому
let ro_map = ro.map(Prot::READ).unwrap();
assert_eq!(ro_map.read::<u32>(0), 0xC0FFEE);
```

## Оборудование через дескрипторы (`hw`)

Для драйверов, которые запускает привилегированный родитель. Программа не может создать эти
объекты.

```rust
impl Interrupt {                       // линия IRQ (сегодня только линии 3, 6, 8 старого 8259)
    pub fn bind(&self, notif: &Notification, bits: u32) -> Result<()>;
    pub fn ack(&self) -> Result<()>;   // размаскировать после обслуживания
}
impl IoPorts {
    pub fn new(handle: Handle, base: u16, count: u16) -> IoPorts;
    pub fn enable(&self) -> Result<()>;
    pub fn disable(&self) -> Result<()>;
    pub fn inb(&self, off: u16) -> u8;
    pub fn outb(&self, off: u16, v: u8);
}
pub unsafe fn inb(port: u16) -> u8;
pub unsafe fn outb(port: u16, v: u8);
pub struct Resource(pub Handle);       // право на DMA для MemoryRegion::create_contig
```

Диапазон MMIO приходит дескриптором `MemoryRegion` вида `MmioRegion` и отображается без кэша тем
же вызовом `map`. `user/uartdrv` — готовый драйвер COM2 в ring 3 и лучший пример.

## Сырые системные вызовы (`sys`)

`sys::syscall0` .. `sys::syscall3` выполняют `SYSCALL` с числом аргументов до трёх, `sys::nr`
хранит номера, `sys::err` — коды ошибок. Форм на четыре и пять аргументов в liboos нет. Эталон —
таблица диспетчеризации ядра (`core/syscall/mod.rs`). У некоторых номеров из `sys::nr` обёртки нет,
например у `WAITPID`, а в ядре есть вызовы, которых в `sys::nr` нет (`spawn` 23, `sysinfo` 50,
`cap_delegate` 70). У программы, запущенной из оболочки, нет привилегий для большинства из них.
Как добавить вызов, см. [Работа с ядром](kernel-hacking.md).

## Чего пока нет

- Переменных окружения и текущего каталога.
- Чтения каталога, `stat`, `mkdir`, `unlink`, `rename` из ring 3.
- Сокетов и любого доступа к сети.
- `spawn`, `exec`, `wait` для других программ; потоков; сигналов.
- Календарного времени и часовых поясов.
- `std`, `eprintln!`, математических функций с плавающей точкой вроде `sin` и `sqrt` (арифметика
  над `f32` и `f64` работает, на SSE2; функции напишите сами или возьмите `no_std`-крейт вроде
  `libm`).
- Ввода мыши. У ring 3 есть интерфейс только к клавиатуре.
- Способа передать дескрипторы новому процессу из ring 3.
