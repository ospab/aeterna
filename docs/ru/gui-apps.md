# Как написать графическое приложение

Приложение зависит от одного крейта, `oos-ui`, и использует его модуль `oos_ui::app`. Оконного
менеджера оно не касается. Тот же код сегодня работает внутри рабочего стола в ядре, а позже — как
процесс в ring 3 (см. [gui.md](gui.md)).

Шаблон — `apps/hello-gui`. Скопируйте его.

## Hello world

`apps/<name>/Cargo.toml`:

```toml
[package]
name = "myapp"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "myapp"
path = "src/lib.rs"

[[bin]]
name = "myapp"
path = "src/main.rs"
required-features = ["ring3"]

[features]
default = ["ring3"]
ring3 = ["dep:liboos"]        # рабочий стол в ядре использует только библиотеку

[dependencies]
oos-ui = { path = "../../gui" }
liboos = { path = "../../user/liboos", optional = true }
```

`src/lib.rs`:

```rust
#![no_std]
extern crate alloc;
use oos_ui::app::prelude::*;

#[derive(Default)]
pub struct Hello { label: NodeId, button: NodeId, clicks: u32 }

impl Application for Hello {
    fn info(&self) -> AppInfo { AppInfo::new("org.example.hello", "Hello", Icon::Info) }

    fn start(&mut self, cx: &mut Ctx, _arg: Option<&str>) {
        let mut ui = Ui::new(Axis::Column, cx.theme().color.bg1);
        let root = ui.root();
        ui.padding(root, Insets::new(24, 20, 24, 20));
        ui.gap(root, 12);
        self.label = ui.label(root, "Hello, ospab.os", TextRole::Headline);
        self.button = ui.button(root, "Click me", ButtonKind::Primary);
        cx.open_window(WindowSpec::new("Hello", 360, 200), ui);
    }

    fn event(&mut self, cx: &mut Ctx, win: WinId, ev: &AppEvent) {
        match ev {
            AppEvent::Action(Action::Clicked(n)) if *n == self.button => {
                self.clicks += 1;
                let text = alloc::format!("Clicked {} times", self.clicks);
                if let Some(ui) = cx.ui(win) { ui.set_text(self.label, &text); }
            }
            AppEvent::CloseRequested => cx.close_window(win),
            _ => {}
        }
    }
}
```

`src/main.rs` (программа ring 3): скопируйте `apps/hello-gui/src/main.rs` и поменяйте тип
приложения.

## Жизненный цикл приложения

| Вызов | Когда |
|---|---|
| `info()` | Один раз, раньше всего. Возвращает `AppInfo { id, name, icon, version }` |
| `start(cx, arg)` | Один раз. Откройте первое окно. `arg` — аргумент запуска (например, путь) |
| `event(cx, win, ev)` | На каждое `AppEvent` любого окна приложения. Для таймеров `win` равен 0 |
| `tick(cx)` | Раз за кадр, до отрисовки. Держите его дешёвым; для периодической работы есть таймеры |

Приложение завершается, когда закрыто его последнее окно или когда оно вызывает `cx.quit()`.
На `AppEvent::CloseRequested` приложение должно закрыть окно. Если оно этого не делает, кнопка
закрытия ничего не делает: так приложение может сначала спросить «сохранить изменения?».

`AppInfo::id` — уникальная строка в обратной DNS-записи. Её используют меню приложений, док и
`Platform::launch`.

## Окна

```rust
let win = cx.open_window(
    WindowSpec::new("Title", 640, 400)   // размер клиента вместе с заголовком
        .min_size(320, 200)              // минимум по умолчанию 240 x 160
        .icon(Icon::Folder),             // по умолчанию — иконка приложения
    ui);
```

| Метод | Назначение |
|---|---|
| `WindowSpec::fixed()` | Размер не меняется (минимум = размер) |
| `cx.set_title(win, "...")` | Сменить заголовок |
| `cx.window_size(win)` | Текущий размер |
| `cx.activate(win)` | Поднять и дать фокус |
| `cx.close_window(win)` | Закрыть |
| `cx.ui(win)` | Дерево виджетов окна; `None`, если окно закрыто |

У окна заголовок высотой 38 пикселей, его рисует библиотека; остальное занимает ваше дерево
виджетов. Когда пользователь меняет размер окна, приходит `AppEvent::Resized(w, h)`; раскладка
пересчитывается автоматически.

## Виджеты и раскладка

Дерево строится через `Ui`. Каждый метод-конструктор принимает `NodeId` родителя и возвращает
`NodeId` нового узла. Нужные потом идентификаторы храните в своей структуре.

| Конструктор | Виджет |
|---|---|
| `row`, `column`, `stack`, `grid(cols)`, `container(parent, axis, BoxStyle)` | Контейнеры. `stack` накладывает детей друг на друга; у `grid` колонки одинаковой ширины |
| `label`, `label_colored`, `paragraph` | Текст. `paragraph` переносит строки |
| `button(label, ButtonKind)`, `icon_button(icon)` | Кнопки. Виды: `Primary`, `Secondary`, `Danger`, `Ghost` |
| `text_field(text, placeholder)` | Однострочное поле с выделением и буфером обмена |
| `checkbox`, `toggle`, `slider(0..=1000)` | Переключатели и значения |
| `list(columns, header, items, row_h)` | Таблица с выделением, прокруткой и необязательным заголовком |
| `tabs(&labels, selected)` | Полоса вкладок |
| `editor(text)` | Многострочный моноширинный редактор с номерами строк |
| `terminal(lines)` | Цветной моноширинный экран с прокруткой назад |
| `progress(value)`, `icon`, `separator`, `spacer` | Разное |

Свойства раскладки (для любого узла):

| Метод | Смысл |
|---|---|
| `width(id, Length)`, `height`, `size(id, w, h)` | `Length::Hug` (по содержимому), `Px(n)`, `Fill(weight)` (доля свободного места) |
| `padding(id, Insets)` | Внутренний отступ. `Insets::new(l, t, r, b)`, `Insets::xy(x, y)` |
| `gap(id, px)` | Промежуток между детьми |
| `align(id, main, cross)` | `Align::Start`, `Center`, `End`, `Stretch`, `SpaceBetween` (только по главной оси) |

Пример: панель инструментов с полем, которое занимает всю свободную ширину.

```rust
let bar = ui.row(root);
ui.padding(bar, Insets::xy(10, 8));
ui.gap(bar, 8);
ui.align(bar, Align::Start, Align::Center);
let field = ui.text_field(bar, "", "Search");
ui.width(field, Length::Fill(1));
ui.button(bar, "Go", ButtonKind::Primary);
```

Читать и менять состояние: `ui.text(id)`, `set_text`, `checked`, `set_checked`, `selected`,
`set_selected`, `list_items_mut`, `slider_value`, `set_slider`, `set_enabled`, `set_visible`,
`set_focus`, `editor_text`, `terminal_mut`. Дерево перерисовывает только то, что изменилось.

## События

Варианты `AppEvent`:

| Вариант | Смысл |
|---|---|
| `Action(Action)` | Виджет что-то сделал (ниже) |
| `Key(Event)` | Нажатие клавиши, которое не обработал ни один виджет: сочетания клавиш, терминалы |
| `CloseRequested` | Кнопка закрытия, Alt+F4 или док |
| `Resized(w, h)` | Окно сменило размер |
| `Focus(bool)` | Окно получило или потеряло фокус клавиатуры |
| `Timer(id)` | Сработал таймер |
| `Dialog(id, DialogResult)` | Закрылся диалог, открытый этим приложением |

Варианты `Action`: `Clicked(node)`, `Toggled(node, on)`, `TextChanged(node)`, `Submitted(node)`
(Enter в поле ввода), `Selected(node, row_or_tab)`, `Activated(node, row)` (двойной щелчок или
Enter на строке списка), `MenuChosen(owner, index)`, `ValueChanged(node, 0..=1000)`.

Сравнивайте с сохранённым идентификатором узла: `Action::Clicked(n) if *n == self.button`.

Сочетания клавиш: обрабатывайте `AppEvent::Key(Event::KeyDown { key, mods, .. })`:

```rust
AppEvent::Key(Event::KeyDown { key: Key::Char('s'), mods, .. }) if mods.ctrl => self.save(cx),
```

Ctrl+буква приходит строчной буквой с `mods.ctrl`.

## Таймеры, диалоги, меню, буфер обмена

```rust
let t = cx.set_timer(1000, true);   // каждую секунду; AppEvent::Timer(t)
cx.cancel_timer(t);
```

Диалоги — модальные на вид окна, принадлежащие родительскому окну. Каждый вызов возвращает
`DialogId`; результат приходит как `AppEvent::Dialog(id, result)` с `DialogResult::Ok`, `Cancel`
или `Path(p)`.

| Вызов | Результат |
|---|---|
| `cx.alert(win, title, message)` | `Ok` |
| `cx.confirm(win, title, message, "Delete", destructive)` | `Ok` или `Cancel` |
| `cx.open_file(win, start_dir)` | `Path(..)` или `Cancel`; нужен `Platform::list_dir` |

Всплывающее меню: `cx.open_menu(win, owner_node, anchor_rect, vec![MenuItem::new("Copy").shortcut("Ctrl+C")])`;
выбор приходит как `Action::MenuChosen(owner, index)`.

Буфер обмена: `oos_ui::app::clipboard_get()` и `clipboard_set(&str)` или `cx.clipboard()` /
`cx.set_clipboard()`. Поля ввода и редактор используют его для Ctrl+C, Ctrl+X и Ctrl+V.

## Тема

Не задавайте цвета вручную. `cx.theme()` возвращает токены дизайна:

| Группа | Примеры |
|---|---|
| `theme.color` | `bg0`, `bg1`, `surface`, `elevated`, `field`, `hairline`, `text`, `text_secondary`, `text_disabled`, `accent`, `accent_text`, `danger`, `success`, `warning` |
| `theme.radius` | `sm`, `md`, `lg`, `window` |
| `theme.spacing` | `xxs` ... `xxl` |
| `theme.text` | шкала шрифтов: `caption`, `body`, `body_strong`, `title`, `headline`, `mono` |

Стиль: почти чёрные поверхности, разделённые небольшими шагами яркости и линиями в 1 пиксель,
один синий акцент, без градиентов. Для текста используйте `TextRole`, а не выбирайте шрифты сами.

## Системные службы: `Platform`

`cx.platform()` даёт доступ к файлам и запуску приложений. Реализует его среда (сейчас VFS ядра,
в ring 3 — системные вызовы liboos). У каждого метода безопасное значение по умолчанию
(`None` / `false`).

| Метод | Назначение |
|---|---|
| `list_dir(path) -> Option<Vec<DirItem>>` | Содержимое каталога |
| `read_file(path)`, `write_file(path, data)` | Чтение и запись файла целиком |
| `mkdir`, `remove`, `rename` | Изменения в файловой системе |
| `launch(app_id, arg)` | Запустить другое приложение по id (например, `"org.ospab.editor"`) |
| `uptime_ms()` | Миллисекунды с загрузки |

## Запуск

На рабочем столе в ядре (встроенные приложения): добавьте крейт приложения зависимостью в корневой
`Cargo.toml` (`default-features = false`), добавьте вариант в `AppKind` в
`src/userspace/axon/desktop/mod.rs` и пересоберите. Hello GUI уже есть в меню приложений.

Как пакет для ring 3:

```
bash apps/build.sh                 # собирает apps/target/x86_64-unknown-oos/release/myapp
```

Добавьте `apps/pkg/myapp.toml`:

```toml
name = "myapp"
version = "0.1.0"
description = "What it does"
arch = "x86_64"
depends = []

[[files]]
src = "../target/x86_64-unknown-oos/release/myapp"
dest = "/usr/bin/myapp"
```

`apps/build.sh` упакует его в `apps/dist/myapp.tmt`; установка — `tomato install dist/myapp.tmt`.
Ограничение сейчас: графическая программа в ring 3 работает с сессией внутри своего процесса
(рисует в память), потому что у композитора ещё нет IPC-интерфейса. Код приложения тот же,
меняется только среда. См. [gui.md](gui.md#перенос-композитора-в-ring-3).

## Чек-лист

* `#![no_std]`, `extern crate alloc;`, никаких типов ядра.
* Каждое окно обрабатывает `CloseRequested`.
* Храните `NodeId`; не пересобирайте дерево, чтобы сменить текст.
* Используйте токены темы и `TextRole`.
* `tick` — дешёвый; для периодической работы — таймеры.
* Файлы — через `Platform`; обрабатывайте `None` и `false`.
