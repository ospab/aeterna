// SPDX-License-Identifier: AGPL-3.0-only
//! Pointer images (pixel art: crisp at 1x, no assets needed).

use crate::canvas::Canvas;
use crate::color::Color;
use crate::event::CursorShape;
use crate::geom::Rect;

const ARROW: [&str; 19] = [
    "B           ",
    "BB          ",
    "BWB         ",
    "BWWB        ",
    "BWWWB       ",
    "BWWWWB      ",
    "BWWWWWB     ",
    "BWWWWWWB    ",
    "BWWWWWWWB   ",
    "BWWWWWWWWB  ",
    "BWWWWWWWWWB ",
    "BWWWWWWBBBBB",
    "BWWWBWWB    ",
    "BWWBBWWB    ",
    "BWB  BWWB   ",
    "BB   BWWB   ",
    "B     BWWB  ",
    "      BWWB  ",
    "       BB   ",
];

const IBEAM: [&str; 18] = [
    "BBB BBB",
    "BWWBWWB",
    "BBBWBBB",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "  BWB  ",
    "BBBWBBB",
    "BWWBWWB",
    "BBB BBB",
];


const RESIZE_H: [&str; 9] = [
    "    B         B    ",
    "   BB         BB   ",
    "  BWB         BWB  ",
    " BWWBBBBBBBBBBBWWB ",
    "BWWWWWWWWWWWWWWWWWB",
    " BWWBBBBBBBBBBBWWB ",
    "  BWB         BWB  ",
    "   BB         BB   ",
    "    B         B    ",
];

const RESIZE_V: [&str; 19] = [
    "    B    ",
    "   BWB   ",
    "  BWWWB  ",
    " BWWWWWB ",
    "BBBBWBBBB",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "   BWB   ",
    "BBBBWBBBB",
    " BWWWWWB ",
    "  BWWWB  ",
    "   BWB   ",
    "    B    ",
];

const RESIZE_NWSE: [&str; 13] = [
    "BBBBBBB      ",
    "BWWWWB       ",
    "BWWWB        ",
    "BWWWWB       ",
    "BWBBWWB      ",
    "BB  BWWB     ",
    "     BWB     ",
    "     BWWB  BB",
    "      BWWBBWB",
    "       BWWWWB",
    "        BWWWB",
    "       BWWWWB",
    "      BBBBBBB",
];

const RESIZE_NESW: [&str; 13] = [
    "      BBBBBBB",
    "       BWWWWB",
    "        BWWWB",
    "       BWWWWB",
    "      BWWBBWB",
    "     BWWB  BB",
    "     BWB     ",
    "BB  BWWB     ",
    "BWBBWWB      ",
    "BWWWWB       ",
    "BWWWB        ",
    "BWWWWB       ",
    "BBBBBBB      ",
];

fn art(shape: CursorShape) -> (&'static [&'static str], i32, i32) {
    match shape {
        CursorShape::Text => (&IBEAM, 3, 9),
        CursorShape::ResizeH => (&RESIZE_H, 9, 4),
        CursorShape::ResizeV => (&RESIZE_V, 4, 9),
        CursorShape::ResizeNwse => (&RESIZE_NWSE, 6, 6),
        CursorShape::ResizeNesw => (&RESIZE_NESW, 6, 6),
        _ => (&ARROW, 0, 0),
    }
}

/// Screen rect covered by the cursor (including its shadow) at (x, y).
pub fn bounds(shape: CursorShape, x: i32, y: i32) -> Rect {
    let (a, hx, hy) = art(shape);
    Rect::new(x - hx, y - hy, a[0].len() as i32 + 2, a.len() as i32 + 2)
}

/// Draw the pointer with its hotspot at (x, y).
pub fn draw(c: &mut Canvas, shape: CursorShape, x: i32, y: i32) {
    let (a, hx, hy) = art(shape);
    let (ox, oy) = (x - hx, y - hy);
    let outline = Color::hex(0x0B0C0E);
    let fill = Color::hex(0xF4F5F7);
    // Soft one-pixel drop shadow.
    for (row, line) in a.iter().enumerate() {
        for (col, ch) in line.bytes().enumerate() {
            if ch != b' ' {
                c.fill_rect(Rect::new(ox + col as i32 + 1, oy + row as i32 + 1, 1, 1), Color::black_a(60));
            }
        }
    }
    for (row, line) in a.iter().enumerate() {
        for (col, ch) in line.bytes().enumerate() {
            let color = match ch { b'B' => outline, b'W' => fill, _ => continue };
            c.fill_rect(Rect::new(ox + col as i32, oy + row as i32, 1, 1), color);
        }
    }
}
