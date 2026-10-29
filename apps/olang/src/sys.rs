// New in the OS port (no counterpart in the olang project): files, stdin and the clock
// through the liboos syscalls.
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Read a whole file from the VFS.
pub fn read_file(path: &str) -> Result<String, String> {
    let fd = liboos::open(path, 0);
    if fd < 0 {
        return Err(format!("cannot open (error {})", fd));
    }
    let fd = fd as u64;
    let mut data: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = liboos::read(fd, &mut buf);
        if n < 0 {
            liboos::close(fd);
            return Err(format!("read failed (error {})", n));
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    liboos::close(fd);
    String::from_utf8(data).map_err(|_| "file is not valid UTF-8".to_string())
}

/// Write a whole file (write mode: the VFS decides about create/truncate).
pub fn write_file(path: &str, content: &str) -> Result<(), String> {
    let fd = liboos::open(path, 1);
    if fd < 0 {
        return Err(format!("cannot open for writing (error {})", fd));
    }
    let fd = fd as u64;
    let mut rest = content.as_bytes();
    while !rest.is_empty() {
        let n = liboos::write(fd, &rest[..rest.len().min(4096)]);
        if n <= 0 {
            liboos::close(fd);
            return Err(format!("write failed (error {})", n));
        }
        rest = &rest[n as usize..];
    }
    liboos::close(fd);
    Ok(())
}

/// Read one line from stdin without the newline. `None` at end of input.
pub fn read_line() -> Option<String> {
    let mut line: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = liboos::read(0, &mut b);
        if n <= 0 {
            if line.is_empty() {
                return None;
            }
            break;
        }
        match b[0] {
            b'\n' => break,
            b'\r' => {}
            0x08 | 0x7f => {
                // drop the previous UTF-8 character
                while let Some(c) = line.pop() {
                    if c & 0xC0 != 0x80 {
                        break;
                    }
                }
            }
            c => line.push(c),
        }
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}

/// Milliseconds since boot (the kernel timer runs at 100 Hz).
pub fn uptime_ms() -> i64 {
    (liboos::uptime_ticks() as i64) * 10
}
