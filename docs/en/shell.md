# Shell and tools

The console runs **plum**, a shell with Bourne-style syntax. Today the shell and the coreutils run
inside the kernel; programs installed from packages run as separate ring-3 processes.

## Syntax

| Feature | Example |
|---|---|
| Variables | `x=5; echo $x ${x:-default} ${#x}` |
| Arithmetic | `echo $((x * 2))`, `((x++))`, `let y=x+1` |
| Command substitution | `echo "today: $(date)"`, backticks |
| Pipes and lists | `ls / \| grep etc`, `a && b`, `a \|\| b`, `a; b` |
| Redirects | `> file`, `>> file`, `< file`, `2> file`, `2>&1`, `&> file` |
| Control flow | `if`, `for`, `while`, `until`, `case`, `break`, `continue` |
| Functions | `greet() { echo "hi $1"; }; greet ospab` |
| Globbing, quoting | `ls /etc/*.conf`, `'single'`, `"double $x"`, `~` |
| Scripts | `bash script.sh args`, `./script.sh`, `source file`, `bash -c '...'` |

Builtins: `cd`, `pwd`, `export`, `unset`, `set`, `env`, `alias`, `source`, `type`/`which`,
`test`/`[`/`[[`, `read`, `eval`, `shift`, `echo`, `exit`.

Not yet: background jobs (`&` runs in the foreground), here-documents, arrays. Pipeline stages run
one after another, not concurrently.

## Commands

- Files: `ls`, `cat`, `touch`, `mkdir`, `rmdir`, `rm`, `cp`, `mv`, `stat`, `du`, `df`, `tree`,
  `find`, `tee`, `write`, `sync`.
- Text: `grep` (regular expressions, `-E -F -i -v -n -c -l -o -w -x -r -q`), `head`, `tail`, `wc`,
  `sort`, `uniq`, `cut`, `tr`, `rev`, `nl`, `xxd`, `diff`, `awk` (subset), `seq`, `printf`,
  `xargs`, `yes`.
- System: `uname`, `date`, `uptime`, `hostname`, `free`, `lsmem`, `ps`, `top`, `kill`, `dmesg`,
  `lspci`, `shutdown`, `reboot`.
- Disks: `lsblk`, `fdisk -l`, `mkfs`, `mount`, `install`.
- Network: `ip`, `ifconfig`, `ping`, `nslookup`, `curl`, `traceroute`, `netstat`, `ntpdate`,
  `ostp`. See [Networking](networking.md).
- Apps: `grape` (text editor), `tomato` (packages), `doom`, `soundtest`, `vol`, `clip`.
- Display: `display` (see below).

`help` lists everything; `help <command>` explains one command.

## Programs from packages

A command that is not built in is looked up as a path or in `$PATH` (default `/usr/bin:/bin`).
ELF files start as ring-3 processes: their output goes to the screen or into a pipe, `$?` holds
the exit code, and Ctrl+C asks the kernel to stop them. See [Packages](packages.md).

## Keys

| Key | Action |
|---|---|
| Tab | complete commands and paths |
| Up / Down | history |
| Ctrl+A / Ctrl+E | start / end of the line |
| Ctrl+U / Ctrl+K / Ctrl+W | delete to start / to end / previous word |
| Ctrl+L | clear the screen |
| Ctrl+C | cancel the line, or interrupt the running command |
| Ctrl+V | paste the host clipboard (VMware) |

## Clipboard and serial console

In VMware, **Ctrl+V** pastes the Windows clipboard into the console (copy and paste must be
allowed in the VM's Guest Isolation settings). Line breaks in pasted text become spaces, so a
pasted link never runs a command on its own.

```
# clip                          print the host clipboard
# clip set hello                copy text to the host clipboard
# ostp import $(clip)           use the clipboard in a command
```

The console also accepts input from the first serial port. In VMware add a serial port using a
named pipe (for example `\\.\pipe\ospab`), connect PuTTY to it as a serial line, and paste with a
right click. In QEMU use `-serial stdio`.

## Display

```
# display                   current mode, console grid, driver, autofit state
# display list              modes that can be set (* marks the current one)
# display set fullhd        also: 1280x720, hd, 2k, 4k, "display set 1920 1080"
# display auto              follow the VMware window size (display auto off to stop)
# display scale 2           console font scale: 1, 2 or auto (2 from 2560 px wide)
```

`display set` switches at once, turns autofit off and saves the mode in `/etc/display.conf`;
it is applied at the next boot. Changing the mode works only on the VMware SVGA II adapter
(VMware, QEMU `-vga vmware`); elsewhere `display list` shows the boot mode only. The text on the
console is redrawn at the new size; lines longer than the new width are cut. See
[Hardware](hardware.md#display-modes-and-autofit).

## Time

The clock starts from the CMOS RTC at boot and is corrected by NTP (`ntpdate`, and once at
console start when the network is up). If the RTC keeps local time, as Windows and VMware do,
the offset is learned on the first NTP sync and saved to `/etc/rtc_offset`. The time zone for
display is read from `/etc/timezone`, for example `UTC+3`.

`date -e` prints seconds since the ospab epoch, 2012-08-09 00:00:00 UTC; `date --unix` prints
Unix time.
