/*
 * ospab.os Network Stack
 *
 * Bare-metal IPv4 networking.  No VM / SLIRP / QEMU assumptions.
 *
 * Boot flow:
 *   1. Probe PCI for supported NIC (RTL8139, e1000, RTL8169)
 *   2. Read MAC from hardware registers
 *   3. DHCP handshake → obtain IP / subnet / gateway / DNS
 *   4. ARP-resolve gateway MAC
 *   5. Stack is UP — ARP, IPv4, ICMP, UDP, TCP, DNS all functional
 */

pub mod virtio_net;
pub mod rtl8139;
pub mod e1000;
pub mod rtl8169;
pub mod pcnet;
pub mod vmxnet3;
pub mod ethernet;
pub mod diag;
pub mod arp;
pub mod ipv4;
pub mod icmp;
pub mod udp;
pub mod tcp;
pub mod dhcp;
pub mod dns;
pub mod sntp;
pub mod tls;
pub mod resolver;
pub mod ostp;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ─── Universal NIC trait (owned by this module) ───
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState { Down, Up }

pub trait NetDriver {
    fn name(&self) -> &'static str;
    fn probe_and_init(&self) -> bool;
    fn mac_address(&self) -> [u8; 6];
    fn send_packet(&self, buf: &[u8], len: usize);
    fn receive_packet(&self) -> Option<(&'static [u8], usize)>;
    fn handle_irq(&self);
    fn link_state(&self) -> LinkState;
}

// ─── Network configuration (all zeros until DHCP assigns them) ───
pub static mut OUR_IP: [u8; 4]       = [0; 4];
pub static mut GATEWAY_IP: [u8; 4]   = [0; 4];
pub static mut SUBNET_MASK: [u8; 4]  = [255, 255, 255, 0];
pub static mut DNS_IP: [u8; 4]       = [0; 4];
pub static mut OUR_MAC: [u8; 6]      = [0; 6];
pub static mut GATEWAY_MAC: [u8; 6]  = [0xFF; 6]; // broadcast until ARP resolve

static NET_UP: AtomicBool = AtomicBool::new(false);
pub const NIC_VIRTIO: u8 = 0;
pub const NIC_RTL8139: u8 = 1;
pub const NIC_E1000: u8 = 2;
pub const NIC_RTL8169: u8 = 3;
pub const NIC_PCNET: u8 = 4;
pub const NIC_VMXNET3: u8 = 5;
pub const NIC_NONE: u8 = 0xFF;
static mut ACTIVE_NIC: u8 = NIC_NONE;
// Packet counters
static RX_PKTS: AtomicU64 = AtomicU64::new(0);
static TX_PKTS: AtomicU64 = AtomicU64::new(0);
// Byte counters
static RX_BYTES: AtomicU64 = AtomicU64::new(0);
static TX_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn is_up() -> bool { NET_UP.load(Ordering::Relaxed) }
pub fn rx_packets() -> u64 { RX_PKTS.load(Ordering::Relaxed) }
pub fn tx_packets() -> u64 { TX_PKTS.load(Ordering::Relaxed) }
pub fn rx_bytes() -> u64 { RX_BYTES.load(Ordering::Relaxed) }
pub fn tx_bytes() -> u64 { TX_BYTES.load(Ordering::Relaxed) }

/// Check actual hardware link state from the active NIC.
pub fn link_up() -> bool {
    if !is_up() { return false; }
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => virtio_net::link_up(),
        NIC_RTL8139 => rtl8139::link_up(),
        NIC_E1000   => e1000::link_up(),
        NIC_RTL8169 => rtl8169::link_up(),
        NIC_PCNET   => pcnet::link_up(),
        NIC_VMXNET3 => vmxnet3::link_up(),
        _ => false,
    }
}

/// Renew DHCP lease and re-apply network settings at runtime.
///
/// Useful after changing hostname so DHCP option 12 is advertised immediately.
pub fn dhcp_renew() -> bool {
    if !is_up() {
        return false;
    }

    crate::arch::x86_64::serial::write_str("[NET] DHCP renew requested\r\n");
    let mac = unsafe { OUR_MAC };
    match dhcp::discover(mac) {
        Some(lease) => {
            unsafe {
                OUR_IP      = lease.your_ip;
                SUBNET_MASK = lease.subnet;
                GATEWAY_IP  = lease.gateway;
                DNS_IP      = lease.dns;
                GATEWAY_MAC = [0xFF; 6];
            }

            let gw = unsafe { GATEWAY_IP };
            if gw != [0, 0, 0, 0] {
                arp::send_request(gw);
                let start = crate::arch::x86_64::idt::timer_ticks();
                loop {
                    poll_rx();
                    let done = unsafe { GATEWAY_MAC[0] != 0xFF || GATEWAY_MAC[1] != 0xFF };
                    if done { break; }
                    if crate::arch::x86_64::idt::timer_ticks().saturating_sub(start) > 200 {
                        break;
                    }
                    unsafe { core::arch::asm!("hlt"); }
                }
            }
            true
        }
        None => false,
    }
}

/// Initialize the network stack. Call after PCI scan.
pub fn init() -> bool {
    crate::arch::x86_64::serial::write_str("[NET] Initializing network stack...\r\n");

    // Step 1: Find and init a NIC. ACTIVE_NIC numbering (see NIC_* consts)
    // is used by poll_rx / send_raw / link_up / diag / nic_name.
    let s = crate::arch::x86_64::serial::write_str;
    let nic: u8 = if rtl8139::probe_and_init() {
        NIC_RTL8139
    } else if e1000::probe_and_init() {
        NIC_E1000
    } else if rtl8169::probe_and_init() {
        NIC_RTL8169
    } else if virtio_net::probe_and_init() {
        NIC_VIRTIO
    } else if pcnet::probe_and_init() {
        NIC_PCNET
    } else if vmxnet3::probe_and_init() {
        NIC_VMXNET3
    } else {
        s("[NET] No supported NIC found (supported: RTL8139, Intel e1000 family, RTL8169/8111, virtio-net, AMD PCnet = VMware vlance, VMware vmxnet3)\r\n");
        return false;
    };

    // Store which NIC is active so poll_rx / send_raw know which to call
    unsafe { ACTIVE_NIC = nic; }
    s("[NET] Using NIC driver: ");
    s(nic_model());
    s("\r\n");

    // Copy MAC from whichever NIC was found
    let mac = match nic {
        NIC_VIRTIO  => virtio_net::mac_address(),
        NIC_RTL8139 => rtl8139::mac_address(),
        NIC_E1000   => e1000::mac_address(),
        NIC_RTL8169 => rtl8169::mac_address(),
        NIC_PCNET   => pcnet::mac_address(),
        _           => vmxnet3::mac_address(),
    };
    unsafe {
        OUR_MAC = mac;
    }

    crate::arch::x86_64::serial::write_str("[NET] NIC initialized, MAC: ");
    for i in 0..6 {
        serial_hex_byte(mac[i]);
        if i < 5 { crate::arch::x86_64::serial::write_byte(b':'); }
    }
    crate::arch::x86_64::serial::write_str("\r\n");

    // Step 2: DHCP — obtain IP configuration from the network
    crate::arch::x86_64::serial::write_str("[NET] Starting DHCP...\r\n");
    let mac = unsafe { OUR_MAC };
    match dhcp::discover(mac) {
        Some(lease) => {
            unsafe {
                OUR_IP      = lease.your_ip;
                SUBNET_MASK = lease.subnet;
                GATEWAY_IP  = lease.gateway;
                DNS_IP      = lease.dns;
            }
            crate::arch::x86_64::serial::write_str("[NET] DHCP configured: ");
            serial_ip(lease.your_ip);
            crate::arch::x86_64::serial::write_str("\r\n");
        }
        None => {
            crate::arch::x86_64::serial::write_str("[NET] DHCP failed — using link-local 169.254.1.1\r\n");
            unsafe {
                OUR_IP      = [169, 254, 1, 1];
                SUBNET_MASK = [255, 255, 0, 0];
                GATEWAY_IP  = [0; 4];
                DNS_IP      = [0; 4];
            }
        }
    }

    // Step 3: ARP resolve gateway (if we have one)
    let gw = unsafe { GATEWAY_IP };
    if gw != [0, 0, 0, 0] {
        crate::arch::x86_64::serial::write_str("[NET] ARP resolving gateway...\r\n");
        arp::send_request(gw);

        let start = crate::arch::x86_64::idt::timer_ticks();
        let mut arp_sends = 1u32;
        loop {
            poll_rx();
            if unsafe { GATEWAY_MAC[0] != 0xFF || GATEWAY_MAC[1] != 0xFF } {
                break;
            }
            let elapsed = crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start);
            if elapsed >= 200 { break; }
            if elapsed >= arp_sends as u64 * 50 {
                arp::send_request(gw);
                arp_sends += 1;
            }
            unsafe { core::arch::asm!("hlt"); }
        }

        let gw_resolved = unsafe { GATEWAY_MAC[0] != 0xFF || GATEWAY_MAC[1] != 0xFF };
        if gw_resolved {
            crate::arch::x86_64::serial::write_str("[NET] Gateway MAC resolved\r\n");
            let gw_mac = unsafe { GATEWAY_MAC };
            arp::cache_update(gw, gw_mac);
        } else {
            crate::arch::x86_64::serial::write_str("[NET] Gateway ARP timeout\r\n");
        }
    }

    NET_UP.store(true, Ordering::Relaxed);
    crate::arch::x86_64::serial::write_str("[NET] Network stack ready\r\n");
    true
}

/// Nesting depth of non-ISR network code (poll_rx / send_raw). While it is
/// non-zero the NIC IRQ handler must NOT touch the RX/TX rings or the shared
/// packet buffers: the interrupted code may be in the middle of using them.
static NET_BUSY: AtomicU32 = AtomicU32::new(0);

/// Per-packet serial tracing in the NIC drivers. Off by default: at 115200 baud
/// each trace line costs several milliseconds, which throttles TCP badly.
static NET_TRACE: AtomicBool = AtomicBool::new(false);

pub fn trace() -> bool { NET_TRACE.load(Ordering::Relaxed) }
pub fn set_trace(on: bool) { NET_TRACE.store(on, Ordering::Relaxed); }

/// RAII marker for non-ISR code that mutates shared network state (TCP
/// connection table etc.). While alive, the NIC IRQ handler does not drain RX.
pub struct BusyGuard;
impl BusyGuard {
    pub fn new() -> Self { NET_BUSY.fetch_add(1, Ordering::Acquire); BusyGuard }
}
impl Drop for BusyGuard {
    fn drop(&mut self) { NET_BUSY.fetch_sub(1, Ordering::Release); }
}

/// Poll for received packets — dispatches to the active NIC
pub fn poll_rx() {
    NET_BUSY.fetch_add(1, Ordering::Acquire);
    poll_rx_inner();
    NET_BUSY.fetch_sub(1, Ordering::Release);
}

fn poll_rx_inner() {
    fn drain(recv: fn() -> Option<(&'static [u8], usize)>) {
        // Bounded so a flood cannot starve the caller forever.
        for _ in 0..256 {
            match recv() {
                Some((buf, len)) => {
                    if len < 14 { continue; }
                    RX_PKTS.fetch_add(1, Ordering::Relaxed);
                    RX_BYTES.fetch_add(len as u64, Ordering::Relaxed);
                    ethernet::handle_frame(&buf[..len]);
                }
                None => break,
            }
        }
    }
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => drain(virtio_net::receive_packet),
        NIC_RTL8139 => drain(rtl8139::receive_packet),
        NIC_E1000   => drain(e1000::receive_packet),
        NIC_RTL8169 => drain(rtl8169::receive_packet),
        NIC_PCNET   => drain(pcnet::receive_packet),
        NIC_VMXNET3 => drain(vmxnet3::receive_packet),
        _ => {}
    }
}

/// Send a raw Ethernet frame
pub fn send_raw(buf: &[u8], len: usize) {
    NET_BUSY.fetch_add(1, Ordering::Acquire);
    TX_PKTS.fetch_add(1, Ordering::Relaxed);
    TX_BYTES.fetch_add(len as u64, Ordering::Relaxed);
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => virtio_net::send_packet(buf, len),
        NIC_RTL8139 => rtl8139::send_packet(buf, len),
        NIC_E1000   => e1000::send_packet(buf, len),
        NIC_RTL8169 => rtl8169::send_packet(buf, len),
        NIC_PCNET   => pcnet::send_packet(buf, len),
        NIC_VMXNET3 => vmxnet3::send_packet(buf, len),
        _ => {}
    }
    NET_BUSY.fetch_sub(1, Ordering::Release);
}

/// Handle network IRQ — called from the IDT IRQ 9/10/11 dispatcher (inside ISR).
///
///   1. Acknowledge the NIC's interrupt register (de-asserts the IRQ line).
///   2. Drain received frames right away — unless non-ISR network code was
///      interrupted mid-operation (NET_BUSY), in which case that code polls
///      the NIC itself as soon as it resumes.
/// All network paths also work purely by polling, so a NIC whose IRQ is not
/// routed (e.g. IRQ line > 15 behind a bridge) still works.
pub fn handle_net_irq() {
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => virtio_net::handle_irq(),
        NIC_RTL8139 => rtl8139::handle_irq(),
        NIC_E1000   => e1000::handle_irq(),
        NIC_RTL8169 => rtl8169::handle_irq(),
        NIC_PCNET   => pcnet::handle_irq(),
        NIC_VMXNET3 => vmxnet3::handle_irq(),
        _ => return,
    }
    if NET_BUSY.load(Ordering::Acquire) == 0 {
        poll_rx();
    }
}

/// Diagnostic registers for the active NIC
/// For e1000: (STATUS, ICR, RDH, RDT)
/// For RTL8139: (ISR as u32, CMD as u32, CBR as u32, CAPR as u32)
pub fn diag() -> (u32, u32, u32, u32) {
    match unsafe { ACTIVE_NIC } {
        NIC_RTL8139 => {
            let (isr, cmd, cbr, capr) = rtl8139::diag();
            (isr as u32, cmd as u32, cbr as u32, capr as u32)
        }
        NIC_E1000 => e1000::diag_regs(),
        _ => (0, 0, 0, 0),
    }
}

/// Short name of the active NIC driver (for ifconfig / ip / netstat).
pub fn nic_name() -> &'static str {
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => "VirtIO-Net",
        NIC_RTL8139 => "RTL8139",
        NIC_E1000   => "Intel e1000",
        NIC_RTL8169 => "RTL8169/8111",
        NIC_PCNET   => "AMD PCnet",
        NIC_VMXNET3 => "vmxnet3",
        _           => "none",
    }
}

/// Descriptive model string of the active NIC, including PCI vendor:device.
pub fn nic_model() -> &'static str {
    match unsafe { ACTIVE_NIC } {
        NIC_VIRTIO  => "virtio-net (1af4:1000, legacy I/O)",
        NIC_RTL8139 => "Realtek RTL8139 (10ec:8139)",
        NIC_E1000   => "Intel e1000 family (8086:xxxx)",
        NIC_RTL8169 => "Realtek RTL8169/8111 (10ec:8169/8168)",
        NIC_PCNET   => "AMD PCnet-PCI II Am79C970A (1022:2000, VMware vlance)",
        NIC_VMXNET3 => "VMware vmxnet3 (15ad:07b0)",
        _           => "none",
    }
}

/// Brute-force PCI configuration scan of every bus/device/function (covers
/// devices behind PCI-PCI bridges and does not depend on the size of the
/// kernel's PCI device table). Returns the first match.
pub fn pci_scan(vendor: u16, device: u16) -> Option<(u8, u8, u8)> {
    for bus in 0u16..256 {
        for dev in 0u8..32 {
            if crate::pci::vendor_id(bus as u8, dev, 0) == 0xFFFF { continue; }
            let multi = crate::pci::header_type(bus as u8, dev, 0) & 0x80 != 0;
            let nfunc = if multi { 8 } else { 1 };
            for func in 0..nfunc {
                if crate::pci::vendor_id(bus as u8, dev, func) == vendor
                    && crate::pci::device_id(bus as u8, dev, func) == device
                {
                    return Some((bus as u8, dev, func));
                }
            }
        }
    }
    None
}

pub(crate) fn serial_bdf(bus: u8, dev: u8, func: u8) {
    serial_hex_byte(bus);
    crate::arch::x86_64::serial::write_byte(b':');
    serial_hex_byte(dev);
    crate::arch::x86_64::serial::write_byte(b'.');
    crate::arch::x86_64::serial::write_byte(b'0' + func);
}

pub(crate) fn serial_hex16(v: u16) {
    serial_hex_byte((v >> 8) as u8);
    serial_hex_byte(v as u8);
}

pub(crate) fn serial_dec(mut v: u64) {
    if v == 0 { crate::arch::x86_64::serial::write_byte(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while v > 0 { buf[i] = b'0' + (v % 10) as u8; v /= 10; i += 1; }
    for j in (0..i).rev() { crate::arch::x86_64::serial::write_byte(buf[j]); }
}

/// Format IP for display: writes "x.x.x.x" into buf, returns len
pub fn format_ip(ip: [u8; 4], buf: &mut [u8; 16]) -> usize {
    let mut pos = 0;
    for i in 0..4 {
        let mut n = ip[i];
        if n >= 100 {
            buf[pos] = b'0' + n / 100;
            pos += 1;
            n %= 100;
            buf[pos] = b'0' + n / 10;
            pos += 1;
            n %= 10;
        } else if n >= 10 {
            buf[pos] = b'0' + n / 10;
            pos += 1;
            n %= 10;
        }
        buf[pos] = b'0' + n;
        pos += 1;
        if i < 3 {
            buf[pos] = b'.';
            pos += 1;
        }
    }
    pos
}

pub fn format_mac(mac: [u8; 6], buf: &mut [u8; 18]) -> usize {
    let hex = b"0123456789abcdef";
    let mut pos = 0;
    for i in 0..6 {
        buf[pos] = hex[(mac[i] >> 4) as usize];
        pos += 1;
        buf[pos] = hex[(mac[i] & 0xF) as usize];
        pos += 1;
        if i < 5 {
            buf[pos] = b':';
            pos += 1;
        }
    }
    pos
}

fn serial_hex_byte(v: u8) {
    let hex = b"0123456789abcdef";
    crate::arch::x86_64::serial::write_byte(hex[(v >> 4) as usize]);
    crate::arch::x86_64::serial::write_byte(hex[(v & 0xF) as usize]);
}

fn serial_ip(ip: [u8; 4]) {
    for i in 0..4 {
        let mut v = ip[i];
        if v >= 100 { crate::arch::x86_64::serial::write_byte(b'0' + v / 100); v %= 100; crate::arch::x86_64::serial::write_byte(b'0' + v / 10); }
        else if v >= 10 { crate::arch::x86_64::serial::write_byte(b'0' + v / 10); }
        crate::arch::x86_64::serial::write_byte(b'0' + v % 10);
        if i < 3 { crate::arch::x86_64::serial::write_byte(b'.'); }
    }
}
