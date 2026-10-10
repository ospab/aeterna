/*
SPDX-License-Identifier: AGPL-3.0-only
Copyright (c) 2026 ospab
Minimal UEFI bindings: only what the loader uses (UEFI spec 2.10).
Unused table slots are kept as `usize` so the layout stays right.
*/
#![allow(dead_code)]

use core::ffi::c_void;

pub type Handle = *mut c_void;
pub type Event = *mut c_void;
pub type Status = usize;

pub const SUCCESS: Status = 0;
const ERR: usize = 1 << 63;
pub const LOAD_ERROR: Status = ERR | 1;
pub const INVALID_PARAMETER: Status = ERR | 2;
pub const UNSUPPORTED: Status = ERR | 3;
pub const BUFFER_TOO_SMALL: Status = ERR | 5;
pub const NOT_READY: Status = ERR | 6;
pub const OUT_OF_RESOURCES: Status = ERR | 9;
pub const NOT_FOUND: Status = ERR | 14;

pub fn is_error(s: Status) -> bool { s & ERR != 0 }

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

pub const LOADED_IMAGE_GUID: Guid =
    Guid(0x5B1B31A1, 0x9562, 0x11d2, [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]);
pub const SIMPLE_FS_GUID: Guid =
    Guid(0x964e5b22, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
pub const BLOCK_IO_GUID: Guid =
    Guid(0x964e5b21, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
pub const GOP_GUID: Guid =
    Guid(0x9042a9de, 0x23dc, 0x4a38, [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a]);
pub const EDID_ACTIVE_GUID: Guid =
    Guid(0xbd8c1056, 0x9f36, 0x44ec, [0x92, 0xa8, 0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86]);
pub const EDID_DISCOVERED_GUID: Guid =
    Guid(0x1c0c34f6, 0xd380, 0x41fa, [0xa0, 0x49, 0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa]);
pub const DEVICE_PATH_GUID: Guid =
    Guid(0x09576e91, 0x6d3f, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
pub const GLOBAL_VARIABLE_GUID: Guid =
    Guid(0x8be4df61, 0x93ca, 0x11d2, [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
/// Private vendor GUID for the variables ospab-boot stores (last chosen entry).
pub const OSPAB_VARIABLE_GUID: Guid =
    Guid(0x6f737061, 0x622d, 0x4f53, [0x80, 0x01, 0x6f, 0x73, 0x70, 0x61, 0x62, 0x00]);
pub const ACPI20_GUID: Guid =
    Guid(0x8868e871, 0xe4f1, 0x11d3, [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81]);
pub const ACPI10_GUID: Guid =
    Guid(0xeb9d2d30, 0x2d88, 0x11d3, [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]);

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut SimpleTextInput,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub stderr_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

// Memory types.
pub const LOADER_CODE: u32 = 1;
pub const LOADER_DATA: u32 = 2;
pub const BOOT_SERVICES_CODE: u32 = 3;
pub const BOOT_SERVICES_DATA: u32 = 4;
pub const RUNTIME_SERVICES_CODE: u32 = 5;
pub const RUNTIME_SERVICES_DATA: u32 = 6;
pub const CONVENTIONAL_MEMORY: u32 = 7;
pub const UNUSABLE_MEMORY: u32 = 8;
pub const ACPI_RECLAIM_MEMORY: u32 = 9;
pub const ACPI_MEMORY_NVS: u32 = 10;
pub const MEMORY_MAPPED_IO: u32 = 11;
pub const MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const PAL_CODE: u32 = 13;
pub const PERSISTENT_MEMORY: u32 = 14;
/// OS-defined types (0x8000_0000..): what the loader hands to the kernel.
pub const OSPAB_KERNEL_MEMORY: u32 = 0x8000_0000;
pub const OSPAB_RECLAIM_MEMORY: u32 = 0x8000_0001;

pub const ALLOCATE_ANY_PAGES: u32 = 0;
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;
pub const ALLOCATE_ADDRESS: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryDescriptor {
    pub typ: u32,
    pub _pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

pub const EVT_TIMER: u32 = 0x8000_0000;
pub const TIMER_PERIODIC: u32 = 1;
pub const TIMER_RELATIVE: u32 = 2;
pub const BY_PROTOCOL: u32 = 2;

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    pub allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    pub free_pages: unsafe extern "efiapi" fn(u64, usize) -> Status,
    pub get_memory_map: unsafe extern "efiapi" fn(
        *mut usize, *mut MemoryDescriptor, *mut usize, *mut usize, *mut u32) -> Status,
    pub allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    pub free_pool: unsafe extern "efiapi" fn(*mut u8) -> Status,
    pub create_event: unsafe extern "efiapi" fn(
        u32, usize, *mut c_void, *mut c_void, *mut Event) -> Status,
    pub set_timer: unsafe extern "efiapi" fn(Event, u32, u64) -> Status,
    pub wait_for_event: unsafe extern "efiapi" fn(usize, *const Event, *mut usize) -> Status,
    signal_event: usize,
    pub close_event: unsafe extern "efiapi" fn(Event) -> Status,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    pub handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    pub load_image: unsafe extern "efiapi" fn(bool, Handle, *const u8, *const c_void, usize, *mut Handle) -> Status,
    pub start_image: unsafe extern "efiapi" fn(Handle, *mut usize, *mut *mut u16) -> Status,
    exit: usize,
    unload_image: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
    get_next_monotonic_count: usize,
    pub stall: unsafe extern "efiapi" fn(usize) -> Status,
    pub set_watchdog_timer: unsafe extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
    connect_controller: usize,
    disconnect_controller: usize,
    open_protocol: usize,
    close_protocol: usize,
    open_protocol_information: usize,
    protocols_per_handle: usize,
    pub locate_handle_buffer: unsafe extern "efiapi" fn(
        u32, *const Guid, *mut c_void, *mut usize, *mut *mut Handle) -> Status,
    pub locate_protocol: unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
}

#[repr(C)]
pub struct SimpleTextOutput {
    reset: usize,
    pub output_string: unsafe extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
    test_string: usize,
    pub query_mode: unsafe extern "efiapi" fn(*mut SimpleTextOutput, usize, *mut usize, *mut usize) -> Status,
    set_mode: usize,
    pub set_attribute: unsafe extern "efiapi" fn(*mut SimpleTextOutput, usize) -> Status,
    pub clear_screen: unsafe extern "efiapi" fn(*mut SimpleTextOutput) -> Status,
    pub set_cursor_position: unsafe extern "efiapi" fn(*mut SimpleTextOutput, usize, usize) -> Status,
    pub enable_cursor: unsafe extern "efiapi" fn(*mut SimpleTextOutput, bool) -> Status,
    pub mode: *mut TextMode,
}

#[repr(C)]
pub struct TextMode {
    pub max_mode: i32,
    pub mode: i32,
    pub attribute: i32,
    pub cursor_column: i32,
    pub cursor_row: i32,
    pub cursor_visible: bool,
}

/// Text attributes: foreground | background << 4.
pub const ATTR_NORMAL: usize   = 0x07; // light gray on black
pub const ATTR_BRIGHT: usize   = 0x0F; // white on black
pub const ATTR_DIM: usize      = 0x08; // dark gray on black
pub const ATTR_SELECTED: usize = 0x70; // black on light gray

/// SimpleTextInput scan codes.
pub const SCAN_UP: u16   = 0x01;
pub const SCAN_DOWN: u16 = 0x02;
pub const SCAN_RIGHT: u16 = 0x03;
pub const SCAN_LEFT: u16 = 0x04;
pub const SCAN_DELETE: u16 = 0x08;
pub const SCAN_HOME: u16 = 0x05;
pub const SCAN_END: u16  = 0x06;
pub const SCAN_ESC: u16  = 0x17;

#[repr(C)]
pub struct InputKey {
    pub scan_code: u16,
    pub unicode_char: u16,
}

#[repr(C)]
pub struct SimpleTextInput {
    pub reset: unsafe extern "efiapi" fn(*mut SimpleTextInput, bool) -> Status,
    pub read_key_stroke: unsafe extern "efiapi" fn(*mut SimpleTextInput, *mut InputKey) -> Status,
    pub wait_for_key: Event,
}

#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    unload: usize,
}

#[repr(C)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume: unsafe extern "efiapi" fn(*mut SimpleFileSystem, *mut *mut File) -> Status,
}

pub const FILE_MODE_READ: u64 = 1;

#[repr(C)]
pub struct File {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(*mut File, *mut *mut File, *const u16, u64, u64) -> Status,
    pub close: unsafe extern "efiapi" fn(*mut File) -> Status,
    delete: usize,
    pub read: unsafe extern "efiapi" fn(*mut File, *mut usize, *mut u8) -> Status,
    write: usize,
    pub get_position: unsafe extern "efiapi" fn(*mut File, *mut u64) -> Status,
    pub set_position: unsafe extern "efiapi" fn(*mut File, u64) -> Status,
}

#[repr(C)]
pub struct BlockIoMedia {
    pub media_id: u32,
    pub removable_media: u8,
    pub media_present: u8,
    pub logical_partition: u8,
    pub read_only: u8,
    pub write_caching: u8,
    pub block_size: u32,
    pub io_align: u32,
    pub last_block: u64,
}

#[repr(C)]
pub struct BlockIo {
    pub revision: u64,
    pub media: *mut BlockIoMedia,
    reset: usize,
    pub read_blocks: unsafe extern "efiapi" fn(*mut BlockIo, u32, u64, usize, *mut u8) -> Status,
}

pub const PIXEL_RGB: u32 = 0;
pub const PIXEL_BGR: u32 = 1;
pub const PIXEL_BITMASK: u32 = 2;

#[repr(C)]
pub struct PixelBitmask {
    pub red: u32,
    pub green: u32,
    pub blue: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct GopModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: PixelBitmask,
    pub pixels_per_scan_line: u32,
}

#[repr(C)]
pub struct GopMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut GopModeInfo,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

#[repr(C)]
pub struct Gop {
    pub query_mode: unsafe extern "efiapi" fn(*mut Gop, u32, *mut usize, *mut *mut GopModeInfo) -> Status,
    pub set_mode: unsafe extern "efiapi" fn(*mut Gop, u32) -> Status,
    blt: usize,
    pub mode: *mut GopMode,
}

/// EFI_EDID_ACTIVE_PROTOCOL / EFI_EDID_DISCOVERED_PROTOCOL.
#[repr(C)]
pub struct Edid {
    pub size: u32,
    pub edid: *const u8,
}

pub const VAR_NV: u32 = 1;
pub const VAR_BS: u32 = 2;
pub const VAR_RT: u32 = 4;
pub const RESET_COLD: u32 = 0;
pub const RESET_SHUTDOWN: u32 = 2;

#[repr(C)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

#[repr(C)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
    pub get_time: unsafe extern "efiapi" fn(*mut EfiTime, *mut c_void) -> Status,
    set_time: usize,
    get_wakeup_time: usize,
    set_wakeup_time: usize,
    set_virtual_address_map: usize,
    convert_pointer: usize,
    pub get_variable: unsafe extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut usize, *mut u8) -> Status,
    get_next_variable_name: usize,
    pub set_variable: unsafe extern "efiapi" fn(*const u16, *const Guid, u32, usize, *const u8) -> Status,
    get_next_high_monotonic_count: usize,
    pub reset_system: unsafe extern "efiapi" fn(u32, Status, usize, *const u8),
}
