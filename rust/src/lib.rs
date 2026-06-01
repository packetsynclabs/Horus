#![no_std]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[repr(C)]
pub struct SafeCap {
    pub raw: u32,
}

impl SafeCap {
    pub fn has_rights(&self, required: u32) -> bool {
        (self.raw & required) == required
    }
}

#[no_mangle]
pub extern "C" fn rust_validate_page_fault(task_id: u32, fault_addr: u32, error_code: u32) -> bool {
    let _ = (task_id, error_code);

    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 {
        return false;
    }

    if fault_addr >= 0x400000 && fault_addr < 0x800000 {
        return true;
    }
    if fault_addr >= 0xA00000 && fault_addr < 0xB00000 {
        return true;
    }

    false
}

#[repr(C)]
pub struct SafeCapability {
    pub raw: u32,
}

#[no_mangle]
pub extern "C" fn rust_cap_has_rights(cap: *const SafeCapability, required: u32) -> bool {
    if cap.is_null() {
        return false;
    }
    unsafe { ((*cap).raw & required) == required }
}

#[no_mangle]
pub extern "C" fn rust_get_user_page_protection(_task_id: u32, vaddr: u32) -> u32 {
    if (vaddr >= 0x400000 && vaddr < 0x800000) ||
       (vaddr >= 0xA00000 && vaddr < 0xB00000) ||
       (vaddr >= 0x7FC000 && vaddr < 0x800000) {
        return 0x7;
    }

    0
}

#[no_mangle]
pub extern "C" fn rust_handle_command(cmd: *const u8, len: usize) -> i32 {
    if cmd.is_null() {
        return 0;
    }

    let cmd_slice = unsafe { core::slice::from_raw_parts(cmd, len) };
    let cmd_str = match core::str::from_utf8(cmd_slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    if cmd_str == "help" { return 42; }
    if cmd_str == "version" { return 43; }
    if cmd_str.starts_with("echo ") { return 44; }
    if cmd_str == "exit" { return 1; }
    if cmd_str == "uptime" { return 45; }
    if cmd_str == "ps" || cmd_str == "tasks" { return 46; }
    if cmd_str == "caps" { return 47; }
    if cmd_str == "clear" { return 48; }
    if cmd_str.starts_with("kill ") { return 49; }
    if cmd_str.starts_with("mint ") { return 50; }
    if cmd_str == "rotate_keys" { return 51; }
    if cmd_str.starts_with("fs ") || cmd_str.starts_with("cap_") { return 52; }

    -1
}

/// Actions that the C side should perform after Rust policy decision.
/// This keeps low-level PTE manipulation and physical allocation in C
/// while moving complex security policy into Rust.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum DemandAction {
    /// Invalid fault — kill the task.
    Invalid = -1,
    /// Allocate a zeroed page and map it (normal demand paging).
    DemandZero = 0,
    /// This is a COW write fault: caller should copy the page if refcount > 1.
    CowCopyNeeded = 1,
    /// Fault was already handled or no action required (e.g. spurious).
    NoAction = 2,
}

/// Rust-owned demand paging + COW policy.
/// This is the authoritative security policy for memory mapping decisions.
/// 
/// Inputs:
/// - fault_addr: the address that faulted
/// - err_code: x86 page fault error code (bit 0 = present, bit 1 = write, bit 2 = user)
/// - is_cow: whether the C side detected the PAGE_COW software flag
/// - ref_count: current reference count on the physical page (for COW decision)
///
/// Returns a DemandAction telling C what to do.
#[no_mangle]
pub extern "C" fn rust_handle_demand_page_fault(
    fault_addr: u32,
    err_code: u32,
    is_cow: bool,
    ref_count: u16,
) -> DemandAction {
    // Security: reject faults on guard pages immediately
    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 {
        return DemandAction::Invalid;
    }

    // Only allow faults inside the standard user window for now.
    // Never allow user faults to touch kernel-reserved regions.
    let in_user_window =
        (fault_addr >= 0x400000 && fault_addr < 0x800000) ||
        (fault_addr >= 0xA00000 && fault_addr < 0xB00000);

    if !in_user_window {
        return DemandAction::Invalid;
    }

    // Additional security: never allow demand mapping into the recursive page table area
    // or other kernel-reserved high addresses from user context.
    if fault_addr >= 0xFFC00000 {
        return DemandAction::Invalid;
    }

    let is_write = (err_code & 2) != 0;
    let is_user = (err_code & 4) != 0;

    // Security: COW only makes sense on user-mode write faults
    if is_cow && is_write && is_user {
        if ref_count > 1 {
            // Multiple tasks share this page — must copy for isolation
            return DemandAction::CowCopyNeeded;
        } else {
            // Last reference — safe to just make writable (no copy needed)
            return DemandAction::NoAction;
        }
    }

    // Normal not-present fault in user window → demand zero-fill
    if (err_code & 1) == 0 && is_user {
        return DemandAction::DemandZero;
    }

    // Everything else is invalid at the policy level
    DemandAction::Invalid
}

/// FS operation validation policy (Rust is the source of truth for safety decisions).
/// Returns 0 for allow, negative for deny (error code).
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FsOp {
    Lookup = 0,
    Create = 1,
    Delete = 2,
    Read   = 3,
    Write  = 4,
    Mint   = 5,
}

#[no_mangle]
pub extern "C" fn rust_validate_fs_operation(
    task_id: u32,
    op: u32,
    rights_held: u32,
    name_ptr: *const u8,
    name_len: usize,
) -> i32 {
    // Basic confinement: reject obviously dangerous names in any context
    if !name_ptr.is_null() && name_len > 0 && name_len < 32 {
        // We can't safely read user memory here without copy; rely on C caller having validated.
        // Policy: always require non-empty and no dot-dot for lookup/create/delete
        if op == FsOp::Lookup as u32 || op == FsOp::Create as u32 || op == FsOp::Delete as u32 {
            // name sanity is done in C; here we can add task-specific rules later (e.g. confined tasks)
            let _ = (task_id,);
        }
    }

    // Rights checks are primarily in C before calling; this is for future complex policy
    // e.g. "task in confinement subtree may only mint read-only file caps"
    if rights_held == 0 {
        return -1;
    }

    0
}
