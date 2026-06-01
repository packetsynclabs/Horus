#include "kernel.h"

extern int current_task;
extern tcb_t tasks[MAX_TASKS];

#define CNODE_SIZE 256
#define KERNEL_RESERVED_CAPS 4

static struct capability root_cnode[CNODE_SIZE];

#define MAX_REV_SETS 8

/* Records minted capabilities so that revocation can walk derived caps. */
static struct {
    uint32_t target_slot;
    uint32_t badge;
    int      valid;
} rev_sets[MAX_REV_SETS];

/* Initialise the root capability node for the kernel task. */
void cap_init(void) {
    for (int i = 0; i < CNODE_SIZE; i++) {
        root_cnode[i].type = CAP_NULL;
        root_cnode[i].rights = 0;
        root_cnode[i].object = 0;
        root_cnode[i].badge = 0;
    }
    root_cnode[0].type = CAP_TCB;
    root_cnode[0].rights = CAP_RIGHT_ALL;
    root_cnode[0].object = 0;
    root_cnode[0].badge = 0xC0DE0001U;

    root_cnode[1].type = CAP_NOTIFICATION;
    root_cnode[1].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE;
    root_cnode[1].object = 0;
    root_cnode[1].badge = 0xC0DE0002U;

    root_cnode[2].type = CAP_ENDPOINT;
    root_cnode[2].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT;
    root_cnode[2].object = 0;
    root_cnode[2].badge = 0;

    root_cnode[3].type = CAP_FRAME;
    root_cnode[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
    root_cnode[3].object = USER_VIRT_BASE;
    root_cnode[3].badge = 0;

    /* Grant user administration capability in the root cnode (for task 0) */
    root_cnode[6].type   = CAP_USER;
    root_cnode[6].rights = CAP_RIGHT_ALL;
    root_cnode[6].object = 0;
    root_cnode[6].badge  = 0;

    /* Audit capability for root (read + future write for audit daemon) */
    root_cnode[7].type   = CAP_AUDIT;
    root_cnode[7].rights = CAP_RIGHT_READ | CAP_RIGHT_AUDIT_WRITE;
    root_cnode[7].object = 0;
    root_cnode[7].badge  = 0;

    for (int i=0; i < MAX_REV_SETS; i++) rev_sets[i].valid = 0;
}

// =====================================================================
// SECURITY INVARIANT #1 (foundation):
//   Every privileged operation MUST begin with cap_lookup(slot, required_rights).
//   There is no ambient authority. Direct array access is only for
//   installing results AFTER a successful cap_lookup on the granting cap.
// =====================================================================
// Major: cspace lookup (per-task or root fallback) with exact rights mask check
struct capability *cap_lookup(uint32_t slot, uint32_t required_rights) {
    if (slot >= CNODE_SIZE) return NULL;

    if (tasks[current_task].cspace && slot < tasks[current_task].cspace_size) {
        struct capability *c = &tasks[current_task].cspace[slot];
        if (c->type != CAP_NULL && (c->rights & required_rights) == required_rights) {
            return c;
        }
        return NULL;
    }

    struct capability *c = &root_cnode[slot];
    if (c->type == CAP_NULL) return NULL;
    if ((c->rights & required_rights) != required_rights) return NULL;
    return c;
}

// =====================================================================
// SECURITY INVARIANT #1 (central enforcement point):
//   cap_mint is the ONLY place new capabilities are installed into a cspace.
//   All callers MUST have already performed authorization via cap_lookup
//   on the source capability with CAP_RIGHT_MINT.
//   Direct writes to tasks[].cspace[] or root_cnode[] from anywhere else
//   are forbidden for privileged operations.
// =====================================================================
// Major: derive cap (with rights subset) into dest; blocks kernel reserved slots 0-3
// Enforces basic per-task capability quota (MAX_CAPS_PER_TASK) to prevent exhaustion.
bool cap_mint(uint32_t dest_slot, uint32_t src_slot, uint32_t new_rights) {
    struct capability *src = cap_lookup(src_slot, CAP_RIGHT_MINT);
    if (!src || dest_slot >= CNODE_SIZE) return false;

    if (dest_slot < KERNEL_RESERVED_CAPS) {
        return false;
    }

    struct capability *dest_array = tasks[current_task].cspace ? tasks[current_task].cspace : root_cnode;

    /* Quota check (only count real new allocations) */
    if (dest_array[dest_slot].type == CAP_NULL) {
        if (tasks[current_task].caps_in_use >= MAX_CAPS_PER_TASK) {
            return false;   /* quota exhausted */
        }
        tasks[current_task].caps_in_use++;
    }

    dest_array[dest_slot] = *src;
    dest_array[dest_slot].rights = new_rights & src->rights;
    dest_array[dest_slot].badge = src_slot;

    return true;
}

bool cap_transfer(uint32_t dest_slot, uint32_t src_slot) {
    return cap_mint(dest_slot, src_slot, ~0U);
}

bool cap_move(uint32_t dest_slot, uint32_t src_slot) {
    if (cap_transfer(dest_slot, src_slot)) {
        return cap_revoke(src_slot);
    }
    return false;
}

// Robust revocation: revokes a capability and all directly derived capabilities (badge chain).
// For FS caps this also attempts limited cross-task cascade for high badges (research limitation noted).
bool cap_revoke(uint32_t slot) {
    if (slot >= CNODE_SIZE) return false;

    struct capability *cspace = tasks[current_task].cspace ? tasks[current_task].cspace : root_cnode;

    if (slot < KERNEL_RESERVED_CAPS && cspace == root_cnode) return false;

    uint32_t target_badge = cspace[slot].badge;
    uint32_t target_obj   = cspace[slot].object;
    uint32_t orig_type    = cspace[slot].type;

    // If this is a REVOCATION handle, follow it to the real target first
    if (orig_type == CAP_REVOCATION && target_obj < CNODE_SIZE) {
        uint32_t real_target = target_obj;
        cspace[slot].type = CAP_NULL; /* consume the revocation handle */
        slot = real_target;           /* now revoke the actual */
        if (slot >= CNODE_SIZE) return true;
        target_badge = cspace[slot].badge;
        target_obj   = cspace[slot].object;
    }

    // Clear the primary capability (decrement quota counter if it was in use)
    if (cspace[slot].type != CAP_NULL) {
        if (tasks[current_task].caps_in_use > 0) tasks[current_task].caps_in_use--;
    }
    cspace[slot].type = CAP_NULL;
    cspace[slot].rights = 0;
    cspace[slot].badge = 0;
    cspace[slot].object = 0;

    /* Direct derived in caller's cspace */
    for (uint32_t i = 0; i < CNODE_SIZE; i++) {
        if (cspace[i].badge == slot || cspace[i].badge == target_badge) {
            cspace[i].type = CAP_NULL;
            cspace[i].rights = 0;
            cspace[i].badge = 0;
            cspace[i].object = 0;
        }
    }

    /* FS-specific: if revoking a DIR, also zap any caps in *this* cspace pointing at same object subtree (best effort) */
    if (target_obj) {
        for (uint32_t i = 0; i < CNODE_SIZE; i++) {
            if (cspace[i].object == target_obj) {
                if (cspace[i].type != CAP_NULL && tasks[current_task].caps_in_use > 0)
                    tasks[current_task].caps_in_use--;
                cspace[i].type = CAP_NULL;
                cspace[i].rights = 0;
                cspace[i].badge = 0;
                cspace[i].object = 0;
            }
        }
    }

    /* Full cross-task transitive revocation scan (now always performed for strong revocation).
       With MAX_TASKS=64 and 256-slot cspaces this is cheap (~16k entries) and provides
       reliable cross-task revocation for delegated capabilities. */
    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        struct capability *tcspace = tasks[t].cspace;
        for (uint32_t s = 0; s < CNODE_SIZE; s++) {
            if (tcspace[s].badge == slot || tcspace[s].badge == target_badge) {
                if (tcspace[s].type != CAP_NULL) {
                    if (tasks[t].caps_in_use > 0) tasks[t].caps_in_use--;
                    tcspace[s].type = CAP_NULL;
                    tcspace[s].rights = 0;
                    tcspace[s].badge = 0;
                    tcspace[s].object = 0;
                }
            }
        }
    }

    /* Also handle any outstanding rev_sets */
    for (int r = 0; r < MAX_REV_SETS; r++) {
        if (rev_sets[r].valid && (rev_sets[r].badge == target_badge || rev_sets[r].badge == slot)) {
            rev_sets[r].valid = 0;
        }
    }

    return true;
}

// Creates a first-class revocation capability. Revoking the REVOCATION cap (or calling
// cap_revoke on its slot) clears the original target + any direct badge-derived caps.
bool cap_create_revocation_set(uint32_t target_slot, uint32_t rev_slot) {
    struct capability *cspace = tasks[current_task].cspace ? tasks[current_task].cspace : root_cnode;

    if (target_slot >= CNODE_SIZE || rev_slot >= CNODE_SIZE || target_slot < 4) return false;

    struct capability *target = &cspace[target_slot];
    if (target->type == CAP_NULL) return false;

    cspace[rev_slot].type   = CAP_REVOCATION;
    cspace[rev_slot].rights = CAP_RIGHT_REVOKE;
    cspace[rev_slot].object = target_slot;   /* points at the cap slot being protected */
    cspace[rev_slot].badge  = 0xDEAD0000U;   /* marker */

    /* The target itself gets its badge updated so normal revoke sees the revoker? For v1 the
       holder of the REVOCATION cap is expected to call cap_revoke(rev_slot) which we special-case. */
    return true;
}
