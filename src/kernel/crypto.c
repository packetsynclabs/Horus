#include "kernel.h"

/* =====================================================================
 * Cryptography + Platform Detection
 * =====================================================================
 *
 * This module now contains comprehensive early-boot hardware detection.
 * The goal is to make the kernel load and behave intelligently based on
 * the actual machine (32-bit vs 64-bit, SMP, CPU features, memory).
 */

static uint32_t cpu_features_ecx = 0;
static uint32_t cpu_features_edx = 0;
static uint32_t cpu_features_ebx = 0;   /* from leaf 1 - needed for logical CPU count */
static uint32_t ext_features_edx = 0;   /* 0x80000001 EDX */

platform_info_t platform;

static void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile (
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf)
    );
}

void cpu_detect_features(void) {
    uint32_t eax, ebx, ecx, edx;

    /* Basic features */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    cpu_features_ecx = ecx;
    cpu_features_edx = edx;
    cpu_features_ebx = ebx;   /* Save for HTT / logical CPU count */

    platform.family   = (eax >> 8) & 0xF;
    platform.model    = (eax >> 4) & 0xF;
    platform.stepping = eax & 0xF;

    /* Extended features for long mode */
    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    ext_features_edx = edx;
    platform.has_long_mode = (edx & (1 << 29)) != 0;   /* LM bit */

    /* Vendor string */
    uint32_t v[4] = {0};
    cpuid(0, &v[0], &v[1], &v[2], &v[3]);
    /* ebx, edx, ecx contain the vendor in a weird order */
    char *p = platform.vendor;
    *(uint32_t*)p = v[1]; p += 4;
    *(uint32_t*)p = v[3]; p += 4;
    *(uint32_t*)p = v[2]; p += 4;
    *p = 0;
}

int cpu_has_aesni(void) {
    return (cpu_features_ecx & (1 << 25)) != 0;
}

/* Comprehensive platform detection. Called early in kernel_main. */
void platform_detect(void) {
    /* Zero the struct */
    for (int i = 0; i < (int)sizeof(platform); i++) ((uint8_t*)&platform)[i] = 0;

    cpu_detect_features();

    /* Fill in the rich platform_info_t from basic cpuid(1) only */
    platform.has_aesni         = cpu_has_aesni();
    platform.has_tsc           = (cpu_features_edx & (1 << 4)) != 0;
    platform.has_sse           = (cpu_features_edx & (1 << 25)) != 0;
    platform.has_sse2          = (cpu_features_edx & (1 << 26)) != 0;
    platform.has_sse4_2        = (cpu_features_ecx & (1 << 20)) != 0;
    platform.has_rdrand        = (cpu_features_ecx & (1 << 30)) != 0;

    /* Vendor string from cpuid(0) - safe */
    uint32_t v[4] = {0};
    cpuid(0, &v[0], &v[1], &v[2], &v[3]);
    char *p = platform.vendor;
    *(uint32_t*)p = v[1]; p += 4;
    *(uint32_t*)p = v[3]; p += 4;
    *(uint32_t*)p = v[2]; p += 4;
    *p = 0;

    /* Long mode detection (extended leaf 0x80000001) - safe on all modern CPUs */
    uint32_t eax, ebx, ecx, edx;
    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    platform.has_long_mode = (edx & (1 << 29)) != 0;

    /* Skip leaf 0x80000007 (invariant TSC) for now - was causing hangs on some QEMU setups */
    platform.has_invariant_tsc = 0;

    /* Basic logical CPU count from CPUID (use the saved ebx from leaf 1) */
    if (cpu_features_edx & (1 << 28)) {  /* HTT bit */
        platform.num_logical_cpus = (cpu_features_ebx >> 16) & 0xFF;
    } else {
        platform.num_logical_cpus = 1;
    }
    platform.num_physical_cpus = platform.num_logical_cpus;

    /* Memory will be filled by multiboot info later if available */
    platform.total_memory_bytes = 0;
}

void platform_print_summary(void) {
    /* Single safe line - now with correct vendor + long_mode */
    set_text_colour(0x0F);
    print("  [ OK ] Platform: ");
    print(platform.vendor);
    print("  ");
    if (platform.has_long_mode) {
        print("64-bit capable");
    } else {
        print("32-bit only");
    }
    print("  CPUs:");
    print_decimal(platform.num_logical_cpus);
    if (platform.has_aesni) print("  AES-NI");
    if (platform.has_tsc) print("  TSC");
    println("");
}

/* Placeholder for future hardware-accelerated path.
 * When cpu_has_aesni() is true, storage can call a real AES-CTR here.
 */
void crypto_aes128_block_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    (void)key;
    for (int i = 0; i < 16; i++) out[i] = in[i];   /* identity for now */
}

void crypto_aes128_ctr_encrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *inout, size_t len) {
    (void)key; (void)nonce; (void)inout; (void)len;
    /* Software path in storage.c is currently authoritative.
     * This is just the hook for when we add real AES-NI.
     */
}
