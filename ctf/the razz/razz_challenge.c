/*
 * razz_challenge.c - Linux CTF Reverse Engineering Challenge (Final)
 *
 * A multithreaded "kernel integrity monitor" that hides a flag behind
 * layered anti-debug, per-byte XOR+arithmetic encoding with runtime
 * dependency, race conditions, delayed flag generation, and per-byte
 * in-memory masking.
 *
 * Compile:
 *   gcc -O2 -o razz_challenge razz_challenge.c -lpthread
 *   strip razz_challenge
 *
 * Verify:
 *   strings razz_challenge | grep -i flag    → nothing
 *   ltrace ./razz_challenge                  → no flag leaks
 *   checksec --file=razz_challenge           → check protections
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <errno.h>

/* ========================================================================
 * Shared state structure
 * ======================================================================== */
struct CoreState {
    uint64_t key_part1;
    uint64_t key_part2;
    uint64_t trigger;
    char     flag[64];          /* per-byte masked; never plaintext */
    uint32_t check_count;       /* must reach REQUIRED_CHECKS consecutively */
    uint8_t  chunk_ready[3];    /* per-chunk decode status */
    uint8_t  flag_assembled;
    uint8_t  flag_encoded;
    uint8_t  pos_masks[64];     /* per-position XOR mask (unique per byte) */
};

/* Global state — no mutex (intentional race condition) */
static volatile struct CoreState g_state;
static volatile int g_running = 1;
static volatile int g_debug_detected = 0;

/* ========================================================================
 * Anti-debugging layer 1: ptrace self-attach
 * ======================================================================== */
static void __attribute__((constructor)) _ad_layer1(void)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "[SYSTEM] Integrity check failed. Aborting.\n");
        _exit(1);
    }
}

/* ========================================================================
 * Anti-debugging layer 2: parent process name check
 *
 * Reads /proc/<ppid>/comm.  If it matches a known debugger, sets
 * g_debug_detected which silently poisons the flag decode — the
 * program keeps running but produces garbage.
 * ======================================================================== */
static void __attribute__((constructor)) _ad_layer2(void)
{
    char path[64];
    char comm[256];
    pid_t ppid = getppid();

    snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(comm, sizeof(comm), f)) {
            const char *dbg[] = {"gdb", "lldb", "strace", "ltrace",
                                 "radare2", "r2", "ida", "x64dbg", NULL};
            for (int i = 0; dbg[i]; i++) {
                if (strstr(comm, dbg[i])) {
                    g_debug_detected = 1;
                    break;
                }
            }
        }
        fclose(f);
    }
}

/* ========================================================================
 * Anti-debugging layer 3: timing check
 *
 * Runs a deterministic LCG for 100K iterations.  On real hardware this
 * takes well under 100ms.  Under single-stepping it takes minutes.
 *
 * The LCG result (_timing_canary) also serves as a runtime dependency
 * for the flag decoder — pure static analysis must trace this to get
 * the correct canary value.
 *
 * Threshold: 2 seconds — generous enough to avoid false positives on
 * slow VMs or loaded machines while still catching single-steppers.
 * ======================================================================== */
static volatile uint64_t _timing_canary = 0;

static void __attribute__((constructor)) _ad_layer3(void)
{
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Deterministic LCG — result feeds into flag decoding */
    volatile uint64_t x = 0x12345678ULL;
    for (int i = 0; i < 100000; i++)
        x = (x * 6364136223846793005ULL) + 1442695040888963407ULL;
    _timing_canary = x;

    clock_gettime(CLOCK_MONOTONIC, &t2);
    long elapsed_us = (t2.tv_sec - t1.tv_sec) * 1000000L +
                      (t2.tv_nsec - t1.tv_nsec) / 1000L;

    /* 2-second threshold: avoids false positives on slow machines */
    if (elapsed_us > 2000000) {
        g_debug_detected = 1;
    }
}

/* ========================================================================
 * XOR-obfuscated target constants
 *
 * Target values:
 *   key_part1 → 0x1337C0DE
 *   key_part2 → 0xDEADBEEF
 *   trigger   → 0x0BADC0DE
 * ======================================================================== */
static volatile uint64_t _omA = 0xA5A5A5A5ULL;
static volatile uint64_t _omB = 0x5A5A5A5AULL;
static volatile uint64_t _omC = 0x3C3C3C3CULL;

static volatile uint64_t _ekA = 0xB692657BULL;  /* 0x1337C0DE ^ 0xA5A5A5A5 */
static volatile uint64_t _ekB = 0x84F7E4B5ULL;  /* 0xDEADBEEF ^ 0x5A5A5A5A */
static volatile uint64_t _ekC = 0x3791FCE2ULL;  /* 0x0BADC0DE ^ 0x3C3C3C3C */

static inline uint64_t _dt1(void) { return _ekA ^ _omA; }
static inline uint64_t _dt2(void) { return _ekB ^ _omB; }
static inline uint64_t _dt3(void) { return _ekC ^ _omC; }

/* ========================================================================
 * XOR + Arithmetic + Runtime-dependent flag encoding
 *
 * Flag: "flag{razzsecurity-by-brijesh}"  (29 chars)
 *
 * Encoding:  encoded[i] = (plain[i] ^ fbk[i] ^ canary_low_byte) + fbo[i]
 *
 * The canary_low_byte comes from _timing_canary (the LCG result from
 * layer 3).  A pure static reverser must trace the LCG to get 0x98,
 * then use it alongside the per-byte keys and offsets to decode.
 * ======================================================================== */

/* Per-byte XOR keys (29 unique keys) */
static volatile uint8_t _fbk[] = {
    0x42, 0x9A, 0xF1, 0x3D, 0x77, 0xBB, 0x2E, 0x55, 0xCC,
    0x11, 0x6F, 0xAA, 0xD3, 0x48, 0x19, 0xE7, 0x5C, 0x83,
    0x64, 0x0B, 0x99, 0x37, 0xFE, 0xC5, 0x2A, 0xDD, 0x8E,
    0x46, 0xA1
};

/* Per-byte signed arithmetic offsets */
static volatile int8_t _fbo[] = {
     3, -7,  5, -2,  9, -4,  1, -8,  6,
    -3,  7, -1,  4, -9,  2, -6,  8, -5,
     3, -7,  5, -2,  9, -4,  1, -8,  6,
    -3,  7
};

/* Encoded bytes: (plain[i] ^ _fbk[i] ^ 0x98) + _fbo[i]
 * The 0x98 comes from (_timing_canary & 0xFF) at runtime */
static const uint8_t _eflag[] = {
    0xBF, 0x67, 0x0D, 0xC0, 0x9D, 0x4D, 0xD8, 0xAF, 0x34,
    0xF7, 0x99, 0x50, 0x42, 0x99, 0xEA, 0x05, 0xC5, 0x31,
    0xA1, 0xE3, 0x31, 0xCB, 0x1D, 0x30, 0xD9, 0x18, 0x6B,
    0xB3, 0x4B
};
#define FLAG_LEN 29

/* Consecutive condition passes needed before flag generation */
#define REQUIRED_CHECKS 5

/* ========================================================================
 * Condition checks — split across noinline functions
 *
 * Each function reads the target from volatile globals (XOR-masked)
 * and compares.  Being noinline forces them to be separate code blocks
 * in the binary — a static reverser must analyze each one.
 * ======================================================================== */
static int __attribute__((noinline)) _chk_a(uint64_t v)
{
    return v == (_ekA ^ _omA);
}

static int __attribute__((noinline)) _chk_b(uint64_t v)
{
    return v == (_ekB ^ _omB);
}

static int __attribute__((noinline)) _chk_c(uint64_t v)
{
    return v == (_ekC ^ _omC);
}

/* ========================================================================
 * Flag generation via function pointer indirection
 * ======================================================================== */
typedef void (*flag_gen_fn)(volatile struct CoreState *, int);
static volatile flag_gen_fn _fg_ptr = NULL;

/* ========================================================================
 * Partial flag decoding — one chunk at a time
 *
 * Each byte is decoded individually and immediately masked with a
 * per-position XOR key before being stored.  The flag is NEVER fully
 * plaintext in any buffer — not on the stack, not in g_state.flag.
 *
 * To read the flag from memory, you must also know pos_masks[i] for
 * each position.
 *
 * Chunk boundaries:
 *   0: bytes 0–8    "flag{razz"
 *   1: bytes 9–17   "security-"
 *   2: bytes 18–28  "by-brijesh}"
 * ======================================================================== */
static void __attribute__((noinline)) _decode_chunk(volatile struct CoreState *st,
                                                     int chunk_id)
{
    int start, end;
    switch (chunk_id) {
    case 0: start = 0;  end = 9;  break;
    case 1: start = 9;  end = 18; break;
    case 2: start = 18; end = 29; break;
    default: return;
    }

    /* Runtime dependency: canary low byte from LCG timing check */
    uint8_t canary_byte = (uint8_t)(_timing_canary & 0xFF);

    /* Silent poison if debugger detected — subtle bit flip so the
     * output looks 'almost right' (convincing bad-solve, not obviously
     * broken garbage) */
    uint8_t poison = g_debug_detected ? 0x01 : 0x00;

    for (int i = start; i < end; i++) {
        uint8_t key = _fbk[i] ^ poison;
        int8_t  off = _fbo[i];

        /* Decode: plain = (encoded - offset) ^ key ^ canary_byte */
        uint8_t decoded = (uint8_t)((_eflag[i] - off) ^ key ^ canary_byte);

        /* Per-position mask — byte is never stored plaintext */
        uint8_t pos_mask = (uint8_t)((i * 37 + 0xAB) ^ (canary_byte >> 3));
        pos_mask |= 0x01;

        /* Store masked byte */
        ((volatile char *)st->flag)[i] = (char)(decoded ^ pos_mask);
        ((volatile uint8_t *)st->pos_masks)[i] = pos_mask;

        /* Rolling re-mask: immediately re-mask the PREVIOUS byte with
         * a fresh mask via XOR transition.  This never computes plaintext:
         *   flag[prev] was: plain ^ old_mask
         *   XOR with (old_mask ^ new_mask) gives: plain ^ new_mask
         * At most 1 decoded byte exists simultaneously (in a register). */
        if (i > start) {
            int prev = i - 1;
            uint8_t old_m = ((volatile uint8_t *)st->pos_masks)[prev];
            uint8_t fresh = (uint8_t)((prev * 53 + canary_byte + 0x7F) ^ (prev << 3));
            fresh |= 0x01;
            ((volatile char *)st->flag)[prev] ^= (old_m ^ fresh);
            ((volatile uint8_t *)st->pos_masks)[prev] = fresh;
        }
    }

    /* Re-mask the last byte of this chunk (wasn't re-masked in the loop) */
    {
        int last = end - 1;
        uint8_t old_m = ((volatile uint8_t *)st->pos_masks)[last];
        uint8_t fresh = (uint8_t)((last * 53 + canary_byte + 0x7F) ^ (last << 3));
        fresh |= 0x01;
        ((volatile char *)st->flag)[last] ^= (old_m ^ fresh);
        ((volatile uint8_t *)st->pos_masks)[last] = fresh;
    }

    ((volatile uint8_t *)st->chunk_ready)[chunk_id] = 1;
}

/* ========================================================================
 * generate_flag() — orchestrates chunk decoding
 *
 * After decoding all chunks, each byte in flag[] is XOR'd with its
 * corresponding pos_masks[] entry.  A memory dump of flag[] alone
 * yields garbage — you also need pos_masks[].
 * ======================================================================== */
static void __attribute__((noinline)) _generate_flag_impl(
    volatile struct CoreState *state, int _unused)
{
    (void)_unused;

    /* Decode each chunk (each byte immediately masked) */
    _decode_chunk(state, 0);
    _decode_chunk(state, 1);
    _decode_chunk(state, 2);

    /* Null-terminate (also masked) */
    uint8_t term_mask = (uint8_t)((FLAG_LEN * 37 + 0xAB) ^
                        (((uint8_t)(_timing_canary & 0xFF)) >> 3));
    term_mask |= 0x01;
    ((volatile char *)state->flag)[FLAG_LEN] = (char)(0x00 ^ term_mask);
    ((volatile uint8_t *)state->pos_masks)[FLAG_LEN] = term_mask;

    state->flag_encoded = 1;
    state->flag_assembled = 1;
}

/* ========================================================================
 * Thread 1: Mutator — ramps values toward targets
 * ======================================================================== */
static void *thread_mutator(void *arg)
{
    (void)arg;
    uint64_t step = 0;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());

    uint64_t target1 = _dt1();
    uint64_t target2 = _dt2();
    uint64_t target3 = _dt3();

    while (g_running) {
        step++;

        /* Randomized increments */
        uint64_t inc1 = (target1 / 500) + (rand_r(&seed) % 1000) + 1;
        uint64_t inc2 = (target2 / 400) + (rand_r(&seed) % 2000) + 1;
        uint64_t inc3 = (target3 / 300) + (rand_r(&seed) % 1500) + 1;

        if (g_state.key_part1 < target1) {
            g_state.key_part1 += inc1;
            if (g_state.key_part1 > target1)
                g_state.key_part1 = target1;
        }

        if (g_state.key_part2 < target2) {
            g_state.key_part2 += inc2;
            if (g_state.key_part2 > target2)
                g_state.key_part2 = target2;
        }

        if (g_state.trigger < target3) {
            g_state.trigger += inc3;
            if (g_state.trigger > target3)
                g_state.trigger = target3;
        }

        if (step % 100 == 0) {
            printf("\r[CORE] cycle=%lu  k1=0x%lX  k2=0x%lX  t=0x%lX   ",
                   (unsigned long)step,
                   (unsigned long)g_state.key_part1,
                   (unsigned long)g_state.key_part2,
                   (unsigned long)g_state.trigger);
            fflush(stdout);
        }

        usleep(500 + (rand_r(&seed) % 1500));
    }
    return NULL;
}

/* ========================================================================
 * Thread 2: Corruptor — aggressive corruption
 * ======================================================================== */
static void *thread_corruptor(void *arg)
{
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) ^ 0xFEEDFACE ^ getpid());

    while (g_running) {
        int choice = rand_r(&seed) % 12;

        switch (choice) {
        case 0:
            g_state.key_part1 = 0;
            break;
        case 1:
            g_state.key_part2 = 0;
            break;
        case 2:
            g_state.trigger = 0;
            break;
        case 3:
            g_state.key_part1 ^= ((uint64_t)rand_r(&seed) << 16) |
                                  (uint64_t)rand_r(&seed);
            break;
        case 4:
            g_state.key_part2 ^= ((uint64_t)rand_r(&seed) << 16) |
                                  (uint64_t)rand_r(&seed);
            break;
        case 5:
            g_state.trigger ^= ((uint64_t)rand_r(&seed) << 16) |
                                (uint64_t)rand_r(&seed);
            break;
        case 6:
            g_state.key_part1 >>= (rand_r(&seed) % 8 + 1);
            break;
        case 7:
            g_state.key_part2 >>= (rand_r(&seed) % 8 + 1);
            break;
        case 8:
            g_state.key_part1 = 0;
            g_state.key_part2 = 0;
            g_state.trigger = 0;
            break;
        case 9:
            /* Overwrite flag AND masks with garbage */
            for (int i = 0; i < 64; i++) {
                ((volatile char *)g_state.flag)[i] = (char)(rand_r(&seed) & 0xFF);
                ((volatile uint8_t *)g_state.pos_masks)[i] = (uint8_t)(rand_r(&seed) & 0xFF);
            }
            g_state.flag_assembled = 0;
            g_state.check_count = 0;
            for (int i = 0; i < 3; i++)
                ((volatile uint8_t *)g_state.chunk_ready)[i] = 0;
            break;
        case 10:
            {
                uint64_t tmp = g_state.key_part1;
                g_state.key_part1 = g_state.key_part2;
                g_state.key_part2 = tmp;
            }
            break;
        default:
            break;
        }

        usleep(2000 + (rand_r(&seed) % 6000));
    }
    return NULL;
}

/* ========================================================================
 * Thread 3: Checker — delayed multi-check trigger
 * ======================================================================== */
static void *thread_checker(void *arg)
{
    (void)arg;

    _fg_ptr = _generate_flag_impl;

    while (g_running) {
        uint64_t k1 = g_state.key_part1;
        uint64_t k2 = g_state.key_part2;
        uint64_t tr = g_state.trigger;

        if (_chk_a(k1) && _chk_b(k2) && _chk_c(tr)) {
            g_state.check_count++;

            if (g_state.check_count >= REQUIRED_CHECKS &&
                !g_state.flag_assembled) {
                flag_gen_fn fn = (flag_gen_fn)_fg_ptr;
                if (fn) {
                    fn((volatile struct CoreState *)&g_state, 0);
                }
            }
        } else {
            g_state.check_count = 0;
        }

        usleep(1500);
    }
    return NULL;
}

/* ========================================================================
 * Signal handler
 * ======================================================================== */
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ========================================================================
 * main()
 * ======================================================================== */
int main(void)
{
    pthread_t t_mutator, t_corruptor, t_checker;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Fill flag and masks with garbage */
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 64; i++) {
        ((char *)g_state.flag)[i] = (char)(rand() % 94 + 33);
        ((uint8_t *)g_state.pos_masks)[i] = (uint8_t)(rand() & 0xFF);
    }

    g_state.key_part1      = 0;
    g_state.key_part2      = 0;
    g_state.trigger        = 0;
    g_state.check_count    = 0;
    g_state.flag_assembled = 0;
    g_state.flag_encoded   = 0;
    for (int i = 0; i < 3; i++)
        ((uint8_t *)g_state.chunk_ready)[i] = 0;

    printf("\n");
    printf("  ╔════════════════════════════════════════╗\n");
    printf("  ║   RAZZ SECURITY SYSTEMS  v3.7.1-kern   ║\n");
    printf("  ║   Kernel Integrity Monitor              ║\n");
    printf("  ╚════════════════════════════════════════╝\n");
    printf("\n");
    printf("[BOOT] Loading kernel execution layer...\n");
    usleep(200000);
    printf("[BOOT] Mapping secure memory regions...\n");
    usleep(150000);
    printf("[BOOT] Initializing cryptographic subsystem...\n");
    usleep(300000);
    printf("[BOOT] Performing hardware integrity check...\n");
    usleep(250000);
    printf("[BOOT] Integrity check... OK\n");
    usleep(100000);
    printf("[+] Switching to kernel execution layer...\n");
    usleep(400000);
    printf("[KERN] Privileged mode active\n");
    printf("[KERN] Starting monitoring threads...\n\n");

    if (pthread_create(&t_mutator, NULL, thread_mutator, NULL) != 0) {
        perror("[FATAL] thread init");
        return 1;
    }
    if (pthread_create(&t_corruptor, NULL, thread_corruptor, NULL) != 0) {
        perror("[FATAL] thread init");
        return 1;
    }
    if (pthread_create(&t_checker, NULL, thread_checker, NULL) != 0) {
        perror("[FATAL] thread init");
        return 1;
    }

    printf("[KERN] All subsystems operational.\n");
    printf("[KERN] Entering main monitoring loop.\n\n");

    const char *subsys[] = {
        "NETFILTER", "CRYPTO-ENG", "AUTH-MGR", "BLOCK-IO", "SCHED",
        "IPC-BUS", "DRM-CORE", "FS-CACHE", "HUGEPAGE", "AUDIT-LOG",
        "CGROUP-V2", "UEVENT", "KTHREAD", "WORKQUEUE", "TIMER-WHEEL"
    };
    int nsub = sizeof(subsys) / sizeof(subsys[0]);
    int idx = 0;
    unsigned int mseed = (unsigned int)(time(NULL) ^ 0xDECAF);

    while (g_running) {
        sleep(2 + (rand_r(&mseed) % 3));
        if (!g_running) break;

        int si = (idx + rand_r(&mseed)) % nsub;
        int status = rand_r(&mseed) % 100;

        if (status < 55) {
            printf("\n[%s] health check ......... OK", subsys[si]);
        } else if (status < 75) {
            printf("\n[%s] health check ......... WARN: minor drift (0x%04X)",
                   subsys[si], rand_r(&mseed) & 0xFFFF);
        } else if (status < 90) {
            printf("\n[%s] health check ......... ALERT: anomaly sector 0x%X",
                   subsys[si], rand_r(&mseed) & 0xFFFFF);
        } else if (status < 97) {
            printf("\n[%s] health check ......... CRIT: checksum mismatch",
                   subsys[si]);
        } else {
            printf("\n[KERN] Watchdog triggered — subsystem %s unresponsive",
                   subsys[si]);
            printf("\n[KERN] Attempting recovery...");
            usleep(500000);
            printf(" recovered.");
        }
        fflush(stdout);

        if (idx % 7 == 6) {
            printf("\n[KERN] ──── Status Summary ────");
            printf("\n[KERN]  Uptime:    %d cycles", idx + 1);
            printf("\n[KERN]  Threads:   3/3 active");
            printf("\n[KERN]  State:     k1=0x%lX  k2=0x%lX  t=0x%lX",
                   (unsigned long)g_state.key_part1,
                   (unsigned long)g_state.key_part2,
                   (unsigned long)g_state.trigger);
            printf("\n[KERN]  Checks:    %u/%d",
                   g_state.check_count, REQUIRED_CHECKS);
            printf("\n[KERN] ───────────────────────");
            fflush(stdout);
        }

        idx++;
    }

    printf("\n\n[KERN] Received shutdown signal.\n");
    printf("[KERN] Terminating worker threads...\n");

    pthread_join(t_mutator, NULL);
    pthread_join(t_corruptor, NULL);
    pthread_join(t_checker, NULL);

    printf("[KERN] All threads stopped.\n");
    printf("[KERN] Wiping core state from memory...\n");

    /* Secure wipe */
    volatile char *wp = (volatile char *)&g_state;
    for (size_t i = 0; i < sizeof(g_state); i++)
        wp[i] = 0;
    _fg_ptr = NULL;

    printf("[KERN] Shutdown complete.\n");

    return 0;
}
