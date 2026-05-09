# RAZZ SECURITY SYSTEMS — Final RE Challenge

## Overview

A multithreaded Linux ELF binary disguised as a "Kernel Integrity Monitor". The flag is buried behind layered anti-debugging, per-byte XOR+arithmetic encoding with a runtime LCG dependency, aggressive race conditions, delayed multi-check generation, function pointer indirection, and per-byte in-memory masking.

**Difficulty:** Medium-Hard  
**Category:** Reverse Engineering  
**Flag:** *(hidden — must be extracted via RE)*

---

## Build & Deploy

```bash
gcc -O2 -o razz_challenge razz_challenge.c -lpthread
strip razz_challenge

# Verification
strings razz_challenge | grep -i "flag{"     # → nothing
nm razz_challenge 2>&1                       # → no symbols
```

**Distribute only `razz_challenge`** (the stripped binary).

---

## Architecture

### Threads

| Thread | Role |
|--------|------|
| **Mutator** | Ramps `key_part1`, `key_part2`, `trigger` toward targets (randomized increments) |
| **Corruptor** | 11 corruption modes: reset, XOR, bit-shift, swap, full-wipe. 2–8ms interval |
| **Checker** | 3 noinline condition checks → 5 consecutive passes → flag gen via function pointer |
| **Main** | Fake kernel monitor output |

### Anti-Debug (3 Layers)

| # | Method | Behavior |
|---|--------|----------|
| 1 | `ptrace(PTRACE_TRACEME)` | Hard exit with misleading message |
| 2 | `/proc/<ppid>/comm` vs debugger names | **Silent** key poisoning (flag decodes to garbage) |
| 3 | Timing: 100K LCG iterations, 2s threshold | **Silent** key poisoning + canary dependency |

> Layers 2 & 3 don't crash — the program keeps running but produces a wrong flag.
> The 2-second threshold avoids false positives on slow VMs.

### Flag Encoding

```
encoded[i] = (plaintext[i]  ^  per_byte_key[i]  ^  canary_low_byte)  +  offset[i]
```

- **29 unique XOR keys** (`_fbk[]`)
- **29 signed arithmetic offsets** (`_fbo[]`)
- **Runtime LCG canary**: The timing check constructor runs a deterministic LCG (seed `0x12345678`, 100K iterations). The low byte of the result (`0x98`) is XOR'd into every flag byte. Static reversers must trace the LCG to get this value.

### In-Memory Masking (Anti-dump)

After decoding, each flag byte is **never stored plaintext**:

```c
pos_mask[i] = ((i * 37 + 0xAB) ^ (canary >> 3)) | 0x01;
flag[i] = decoded_byte ^ pos_mask[i];
```

- Dumping `flag[]` from `/proc/pid/mem` gives garbage
- Must also dump `pos_masks[]` and XOR each byte to recover
- Masks are unique per position and depend on the canary

### Condition Checks

Each target comparison is in a separate `noinline` function reading from volatile XOR-masked globals:

```c
_chk_a(v): v == (_ekA ^ _omA)    // → 0x1337C0DE
_chk_b(v): v == (_ekB ^ _omB)    // → 0xDEADBEEF
_chk_c(v): v == (_ekC ^ _omC)    // → 0x0BADC0DE
```

No fake obfuscation — the real difficulty is that targets are stored as `value ^ mask` in volatile globals, and the functions are `noinline` so they're separate code blocks.

---

## Solution Approaches

### Static Analysis (Ghidra/IDA)

1. Find `pthread_create` calls → 3 thread entry points
2. In checker thread: find the 3 `_chk_*` noinline calls
3. Each reads two volatile globals and XORs → compute targets
4. Find the constructor that runs the LCG → compute `_timing_canary`
5. Low byte = `0x98`
6. Find `_eflag[]`, `_fbk[]`, `_fbo[]` arrays
7. Decode: `plain[i] = ((eflag[i] - fbo[i]) & 0xFF) ^ fbk[i] ^ 0x98`

### GDB (Dynamic)

```bash
# Bypass ptrace + parent check + timing:
echo 'long ptrace(int a,...){return 0;}' > /tmp/p.c
gcc -shared -o /tmp/p.so /tmp/p.c
LD_PRELOAD=/tmp/p.so gdb ./razz_challenge

# Clear debug poison:
# Find g_debug_detected symbol, set to 0

# Set magic values in g_state:
# key_part1 = 0x1337C0DE
# key_part2 = 0xDEADBEEF
# trigger   = 0x0BADC0DE
# check_count = 5

# Break after flag generation
# Read flag[i] ^ pos_masks[i] for each byte
```

### Binary Patching

1. NOP the 3 constructor anti-debug checks
2. NOP the corruptor pthread_create
3. Wait for mutator to reach targets naturally
4. Dump `flag[]` and `pos_masks[]`, XOR each pair

---

## Challenge Description (for players)

> **RAZZ Security Systems** has deployed a prototype kernel monitoring tool.
> The system appears unstable — threads are behaving unpredictably.
> Your goal is to analyze the binary, understand its internal state, and retrieve the hidden flag.
>
> **Note:** The flag is not stored statically. Anti-tampering measures are active.
