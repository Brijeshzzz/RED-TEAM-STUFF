# 🔐 CTF Challenge: Locked Flag Vault
### "Parent/Child Process Escape"

---

## 📌 What is this?

This is a **CTF (Capture The Flag)** challenge built in C that demonstrates:
- XOR encoding to hide secrets inside a binary
- Anti-debug self-destruct trap using `SIGKILL`
- Reverse engineering using GDB
- Exploiting the trap using **Parent/Child Process + Pipe IPC**

---

## 📁 Files

| File | Purpose |
|------|---------|
| `challenge.c` | The locked vault — contains hidden flag and password |
| `solver.c` | The exploit — uses parent/child process to capture the flag |
| `Makefile` | Build system |

---

## 🔧 How to Build

```bash
make
```

This compiles both `challenge` and `solver` binaries.

---

## 🎯 The Challenge Flow

### Step 1 — Try the vault manually
```bash
./challenge
```
- Wrong password → `Access denied`
- Correct password → flag flashes → **process KILLS ITSELF** 💀

### Step 2 — Reverse engineer using GDB to find the password
```bash
gdb ./challenge
```

Inside GDB:
```bash
break check_password
run
```
Type any fake password (e.g. `hello`), then:
```bash
disassemble check_password
```
Find the `strcmp` address in the output. strcmp = a built-in C function that compares two strings — if they match it returns 0 (correct password), if they don't match it returns non-zero (wrong password)! It looks like:
```
0x00005555555552ab <+55>: callq strcmp@plt   ← note this address!
```

Set breakpoint exactly there:
```bash
break *0x00005555555552ab
continue

When you ran disassemble inside GDB, it showed this:
asm0x555555555284 <+16>:  encoded_pass → load password
0x555555555298 <+36>:  call decode       → decode password  
0x5555555552ab <+55>:  call strcmp@plt   ← THIS LINE!
0x5555555552b0 <+60>:  test %eax,%eax

We just looked for the line that said strcmp in the disassemble output!
That address 0x5555555552ab is simply the memory location of that strcmp instruction in RAM.

Simple analogy:

Disassemble = book
Every instruction = one line in the book
Address = page number
We just found the page number where strcmp is written!

So break *0x5555555552ab means:

"Stop the program exactly at the strcmp page number"

At that exact moment — password is decoded and sitting in $rsi ready to be compared!

```
Type fake password again, then read the real password from memory:
```bash
x/s $rsi
```
```At the time strcmp is called, the CPU loads both strings into registers:
$rdi = your input      (what YOU typed)
$rsi = real password   (what PROGRAM expects)
So we do x/s $rsi because:

x = examine memory
s = as a string
$rsi = the register holding the real password


Simple analogy:

strcmp is like a security guard comparing two ID cards
$rdi = your fake ID
$rsi = the real ID in his hand
We just looked at his ID ($rsi) to copy it!
```

**Real password appears!** ✅

### Step 3 — Enter correct password (watch it die!)
```bash
./challenge
```
Enter the real password → flag flashes → `zsh: killed` 💀

### Step 4 — Exploit using Parent/Child process
```bash
./solver
```
**FLAG captured!** ✅

---

## 🧠 How the Exploit Works

```
PARENT                          CHILD
  │                               │
  ├── fork() ────────────────────►│
  │                               │
  ├── write password ────tube1───►│ reads password
  │                               │ runs challenge
  │                               │ prints FLAG → tube2
  │                               │ SIGKILL 💀 dies
  │◄──────────tube2───────────────│
  │ reads FLAG from tube2         X (dead)
  │
  └── FLAG{p4r3nt_ch1ld_m4st3r} ✅
```

### Why it works:
- `fork()` creates a child process that runs the challenge
- Both processes communicate through **pipes** (kernel-managed tubes)
- Child prints the flag into the pipe buffer, then kills itself
- **Pipe buffer survives process death** — it is owned by the kernel, not the child
- Parent reads the flag from the buffer after child is dead ✅

---

## 🔬 Technical Concepts Covered

| Concept | Where Used |
|--------|-----------|
| XOR Encoding | Hiding flag and password in binary |
| Static Analysis | `strings` command on binary |
| Dynamic Analysis | GDB breakpoints and memory inspection |
| x86-64 Registers | `$rdi`, `$rsi` at strcmp call |
| `fork()` | Creating child process |
| `execl()` | Running challenge inside child |
| `pipe()` | IPC between parent and child |
| `dup2()` | Redirecting stdin/stdout to pipes |
| `SIGKILL` | Signal 9 — force kill, cannot be caught |
| `waitpid()` | Parent waiting for child death |
| Pipe Buffer | Kernel buffer that survives process death |

---

## 🔑 Spoilers (don't look before trying!)

<details>
<summary>Click to reveal</summary>

- **Password**: `0p3n_s3sam3`
- **Flag**: `FLAG{p4r3nt_ch1ld_m4st3r}`
- **XOR Key**: `0x5A`
- **strcmp address**: `0x00005555555552ab` (may vary on your system)

</details>

---

## 💡 Key Takeaway

> The anti-debug trap (`SIGKILL`) assumes output goes to a terminal the process controls.
> By redirecting stdout to a **pipe controlled by the parent**, the flag escapes before SIGKILL executes.
> **Pipe buffers are kernel objects — they don't die with the process!**

---

## 🛠️ Requirements

- Linux (Kali / Ubuntu recommended)
- GCC: `sudo apt install gcc`
- GDB: `sudo apt install gdb`

---

## 👨‍💻 Author

Made for learning ethical hacking, binary exploitation, and Unix process management.