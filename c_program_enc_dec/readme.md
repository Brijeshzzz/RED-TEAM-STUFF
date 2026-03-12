# C Program that Encrypts or Decrypts Files with AES

A command-line tool written in C that encrypts and decrypts files using **AES-256-GCM** and **AES-256-CBC** modes via the OpenSSL library. The AES key and IV are derived from a user-provided password using SHA-256 hashing.

---

## Features

- AES-256-GCM encryption with authentication tag (tamper detection)
- AES-256-CBC encryption with PKCS#7 padding
- Password-based key and IV derivation using SHA-256
- Chunk-based file processing (works on large files)
- Clear error messages on wrong password or corrupted file

---

## How It Works

### Password → Key + IV

The user's password is hashed using SHA-256 to produce the key and IV:

```
Key (32 bytes) = SHA-256(password)
IV  (12/16 bytes) = SHA-256("IV" + password)[first N bytes]
```

### File Layout on Disk

**GCM:**
```
[ IV (12 bytes) | Auth Tag (16 bytes) | Ciphertext ]
```

**CBC:**
```
[ IV (16 bytes) | Ciphertext (PKCS#7 padded) ]
```

---

## Requirements

- GCC compiler
- OpenSSL library

Install OpenSSL on Kali/Debian:
```bash
sudo apt install libssl-dev
```

---

## Compile

```bash
gcc code.c -o aes_crypt -lssl -lcrypto
```

---

## Usage

```bash
# Encrypt with GCM
./aes_crypt enc gcm <password> <input_file> <output_file>

# Decrypt with GCM
./aes_crypt dec gcm <password> <input_file> <output_file>

# Encrypt with CBC
./aes_crypt enc cbc <password> <input_file> <output_file>

# Decrypt with CBC
./aes_crypt dec cbc <password> <input_file> <output_file>
```

---

## Example

```bash
# Create a test file
echo "Hello this is my secret message" > input.txt

# Encrypt
./aes_crypt enc gcm mypassword input.txt encrypted.bin

# Decrypt
./aes_crypt dec gcm mypassword encrypted.bin output.txt

# Verify
cat output.txt
# Output: Hello this is my secret message
```

---

## GCM vs CBC

| Feature | AES-GCM | AES-CBC |
|---|---|---|
| Confidentiality | Yes | Yes |
| Tamper Detection | Yes (Auth Tag) | No |
| Recommended | Yes | Legacy only |

> GCM is preferred — it detects wrong passwords and file corruption immediately via the authentication tag.

---

## Project Structure

```
c_program_enc_dec/
├── code.c       → Main source code
├── aes_crypt    → Compiled binary
├── input.txt    → Sample plaintext
├── encrypted.bin→ Encrypted output
├── output.txt   → Decrypted output
└── README.md    → This file
```

---

## Author

**Brijesh Babu S K**
- GitHub: [github.com/Brijeshzzz](https://github.com/Brijeshzzz)
- LinkedIn: [linkedin.com/in/brijeshbabusk](https://linkedin.com/in/brijeshbabusk)
- Portfolio: [brijeshbabuk.vercel.app](https://brijeshbabuk.vercel.app)
- YouTube: [youtube.com/@Brijeshzeroday](https://youtube.com/@Brijeshzeroday)


# AES File Encryption / Decryption — Code Explanation

This program encrypts and decrypts files using **AES-256** with the **OpenSSL** library.
It supports two modes:

* AES-GCM (modern and secure)
* AES-CBC (older but still common)

The encryption **key and IV are derived from the user password using** SHA-256.

---

# 1. Required Libraries

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
```

Purpose of each library:

| Library      | Purpose                       |
| ------------ | ----------------------------- |
| stdio        | File reading and writing      |
| stdlib       | Memory and exit handling      |
| string       | String operations             |
| openssl/evp  | AES encryption and decryption |
| openssl/sha  | SHA-256 hashing               |
| openssl/rand | Random values                 |
| openssl/err  | OpenSSL error messages        |

---

# 2. Important Constants

```c
#define KEY_LEN       32
#define IV_LEN_CBC    16
#define IV_LEN_GCM    12
#define GCM_TAG_LEN   16
#define BUFFER_SIZE   4096
```

Explanation:

| Constant    | Meaning                            |
| ----------- | ---------------------------------- |
| KEY_LEN     | AES-256 requires a **32-byte key** |
| IV_LEN_CBC  | CBC mode uses a **16-byte IV**     |
| IV_LEN_GCM  | GCM mode uses a **12-byte IV**     |
| GCM_TAG_LEN | Authentication tag size            |
| BUFFER_SIZE | Size used when reading file chunks |

---

# 3. Error Handling Function

```c
static void handle_errors(const char *msg)
```

This function is used whenever OpenSSL fails.

It will:

1. Print an error message
2. Print OpenSSL error details
3. Stop the program

This prevents the program from continuing after a cryptographic failure.

---

# 4. Password → Key + IV

```c
static void derive_key_iv(...)
```

This function converts the **user password into a cryptographic key and IV**.

Steps:

1. Hash the password using SHA-256

```
password → SHA-256 → 32-byte hash
```

2. Use the hash as the AES key

```
key = SHA-256(password)
```

3. Generate the IV from another hash

```
IV = SHA-256("IV" + password)
```

Only the required number of bytes are taken.

Flow:

```
User Password
      ↓
SHA-256
      ↓
Key + IV
```

---

# 5. AES-GCM Encryption

Function:

```c
encrypt_gcm()
```

This encrypts a file using **AES-256-GCM**.

File format produced:

```
[ IV | Authentication Tag | Ciphertext ]
```

Steps:

1. Generate key and IV from password
2. Open input and output files
3. Write IV to output file
4. Reserve space for authentication tag
5. Start AES encryption
6. Read the file in chunks
7. Encrypt each chunk
8. Finish encryption
9. Retrieve authentication tag
10. Write the tag into the output file

Result:

```
plain.txt → cipher.bin
```

---

# 6. AES-GCM Decryption

Function:

```c
decrypt_gcm()
```

Reads the encrypted file and restores the original file.

File structure expected:

```
[ IV | Authentication Tag | Ciphertext ]
```

Steps:

1. Read IV from file
2. Read authentication tag
3. Derive key from password
4. Start AES decryption
5. Decrypt file chunks
6. Verify authentication tag

If verification fails:

```
Authentication FAILED — wrong password or corrupted file
```

This protects against **tampered data**.

---

# 7. AES-CBC Encryption

Function:

```c
encrypt_cbc()
```

This encrypts a file using **AES-256-CBC**.

File format produced:

```
[ IV | Ciphertext ]
```

Steps:

1. Generate key and IV
2. Write IV to output file
3. Start AES encryption
4. Read input file in chunks
5. Encrypt each chunk
6. Finalize encryption (adds padding)

Result:

```
plain.txt → cipher.bin
```

---

# 8. AES-CBC Decryption

Function:

```c
decrypt_cbc()
```

Steps:

1. Read IV from the encrypted file
2. Generate key from password
3. Start decryption
4. Decrypt file chunks
5. Remove padding
6. Restore original file

If password is wrong or data is corrupted:

```
Decryption FAILED
```

---

# 9. Main Function

```c
int main(int argc, char *argv[])
```

This is the **entry point of the program**.

It reads the command arguments and decides what operation to perform.

Example command:

```
./aes_crypt enc gcm mypass file.txt file.enc
```

Arguments:

| Argument | Meaning         |
| -------- | --------------- |
| enc      | Encrypt         |
| dec      | Decrypt         |
| gcm      | AES-GCM mode    |
| cbc      | AES-CBC mode    |
| password | User password   |
| input    | File to process |
| output   | Result file     |

Based on the input, `main()` calls the correct function:

```
enc gcm → encrypt_gcm()
dec gcm → decrypt_gcm()
enc cbc → encrypt_cbc()
dec cbc → decrypt_cbc()
```

---

# 10. Complete Program Flow

```
User Command
     ↓
main()
     ↓
derive_key_iv()
     ↓
AES Encryption or Decryption
     ↓
File Written to Disk
```

---

# Final Summary

This program:

1. Takes a **user password**
2. Converts it into a cryptographic key using **SHA-256**
3. Uses that key to encrypt or decrypt files with **AES-256**
4. Supports both **AES-GCM** and **AES-CBC** modes
5. Stores necessary information (IV and tag) inside the encrypted file so it can be decrypted later.

## Changes Made

### Problem
`handle_errors()` was calling `exit()` directly without freeing resources — causing memory and file handle leaks.

### Fix
Replaced `handle_errors()` with `cleanup_and_die()` which properly frees all resources before exit.

**Old:**
```c
static void handle_errors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}
```

**New:**
```c
static void cleanup_and_die(const char *msg, EVP_CIPHER_CTX *ctx, FILE *fin, FILE *fout) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    if (ctx)  EVP_CIPHER_CTX_free(ctx);
    if (fin)  fclose(fin);
    if (fout) fclose(fout);
    exit(EXIT_FAILURE);
}
```

Every error call updated from `handle_errors("msg")` to `cleanup_and_die("msg", ctx, fin, fout)` so ctx and file handles are always closed before exit.
