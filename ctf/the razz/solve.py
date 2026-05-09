#!/usr/bin/env python3
"""
solve.py - Automated static solver for razz_challenge
Zero manual touch: computes the LCG canary and decodes the hardcoded byte arrays.
"""

def compute_timing_canary():
    # The deterministic LCG loop found in the constructor
    x = 0x12345678
    for _ in range(100000):
        # x = (x * 6364136223846793005 + 1442695040888963407)
        x = ((x * 6364136223846793005) + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
    
    # We only need the lowest byte
    return x & 0xFF

def main():
    print("[*] Computing timing canary from LCG...")
    canary_byte = compute_timing_canary()
    print(f"[+] Computed canary byte: 0x{canary_byte:02X}")

    # Extracted from Ghidra .rodata/.data sections
    # _eflag[]
    eflag = [
        0xBF, 0x67, 0x0D, 0xC0, 0x9D, 0x4D, 0xD8, 0xAF, 0x34,
        0xF7, 0x99, 0x50, 0x42, 0x99, 0xEA, 0x05, 0xC5, 0x31,
        0xA1, 0xE3, 0x31, 0xCB, 0x1D, 0x30, 0xD9, 0x18, 0x6B,
        0xB3, 0x4B
    ]
    
    # _fbk[] (XOR keys)
    fbk = [
        0x42, 0x9A, 0xF1, 0x3D, 0x77, 0xBB, 0x2E, 0x55, 0xCC,
        0x11, 0x6F, 0xAA, 0xD3, 0x48, 0x19, 0xE7, 0x5C, 0x83,
        0x64, 0x0B, 0x99, 0x37, 0xFE, 0xC5, 0x2A, 0xDD, 0x8E,
        0x46, 0xA1
    ]
    
    # _fbo[] (Arithmetic offsets)
    fbo = [
         3, -7,  5, -2,  9, -4,  1, -8,  6,
        -3,  7, -1,  4, -9,  2, -6,  8, -5,
         3, -7,  5, -2,  9, -4,  1, -8,  6,
        -3,  7
    ]

    print(f"[*] Decoding {len(eflag)} bytes...")
    flag = ""
    for i in range(len(eflag)):
        # Decode: plain = ((encoded - offset) ^ key ^ canary_byte)
        # We must mask with 0xFF to handle negative offsets properly in Python
        val = ((eflag[i] - fbo[i]) & 0xFF) ^ fbk[i] ^ canary_byte
        flag += chr(val)

    print("\n[+] FLAG RECOVERED SUCCESSFULLY:")
    print("========================================")
    print(flag)
    print("========================================")

if __name__ == "__main__":
    main()
