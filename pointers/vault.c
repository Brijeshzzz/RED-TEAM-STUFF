#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// ═══════════════════════════════════════
//   VAULT — Security System v1.0
//   Normal users never get past Layer 1
// ═══════════════════════════════════════

// Hidden functions — never called normally
void layer1_win() {
    printf("\n[+] LAYER 1 BREACHED — Buffer overflow success!\n");
}

void layer2_win() {
    printf("[+] LAYER 2 BREACHED — Function pointer hijacked!\n");
}

void layer3_win() {
    printf("[+] LAYER 3 BREACHED — Hidden function found!\n");
}

void print_flag() {
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  FLAG{y0u_pwn3d_th3_vault_l1k3_pr0}  ║\n");
    printf("╚══════════════════════════════════════╝\n");
}

// ═══════════════════════
//   LAYER 2 — Function pointer hijack
// ═══════════════════════
void access_denied() {
    printf("[-] ACCESS DENIED\n");
}

void layer2_challenge() {
    char buffer[32];
    void (*func_ptr)();

    func_ptr = access_denied;

    printf("\n[VAULT] Enter access code: ");
    fflush(stdout);
    read(0, buffer, 200);

    func_ptr();
}

// ═══════════════════════
//   LAYER 1 — Basic overflow
// ═══════════════════════
void layer1_challenge() {
    char buffer[64];
    int auth = 0xdeadbeef;

    printf("\n[VAULT] Enter password: ");
    fflush(stdout);
    read(0, buffer, 200);

    if (auth == 0xcafebabe) {
        layer1_win();
    } else {
        printf("[-] Auth failed. auth = 0x%x\n", auth);
    }
}

// ═══════════════════════
//   LAYER 3 — ret2win
// ═══════════════════════
void layer3_challenge() {
    char buffer[48];

    printf("\n[VAULT] Enter vault key: ");
    fflush(stdout);
    read(0, buffer, 200);

    printf("[*] Processing...\n");
}

// ═══════════════════════
//   MAIN MENU
// ═══════════════════════
int main() {
    int choice;

    printf("╔══════════════════════════════╗\n");
    printf("║     VAULT SECURITY SYSTEM    ║\n");
    printf("║         v1.0 — SECURE        ║\n");
    printf("╚══════════════════════════════╝\n");

    printf("\n[1] Password Check\n");
    printf("[2] Access Code\n");
    printf("[3] Vault Key\n");
    printf("Choice: ");
    scanf("%d", &choice);
    getchar();

    if (choice == 1) layer1_challenge();
    else if (choice == 2) layer2_challenge();
    else if (choice == 3) layer3_challenge();
    else printf("[-] Invalid choice\n");

    return 0;
}
