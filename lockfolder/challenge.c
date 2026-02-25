#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

// The flag is XOR-encoded so it's not plain text in binary
// Key = 0x5A
static unsigned char encoded_flag[] = {
    0x1c,0x16,0x1b,0x1d,0x21,0x2a,0x6e,0x28,
    0x69,0x34,0x2e,0x05,0x39,0x32,0x6b,0x36,
    0x3e,0x05,0x37,0x6e,0x29,0x2e,0x69,0x28,
    0x27
};

// Password is also hidden
// Real password: "0p3n_s3sam3"
static unsigned char encoded_pass[] = {
    0x6a,0x2a,0x69,0x34,0x05,0x29,0x69,0x29,
    0x3b,0x37,0x69,0x00
};

void decode(unsigned char *enc, int len, char *out, unsigned char key) {
    for (int i = 0; i < len; i++) {
        out[i] = enc[i] ^ key;
    }
    out[len] = '\0';
}

int is_running_in_pipe() {
    // Check if stdout is a pipe (solver) or a terminal (normal user)
    return !isatty(STDOUT_FILENO);
}

void reveal_flag() {
    char flag[128];
    decode(encoded_flag, 25, flag, 0x5A);
    printf("\n[FLAG UNLOCKED]: %s\n", flag);
    fflush(stdout);
}

int check_password(const char *input) {
    char real_pass[64];
    decode(encoded_pass, 11, real_pass, 0x5A);
    return strcmp(input, real_pass) == 0;
}

void anti_debug_kill() {
    // Only reveal flag if running through a pipe (solver)
    // If running in terminal directly — just die, no flag shown!
    if (is_running_in_pipe()) {
        reveal_flag();
    }

    printf("\n[!] Correct password detected!\n");
    printf("[!] SELF-DESTRUCT INITIATED... Process terminating.\n");
    fflush(stdout);
    kill(getpid(), SIGKILL);  // Kill self
}

int main() {
    char input[256];

    printf("╔══════════════════════════════════════╗\n");
    printf("║       TOP SECRET FILE VAULT          ║\n");
    printf("║   flag.txt - LOCKED & ENCRYPTED      ║\n");
    printf("╚══════════════════════════════════════╝\n\n");
    printf("[*] Enter password to unlock file: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("[-] Read error.\n");
        exit(1);
    }

    // Strip newline
    input[strcspn(input, "\n")] = '\0';

    if (check_password(input)) {
        anti_debug_kill();
    } else {
        printf("[-] Wrong password. Access denied.\n");
        exit(1);
    }

    return 0;
}
