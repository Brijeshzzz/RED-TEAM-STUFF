#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <signal.h>

/*
 * CTF SOLVER - Parent/Child Process Technique
 * 
 * HOW IT WORKS:
 * 1. Parent forks a child
 * 2. Child runs the challenge program
 * 3. Parent uses ptrace to TRACE the child
 * 4. When child tries to kill itself (SIGKILL on correct password),
 *    parent intercepts and reads memory to extract the flag
 *
 * ALTERNATIVE APPROACH (simpler, shown here):
 * Parent forks child, child runs challenge with correct password via pipe,
 * parent intercepts the output BEFORE the kill completes by reading
 * from child's stdout pipe rapidly.
 *
 * THE TRICK: The challenge kills itself with SIGKILL *after* printing.
 * So parent reads the pipe output before child dies.
 */

int main() {
    int pipe_stdin[2];   // Parent writes password -> Child reads
    int pipe_stdout[2];  // Child writes output -> Parent reads

    if (pipe(pipe_stdin) < 0 || pipe(pipe_stdout) < 0) {
        perror("pipe");
        exit(1);
    }

    printf("[*] CTF Solver using Parent/Child Process Technique\n");
    printf("[*] Forking child process to run challenge...\n\n");

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        // ===== CHILD PROCESS =====
        // Redirect stdin/stdout through pipes
        dup2(pipe_stdin[0], STDIN_FILENO);
        dup2(pipe_stdout[1], STDOUT_FILENO);
        dup2(pipe_stdout[1], STDERR_FILENO);

        // Close unused ends
        close(pipe_stdin[1]);
        close(pipe_stdout[0]);

        // Execute the challenge
        execl("./challenge", "./challenge", NULL);
        perror("execl failed");
        exit(1);

    } else {
        // ===== PARENT PROCESS =====
        // Close unused ends
        close(pipe_stdin[0]);
        close(pipe_stdout[1]);

        // Give child time to start and print banner
        usleep(100000); // 100ms

        // Send the correct password to the child
        // Password discovered via reverse engineering: "0p3n_s3sam3"
        printf("[*] Parent sending cracked password to child...\n");
        const char *password = "0p3n_s3sam3\n";
        write(pipe_stdin[1], password, strlen(password));
        close(pipe_stdin[1]);

        // Read ALL output from child BEFORE it dies
        // The child prints the flag then kills itself
        // Parent reads the pipe which buffers the output
        char buffer[4096];
        int total = 0;
        int n;

        // Read in a loop to get all output
        while ((n = read(pipe_stdout[0], buffer + total, sizeof(buffer) - total - 1)) > 0) {
            total += n;
        }
        buffer[total] = '\0';
        close(pipe_stdout[0]);

        // Wait for child (it will be dead from SIGKILL)
        int status;
        waitpid(pid, &status, 0);

        if (WIFSIGNALED(status)) {
            printf("[*] Child was killed by signal %d (as expected - anti-debug trap!)\n", WTERMSIG(status));
        }

        printf("\n[PARENT CAPTURED OUTPUT FROM CHILD]:\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("%s", buffer);
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        // Extract just the flag line
        char *flag_line = strstr(buffer, "[FLAG UNLOCKED]");
        if (flag_line) {
            char *end = strchr(flag_line, '\n');
            if (end) *end = '\0';
            printf("[+] SUCCESS! FLAG CAPTURED: %s\n", flag_line);
        } else {
            printf("[-] Flag not found in output. Try again.\n");
        }
    }

    return 0;
}
