#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VULN 1: Stack buffer overflow — attacker input is copied into a fixed-size
// stack buffer with no bounds check, corrupting the stack/return address.
void handle_name(const char *input) {
    char name[64];
    strcpy(name, input); // no length check
    printf("hello %s\n", name);
}

// VULN 2: Format string vulnerability — untrusted input is used as the format
// string, enabling memory disclosure and arbitrary writes via %n.
void log_line(const char *user) {
    printf(user); // should be printf("%s", user)
}

// VULN 3: Integer overflow -> undersized allocation -> heap buffer overflow.
char *dup_items(int count, const char *src) {
    char *buf = malloc(count * 16); // count * 16 can wrap to a small value
    memcpy(buf, src, count * 16);   // then this writes far past the allocation
    return buf;
}

// VULN 4: Unbounded read via gets() and shell execution of the result.
void read_cmd(void) {
    char cmd[128];
    gets(cmd);    // no bounds checking whatsoever
    system(cmd);  // and the buffer is executed as a shell command
}

int main(int argc, char **argv) {
    if (argc > 1) {
        handle_name(argv[1]);
        log_line(argv[1]);
    }
    read_cmd();
    return 0;
}
