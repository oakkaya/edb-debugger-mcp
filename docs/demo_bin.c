#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret_function() {
    printf("Secret function called!\n");
}

void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("Hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <name>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    return 0;
}
