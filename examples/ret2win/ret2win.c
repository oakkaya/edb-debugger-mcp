#include <stdio.h>
#include <string.h>

void win(void) {
    printf("You win!\n");
}

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(void) {
    vuln("AAAA");
    return 0;
}
