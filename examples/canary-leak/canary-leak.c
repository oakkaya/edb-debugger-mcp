#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    printf("WIN!\n");
}

void vuln(void) {
    char buf[64];
    printf("Data: ");
    read(0, buf, 128);
    printf("You said: ");
    printf(buf);
    printf("\n");
}

int main(void) {
    vuln();
    return 0;
}
