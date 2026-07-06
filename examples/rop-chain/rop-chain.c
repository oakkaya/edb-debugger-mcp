#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    read(0, buf, 256);
}

int main(void) {
    vuln();
    return 0;
}
