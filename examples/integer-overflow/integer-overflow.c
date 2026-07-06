#include <stdio.h>
#include <string.h>

void win(void) {
    printf("YOU WIN!\n");
}

int main(void) {
    int idx;
    char buf[64];

    printf("Index: ");
    if (scanf("%d", &idx) != 1) return 1;

    if (idx > 64) {
        printf("Out of bounds!\n");
        return 1;
    }

    printf("Writing at buf[%d] (%p)\n", idx, &buf[idx]);
    buf[idx] = 0;
    win();
    return 0;
}
