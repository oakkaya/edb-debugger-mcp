#include <stdio.h>
#include <string.h>

int main(void) {
    char input[64];
    printf("Enter password: ");
    fgets(input, 64, stdin);
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, "s3cr3t_p@ssw0rd") == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
