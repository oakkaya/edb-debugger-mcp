#include <stdio.h>
#include <string.h>

int main(void) {
    char password[8] = "secret!";
    char input[8];
    int authenticated = 0;

    printf("Enter password: ");
    read(0, input, 9);
    if (strncmp(input, password, 8) == 0)
        authenticated = 1;
    if (authenticated)
        printf("Access granted!\n");
    else
        printf("Access denied.\n");
    return 0;
}
