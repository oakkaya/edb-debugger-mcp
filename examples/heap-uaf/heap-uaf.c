#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char name[32];
    void (*greet)(void);
} person_t;

void say_hello(void) {
    printf("Hello!\n");
}

void win(void) {
    printf("WIN!\n");
}

int main(void) {
    person_t *p = malloc(sizeof(person_t));
    p->greet = say_hello;

    char *payload = malloc(64);

    free(p);

    printf("Buffer address: %p\n", payload);
    read(0, payload, 64);

    p->greet();
    free(payload);
    return 0;
}
