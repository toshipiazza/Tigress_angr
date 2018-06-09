#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t SECRET(uint64_t input) {
    int i = 0;
    /* Exercise support for multiple symbolic branches;
     * this branch can happen at most ~6 times so it's
     * still a tractable example.
     */
    while (input /= 2048)
        i += 1;
    return i;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Call this program with 1 arguments\n");
        return 1;
    }
    printf("%lu\n", SECRET(strtoul(argv[1], 0, 10)));
    return 0;
}
