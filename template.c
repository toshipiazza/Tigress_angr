#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t SECRET(uint64_t);
int main(int argc, char *argv[])
{
    printf("%llu\n", SECRET(strtoul(argv[1], NULL, 10)));
    return 0;
}
