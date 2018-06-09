#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static unsigned int table[256];

/* http://www.hackersdelight.org/hdcodetxt/crc.c.txt */
unsigned int crc32c(unsigned char *message, int len) {
   unsigned int byte, crc, mask;
   /* this is all constant wrt input */
   for (byte = 0; byte <= 255; byte++) {
      crc = byte;
      for (int j = 7; j >= 0; j--) {
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
      table[byte] = crc;
   }
   crc = 0xFFFFFFFF;
   for (int i = 0; i < len; ++i) {
      byte = message[i];
      /* table lookup has symbolic index, exercises symbolic
       * memory subsystem
       */
      crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF];
      i = i + 1;
   }
   return ~crc;
}

uint64_t SECRET(uint64_t input) {
  return (uint64_t)crc32c((unsigned char *)&input, sizeof(input));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Call this program with 1 arguments\n");
        return 1;
    }
    printf("%lu\n", SECRET(strtoul(argv[1], 0, 10)));
    return 0;
}
