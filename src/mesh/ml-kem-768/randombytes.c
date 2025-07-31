#include "randombytes.h"
#include <Arduino.h>

/*
 * Write `n` bytes of high quality random data to `buf`.
 */
int randombytes(uint8_t *output, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        output[i] = (uint8_t)random();
    }
    return 0;
}