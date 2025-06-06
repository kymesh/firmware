// #ifndef PQCLEAN_RANDOMBYTES_H
// #define PQCLEAN_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


#include <unistd.h>

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif

// #endif /* PQCLEAN_RANDOMBYTES_H */
