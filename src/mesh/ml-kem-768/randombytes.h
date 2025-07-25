#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <unistd.h>

/*
 * Write `n` bytes of high quality random data to `buf`.
 */
int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif