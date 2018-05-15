#ifndef _ETHEREUM_CRYPTO_SHA3_H_
#define _ETHEREUM_CRYPTO_SHA3_H_


#include <stdint.h>
#include <stdlib.h>


int sha3_256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
int sha3_512(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);


#endif
