#ifndef _ETHEREUM_CRYPTO_UTILS_H_
#define _ETHEREUM_CRYPTO_UTILS_H_


#include <stdint.h>


int size_of_bytes(int str_len);
int hex_to_bytes(const char *buf, int len, uint8_t *out, int outbuf_size);
void bytes_to_hex(uint8_t *buffer, int len, char *out);


#endif
