#ifndef _IOTA_CRYPTO_INTERNAL_H_
#define _IOTA_CRYPTO_INTERNAL_H_


#include <curl.h>
#include <stdint.h>


void iota_curl_hash(Curl *curl, trit_t *trits, int offset, int length);
const char *iota_curl_hash_trytes(Curl *curl, const char *trytes, int length);
int8_t *iota_normalize(const char *trytes);
int64_t trits2int(trit_t *trits, int len);


#endif
