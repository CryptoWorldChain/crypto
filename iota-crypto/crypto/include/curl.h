#ifndef _IOTA_CRYPTO_CURL_H_
#define _IOTA_CRYPTO_CURL_H_


#include "hash.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUMBER_OF_ROUNDS 27

typedef struct _Curl { trit_t state[STATE_LENGTH]; } Curl;

extern void init_curl(Curl* ctx);

extern void absorb(Curl* ctx, trit_t* const trits, int offset, int length);
extern void squeeze(Curl* ctx, trit_t* const trits, int offset, int length);
extern void reset(Curl* ctx);


#endif
