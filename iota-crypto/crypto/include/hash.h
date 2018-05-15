#ifndef _IOTA_CRYPTO_HASH_H_
#define _IOTA_CRYPTO_HASH_H_


#include <unistd.h>
#include <stdint.h>

#define HASH_LENGTH 243
#define STATE_LENGTH 3 * HASH_LENGTH
#define TRYTE_LENGTH 2673
#define TRANSACTION_LENGTH TRYTE_LENGTH * 3
typedef int64_t trit_t;

#ifndef DEBUG
#define DEBUG
#endif // DEBUG


#endif
