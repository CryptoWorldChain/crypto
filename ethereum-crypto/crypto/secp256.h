#ifndef _ETHEREUM_SECP256_H_
#define _ETHEREUM_SECP256_H_


#include <stdint.h>
#include <stdlib.h>
#include "include/secp256k1.h"


extern secp256k1_context *secp256_create_context(void);

extern void secp256_destroy_context(secp256k1_context *context);

extern int secp256_generate_prikey_by_random(const secp256k1_context *context,
                                             uint8_t *prikey, size_t keylen);

extern int secp256_generate_pubkey_by_prikey(const secp256k1_context *context, 
                                             uint8_t *prikey, size_t prklen,
                                             uint8_t *pubkey, size_t pbklen);

extern int secp256_generate_address_by_prikey(const secp256k1_context *context,
                                              uint8_t *prikey, size_t keylen,
                                              uint8_t *address, size_t addrlen);

extern int secp256_generate_address_by_pubkey(uint8_t *pubkey, size_t keylen,
                                              uint8_t *address, size_t addrlen);

extern int secp256_sign_transaction(const secp256k1_context *context,
                                    uint8_t *msghash, size_t msglen,
                                    uint8_t *prikey, size_t keylen,
                                    uint8_t *sigbuf, size_t sigsize);

extern int secp256_verify_signature(const secp256k1_context *context,
                                    uint8_t *pubkey, size_t keylen,
                                    uint8_t *msghash, size_t msglen,
                                    uint8_t *sigdata, size_t siglen);

extern int secp256_recover_pubkey(const secp256k1_context *context,
                                  uint8_t *msghash, size_t msglen,
                                  uint8_t *sigdata, size_t siglen,
                                  uint8_t *pubkey, size_t keylen);


#endif
