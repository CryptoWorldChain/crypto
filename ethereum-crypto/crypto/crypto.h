#ifndef _ETHEREUM_CRYPTO_H_
#define _ETHEREUM_CRYPTO_H_


#include <stdint.h>
#include <stdlib.h>


extern void *create_context(void);

extern void destroy_context(void *context);

extern int generate_prikey_by_random(const void *context,
                          uint8_t *prikey, size_t keylen);

extern int generate_pubkey_by_prikey(const void *context, 
                          uint8_t *prikey, size_t prklen,
                          uint8_t *pubkey, size_t pbklen);

extern int generate_address_by_prikey(const void *context,
                           uint8_t *prikey, size_t keylen,
                           uint8_t *address, size_t addrlen);

extern int generate_address_by_pubkey(uint8_t *pubkey,
                      size_t keylen, uint8_t *address,
                      size_t addrlen);

extern int create_account(const void *context,
               uint8_t *prikey, size_t prilen,
               uint8_t *pubkey, size_t publen,
               uint8_t *address, size_t addrlen);

extern int recover_account(const void *context,
                uint8_t *prikey, size_t prilen,
                uint8_t *pubkey, size_t publen,
                uint8_t *address, size_t addrlen);

extern int sign_transaction(
        const void *context,
        const char *prikey,
        const char *nonce,
        const char *to,
        const char *gas_price,
        const char *gas_limit,
        const char *value,
        const char *data,
        uint8_t *sigbuf);

extern int verify_signature(const void *context,
                uint8_t *msghash, size_t msglen,
                uint8_t *sigdata, size_t siglen);

#if 0
extern int sign_tx(const char *nonce,
        const char *to,
        const char *gas_price,
        const char *gas_limit,
        const char *value,
        const char *data,
        uint8_t *rlp_tx);

extern int sign_tx_sig(const char *nonce,
        const char *to,
        const char *gas_price,
        const char *gas_limit,
        const char *value,
        const char *data,
        const char *sig_r,
        const char *sig_s,
        const uint32_t sig_v,
        uint8_t *rlp_tx);
#endif


#endif
