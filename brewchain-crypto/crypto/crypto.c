#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "utils.h"
#include "secp256.h"
#include "rlp/rlp.h"
#include "sha256/sha256.h"


void *create_context(void)
{
    return (void *)secp256_create_context();
}


void destroy_context(void *context)
{
    secp256_destroy_context((secp256k1_context *)context);
}


int generate_prikey_by_random(const void *context,
                   uint8_t *prikey, size_t keylen)
{
    return secp256_generate_prikey_by_random(
            (const secp256k1_context *)context,
            prikey, keylen);
}


int generate_pubkey_by_prikey(const void *context, 
                   uint8_t *prikey, size_t prklen,
                   uint8_t *pubkey, size_t pbklen)
{
    return secp256_generate_pubkey_by_prikey(
            (const secp256k1_context *)context, 
            prikey, prklen, pubkey, pbklen);
}


int generate_address_by_prikey(const void *context,
                    uint8_t *prikey, size_t keylen,
                    uint8_t *address, size_t addrlen)
{
    return secp256_generate_address_by_prikey(
            (const secp256k1_context *)context,
            prikey, keylen, address, addrlen);
}


int generate_address_by_pubkey(uint8_t *pubkey, size_t keylen,
                               uint8_t *address, size_t addrlen)
{
    return secp256_generate_address_by_pubkey(
            pubkey, keylen, address, addrlen);
}


int create_account(const void *context,
        uint8_t *prikey, size_t prilen,
        uint8_t *pubkey, size_t publen,
        uint8_t *address, size_t addrlen)
{
    uint8_t prikey_bytes[32];
    uint8_t pubkey_bytes[65];
    uint8_t address_bytes[20];

    if (context == NULL
            || prikey == NULL
            || prilen < 65
            || pubkey == NULL
            || publen < 131
            || address == NULL
            || addrlen < 41) {
        return 0;
    }

    if (!secp256_generate_prikey_by_random(
                (const secp256k1_context *)context,
                prikey_bytes, 32)) {
        return 0;
    }

    if (!secp256_generate_pubkey_by_prikey(
                (const secp256k1_context *)context,
                prikey_bytes, 32, pubkey_bytes, 65)) {
        return 0;
    }

    if (!secp256_generate_address_by_pubkey(
                pubkey_bytes, 64, address_bytes, 20)) {
        return 0;
    }

    bytes_to_hex(prikey_bytes, 32, (char *)prikey);
    bytes_to_hex(pubkey_bytes, 65, (char *)pubkey);
    bytes_to_hex(address_bytes, 20, (char *)address);

    return 1;
}


int recover_account(const void *context,
        uint8_t *prikey, size_t prilen,
        uint8_t *pubkey, size_t publen,
        uint8_t *address, size_t addrlen)
{
    uint8_t prikey_bytes[32];
    uint8_t pubkey_bytes[65];
    uint8_t address_bytes[20];

    if (context == NULL
            || prikey == NULL
            || prilen < 64
            || pubkey == NULL
            || publen < 131
            || address == NULL
            || addrlen < 41) {
        return 0;
    }

    hex_to_bytes((const char *)prikey, 64, prikey_bytes, 32);

    if (!secp256_generate_pubkey_by_prikey(
                (const secp256k1_context *)context,
                prikey_bytes, 32, pubkey_bytes, 65)) {
        return 0;
    }

    if (!secp256_generate_address_by_pubkey(
                pubkey_bytes, 64, address_bytes, 20)) {
        return 0;
    }

    bytes_to_hex(pubkey_bytes, 65, (char *)pubkey);
    bytes_to_hex(address_bytes, 20, (char *)address);

    return 1;
}


static int sign_raw_transaction(
        const void *context,
        uint8_t *txhash, size_t hashlen,
        uint8_t *prikey, size_t keylen,
        uint8_t *sigbuf, size_t sigsize)
{
    if (context == NULL
            || txhash == NULL
            || hashlen != 32
            || prikey == NULL
            || keylen != 32
            || sigbuf == NULL
            || sigsize < 65) {
        return 0;
    }

    return secp256_sign_transaction((const secp256k1_context *)context,
            txhash, hashlen, prikey, keylen, sigbuf, sigsize);
}


int verify_signature(const void *context,
        uint8_t *msghash, size_t msglen,
        uint8_t *sigdata, size_t siglen)
{
    uint8_t pubkey[65];

    if (context == NULL
            || msghash == NULL
            || msglen != 32
            || sigdata == NULL
            || siglen != 65) {
        return 0;
    }

    if (secp256_recover_pubkey((const secp256k1_context *)context,
                msghash, msglen, sigdata, siglen, pubkey, 65) == 0) {
        return 0;
    }

    return secp256_verify_signature((const secp256k1_context *)context,
            pubkey, 65, msghash, msglen, sigdata, 64);
}


static void assemble_raw_transaction(
        const char *nonce,
        const char *to,
        const char *gas_price,
        const char *gas_limit,
        const char *value,
        const char *data,
        EthereumSignTx *tx)

{
    uint32_t nonce_length;
    uint32_t nonce_bsize;
    uint8_t  nonce_bytes[32];

    uint32_t gasprice_length;
    uint32_t gasprice_bsize;
    uint8_t  gasprice_bytes[32];

    uint32_t gaslimit_length;
    uint32_t gaslimit_bsize;
    uint8_t  gaslimit_bytes[32];

    uint32_t to_length;
    uint32_t to_bsize;
    uint8_t  to_bytes[20];

    uint32_t value_length;
    uint32_t value_bsize;
    uint8_t  value_bytes[32];

    uint32_t data_length;
    uint32_t data_bsize;
    uint8_t  data_bytes[1024];

    memset(tx, 0, sizeof(EthereumSignTx));

    //nonce
    nonce_length = strlen(nonce);
    nonce_bsize = size_of_bytes(nonce_length);
    hex_to_bytes(nonce, nonce_length, nonce_bytes, 32);
    rlp_encode_element(nonce_bytes, nonce_bsize, tx->nonce.bytes, &tx->nonce.size);

    //gas_price
    gasprice_length = strlen(gas_price);
    gasprice_bsize = size_of_bytes(gasprice_length);
    hex_to_bytes(gas_price, gasprice_length, gasprice_bytes, 32);
    rlp_encode_element(gasprice_bytes, gasprice_bsize, tx->gas_price.bytes, &tx->gas_price.size);

    //gas_limit
    gaslimit_length = strlen(gas_limit);
    gaslimit_bsize = size_of_bytes(gaslimit_length);
    hex_to_bytes(gas_limit, gaslimit_length, gaslimit_bytes, 32);
    rlp_encode_element(gaslimit_bytes, gaslimit_bsize, tx->gas_limit.bytes, &tx->gas_limit.size);

    //to: destination address
    to_length = strlen(to);
    to_bsize = size_of_bytes(to_length);
    hex_to_bytes(to, to_length, to_bytes, 20);
    rlp_encode_element(to_bytes, to_bsize, tx->to.bytes, &tx->to.size);

    //value: coin, unit: Wei
    value_length = strlen(value);
    value_bsize = size_of_bytes(value_length);
    hex_to_bytes(value, value_length, value_bytes, 32);
    rlp_encode_element(value_bytes, value_bsize, tx->value.bytes, &tx->value.size);

    //data: additional data
    data_length = strlen(data);
    data_bsize = size_of_bytes(data_length);
    hex_to_bytes(data, data_length, data_bytes, 1024);
    rlp_encode_element(data_bytes, data_bsize, tx->data_initial_chunk.bytes, &tx->data_initial_chunk.size);
}


static void assemble_raw_signature(
        const char *signature_r,
        const char *signature_s,
        const uint32_t signature_v,
        EthereumSig *sig)
{
    uint32_t signature_r_length;
    uint32_t signature_r_bsize;
    uint8_t  signature_r_bytes[64];

    uint32_t signature_s_length;
    uint32_t signature_s_bsize;
    uint8_t  signature_s_bytes[64];

    memset(sig, 0, sizeof(EthereumSig));

    //signature - V
    rlp_encode_int(signature_v, (uint8_t *)&sig->signature_v);

    //signature - R
    signature_r_length = strlen(signature_r);
    signature_r_bsize = size_of_bytes(signature_r_length);
    hex_to_bytes(signature_r, signature_r_length, signature_r_bytes, 64);
    rlp_encode_element(signature_r_bytes, signature_r_bsize, sig->signature_r.bytes, &sig->signature_r.size);

    //signature - S
    signature_s_length = strlen(signature_s);
    signature_s_bsize = size_of_bytes(signature_s_length);
    hex_to_bytes(signature_s, signature_s_length, signature_s_bytes, 64);
    rlp_encode_element(signature_s_bytes, signature_s_bsize, sig->signature_s.bytes, &sig->signature_s.size);
}


int sign_transaction(
        const void *context,
        const char *prikey,
        const char *nonce,
        const char *to,
        const char *gas_price,
        const char *gas_limit,
        const char *value,
        const char *data,
        uint8_t *sigbuf)
{
    uint32_t prikey_length;
    uint8_t prikey_bytes[32];

    int rlp_raw_tx_len;
    uint8_t rlp_raw_tx_bytes[4096];
    uint8_t rlp_raw_tx_hash[32];
    char rlp_raw_tx_hash_hex[65];
    uint8_t rlp_raw_tx_sig[65];
    char rlp_raw_tx_sig_hex[131];

    char rlp_raw_tx_sig_r[65];
    char rlp_raw_tx_sig_s[65];
    uint32_t rlp_raw_tx_sig_v;

    int rlp_tx_sig_len;
    uint8_t rlp_tx_sig_bytes[4096];
    char rlp_tx_sig_hex[8192];

    EthereumSignTx rlp_raw_tx;
    EthereumSig rlp_raw_sig;

    prikey_length = strlen(prikey);
    if (prikey_length != 64) {
        return 0;
    }

    hex_to_bytes(prikey, prikey_length, prikey_bytes, 32);

    assemble_raw_transaction(nonce, to, gas_price, gas_limit, value, data, &rlp_raw_tx);
    rlp_raw_tx_len = rlp_encode_tx_list(&rlp_raw_tx, (uint64_t *)rlp_raw_tx_bytes);
    //sha3_256(rlp_raw_tx_hash, 32, rlp_raw_tx_bytes, rlp_raw_tx_len);
    sha256_hash(rlp_raw_tx_hash, rlp_raw_tx_bytes, rlp_raw_tx_len);
    bytes_to_hex(rlp_raw_tx_hash, 32, rlp_raw_tx_hash_hex);
    //printf("rlp_raw_tx_hash_hex: %s\n", rlp_raw_tx_hash_hex);

    sign_raw_transaction(context, rlp_raw_tx_hash, 32, prikey_bytes, 32, rlp_raw_tx_sig, 65);
    bytes_to_hex(rlp_raw_tx_sig, 65, rlp_raw_tx_sig_hex);
    //printf("rlp_raw_tx_sig_hex: %s\n", rlp_raw_tx_sig_hex);

    bytes_to_hex(rlp_raw_tx_sig, 32, rlp_raw_tx_sig_r);
    bytes_to_hex(rlp_raw_tx_sig + 32, 32, rlp_raw_tx_sig_s);
    rlp_raw_tx_sig_v = rlp_raw_tx_sig[64] + 27;

    assemble_raw_signature(rlp_raw_tx_sig_r, rlp_raw_tx_sig_s, rlp_raw_tx_sig_v, &rlp_raw_sig);
    rlp_tx_sig_len = rlp_encode_list(&rlp_raw_tx, &rlp_raw_sig, (uint64_t *)rlp_tx_sig_bytes);
    bytes_to_hex(rlp_tx_sig_bytes, rlp_tx_sig_len, rlp_tx_sig_hex);
    //printf("rlp_tx_sig_hex: %s\n", rlp_tx_sig_hex);

    memcpy(sigbuf, rlp_tx_sig_hex, strlen(rlp_tx_sig_hex) + 1);

#if 0
    if (verify_signature(context, rlp_raw_tx_hash, 32, rlp_raw_tx_sig, 65)) {
        printf("verify_signature OK\n");
    } else {
        printf("verify_signature failed\n");
    }
#endif

    return 1;
}
