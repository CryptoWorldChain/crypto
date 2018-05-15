#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sha256/sha256.h"
#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "src/hash_impl.h"
#include "src/testrand_impl.h"


/**
 * `secp256_create_context` create a secp256k1 context.
 *
 * return NULL:failed; context-pointer:successful
 */
secp256k1_context *secp256_create_context(void)
{
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}


/**
 * `secp256_destroy_context` destroy a secp256k1 context.
 *
 * return void
 */
void secp256_destroy_context(secp256k1_context *context)
{
    secp256k1_context_destroy(context);
}


/**
 * `secp256_sign_transaction` creates a recoverable ECDSA signature.
 * The produced signature is in the 65-byte [R || S || V] format where V is 0 or 1.
 *
 * The caller is responsible for ensuring that msg cannot be chosen
 * directly by an attacker. It is usually preferable to use a cryptographic
 * hash function on any input before handing it to this function.
 *
 * return 0:failed; 1:successful
 */
int secp256_sign_transaction(const secp256k1_context *context,
                             uint8_t *msghash, size_t msglen,
                             uint8_t *prikey, size_t keylen,
                             uint8_t *sigbuf, size_t sigsize)
{
    secp256k1_ecdsa_recoverable_signature raw_sig;
    int recover_id;

    if (context == NULL
            || msghash == NULL
            || msglen != 32
            || prikey == NULL
            || keylen != 32
            || sigbuf == NULL
            || sigsize < 65) {
        return 0;
    }

    if (secp256k1_ec_seckey_verify(context, prikey) != 1) {
        return 0;
    }

    if (!secp256k1_ecdsa_sign_recoverable(context,
                &raw_sig, msghash, prikey,
                secp256k1_nonce_function_rfc6979, NULL)) {
        return 0;
    }

    secp256k1_ecdsa_recoverable_signature_serialize_compact(
            context, sigbuf, &recover_id, &raw_sig);

    sigbuf[64] = (uint8_t)recover_id;

    return 1;
}


/**
 * `secp256_verify_signature` checks that the given pubkey created signature over message.
 * The signature should be in [R || S] format.
 *
 * return 0:failed; 1:successful
 */
int secp256_verify_signature(const secp256k1_context *context,
                             uint8_t *pubkey, size_t keylen,
                             uint8_t *msghash, size_t msglen,
                             uint8_t *sigdata, size_t siglen)
{
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey_tmp;

    if (context == NULL
            || pubkey == NULL
            || keylen == 0
            || msghash == NULL
            || msglen != 32
            || sigdata == NULL
            || siglen != 64) {
        return 0;
    }

    if (!secp256k1_ecdsa_signature_parse_compact(context, &sig, sigdata)) {
        return 0;
    }

    if (!secp256k1_ec_pubkey_parse(context, &pubkey_tmp, pubkey, keylen)) {
        return 0;
    }

    return secp256k1_ecdsa_verify(context, &sig, msghash, &pubkey_tmp);
}


/**
 * `secp256_recover_pubkey` recover the public key from message hash.
 *
 * msg must be the 32-byte hash of the message to be signed.
 * sig must be a 65-byte compact ECDSA signature containing
 * the recovery id as the last element.
 *
 * return 0:failed; 1:successful
 */
int secp256_recover_pubkey(const secp256k1_context *context,
                           uint8_t *msghash, size_t msglen,
                           uint8_t *sigdata, size_t siglen,
                           uint8_t *pubkey, size_t keylen)
{
    secp256k1_ecdsa_recoverable_signature raw_sig;
    secp256k1_pubkey raw_pubkey;
    uint8_t serialized_pubkey[65];
    size_t serialized_keylen = 65;

    if (context == NULL
            || msghash == NULL
            || msglen != 32
            || sigdata == NULL
            || siglen != 65 
            || sigdata[64] >= 4
            || pubkey == NULL
            || keylen < 65) {
        return 0;
    }

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
                context, &raw_sig, sigdata, (int)sigdata[64])) {
        return 0;
    }

    if (!secp256k1_ecdsa_recover(context, &raw_pubkey, &raw_sig, msghash)) {
        return 0;
    }

    if (!secp256k1_ec_pubkey_serialize(context,
                serialized_pubkey,
                &serialized_keylen,
                &raw_pubkey,
                SECP256K1_EC_UNCOMPRESSED)) {
        return 0;
    }

    /* header:0x04 -- uncompressed public key. */
    if (serialized_pubkey[0] != 0x04) {
        return 0;
    }

    memcpy(pubkey, serialized_pubkey, 65);

    return 1;
}


/**
 * `secp256_generate_pubkey_by_prikey` generate a public key by private key.
 *
 * return 0:failed; 1:successful
 */
int secp256_generate_pubkey_by_prikey(const secp256k1_context *context, 
                                      uint8_t *prikey, size_t prklen,
                                      uint8_t *pubkey, size_t pbklen)
{
    secp256k1_pubkey raw_pubkey;
    uint8_t serialized_pubkey[65];
    size_t serialized_keylen = 65;

#if 0
    if (context == NULL
            || prikey == NULL
            || prklen != 32
            || pubkey == NULL
            || pbklen != 65) {
        return 0;
    }
#endif

    if (!secp256k1_ec_pubkey_create(context, &raw_pubkey, prikey)) {
        return 0;
    }

    /* public key: 65:uncompressed pubkey; 33:compressed pubkey. */
    secp256k1_ec_pubkey_serialize(context,
            serialized_pubkey, &serialized_keylen,
            &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

    /* header:0x04 -- uncompressed public key. */
    if (serialized_pubkey[0] != 0x04) {
        return 0;
    }

    /* Skipping the serialized pubkey header:0x04. */
    memcpy(pubkey, serialized_pubkey + 1, 64);

    return 1;
}


/**
 * `secp256_generate_address_by_pubkey` generate address by public key.
 *
 * 1.sha3key = sha3-256(pubkey)
 * 2.address = sha3key[12:32]
 *
 * return 0:failed; 1:successful
 */
int secp256_generate_address_by_pubkey(uint8_t *pubkey, size_t keylen,
                                       uint8_t *address, size_t addrlen)
{
    uint8_t sha3key[32];

    if (pubkey == NULL
            || keylen != 64
            || address == NULL
            || addrlen < 20) {
        return 0;
    }

    sha256_hash(sha3key, pubkey, keylen);

    /* Take the right 20 bytes as address. */
    memcpy(address, sha3key + 12, 20);

    return 1;
}


/**
 * `secp256_generate_address_by_prikey` generate address by private key.
 *
 * return 0:failed; 1:successful
 */
int secp256_generate_address_by_prikey(const secp256k1_context *context,
                                       uint8_t *prikey, size_t keylen,
                                       uint8_t *address, size_t addrlen)
{
    uint8_t pubkey[65];

    if (context == NULL
            || prikey == NULL
            || keylen != 32
            || address == NULL
            || addrlen < 20) {
        return 0;
    }

    if (!secp256_generate_pubkey_by_prikey(context, prikey, keylen, pubkey, 65)) {
        return 0;
    }

    return secp256_generate_address_by_pubkey(pubkey, 65, address, addrlen);
}


/**
 * `secp256_generate_prikey_by_random` generate a private key by random.
 *
 * return 0:failed; 1:successful
 */
int secp256_generate_prikey_by_random(const secp256k1_context *context,
                                      uint8_t *prikey, size_t keylen)
{
    uint8_t seed16[16] = { 0 };

    uint64_t t;
    FILE *frand;

    if (prikey == NULL || keylen < 32) {
        return 0;
    }

    frand = fopen("/dev/urandom", "r");

    if ((frand == NULL) || fread(&seed16, 16, 1, frand) != 16) {
        t = (uint64_t)time(NULL) * 1337;
        seed16[0] ^= t;
        seed16[1] ^= t >> 8;
        seed16[2] ^= t >> 16;
        seed16[3] ^= t >> 24;
        seed16[4] ^= t >> 32;
        seed16[5] ^= t >> 40;
        seed16[6] ^= t >> 48;
        seed16[7] ^= t >> 56;
    }

    if (frand) {
        fclose(frand);
    }

    secp256k1_rand_seed(seed16);

    do {
        secp256k1_rand256(prikey);
    } while (!secp256k1_ec_seckey_verify((secp256k1_context *)context, prikey));

    return 1;
}
