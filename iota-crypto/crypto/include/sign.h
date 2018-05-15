#ifndef _IOTA_CRYPTO_SIGN_H_
#define _IOTA_CRYPTO_SIGN_H_


#include <stddef.h>
#include <stdint.h>


/**
 *  @brief Generates the digest used to do the actual signing.
 *
 * Signing keys can have variable length and tend to be quite long,
 * which makes them not-well-suited for use in crypto algorithms.
 *
 * The digest is essentially the result of running the signing key
 * through a PBKDF, yielding a constant-length hash that can be used
 * for crypto.
 *
 * @return NULL if input is too short
 * @return or concatenated string of all hashes
 */
extern const char *iota_digests(const char *trytes);

/**
 * Calculates the checksum for the given trytes
 *
 * @return trytes with checksum
 */
extern const char *iota_checksum(const char *trytes);

/**
 * Takes a normalized (bundle) fragment and the accompanying key fragment and
 * returns
 * a signed fragment.
 *
 * @param normalizedFragment len(normalizedFragment) = 27
 * @return signed fragment (trytes)
 */
extern const char *iota_sign(const int8_t *normalizedFragment,
                             const char *keyTrytes);

/**
 * Validates signatures for a given address and bundle hash.
 *
 * @param address tryte encoded address
 * @param signFrags array of signed fragments
 * @param len number of signed fragments
 * @param bundleHash bundle hash
 *
 * @return 1 if signature fragments are valid
 */
extern int iota_validateSignature(const char *address, const char **signFrags,
                                   size_t len, const char *bundleHash);


#endif
