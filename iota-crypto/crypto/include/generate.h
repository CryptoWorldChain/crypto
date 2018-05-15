#ifndef _IOTA_CRYPTO_GENERATE_H_
#define _IOTA_CRYPTO_GENERATE_H_


/**
 * Generates a new IOTA seed.
 *
 * @warning This uses `rand()` and thus can not be expected to create a truly
 * random seed!
 *
 * @return a valid new seed
 */
extern const char *iota_generateSeed();

/**
 * Generates a private key for the given key index and seed.
 *
 * @param seed wallet seed (must be a valid tryte!)
 * @param keyIndex key index
 * @param securityLevel determines number of ccurl iterations
 * @return
 */
extern const char *iota_generateKey(const char *seed, int keyIndex,
                                    int securityLevel);

/**
 * Generates an address from the given seed and key index.
 *
 * @param seed wallet seed
 * @param keyIndex @link(iota_generateKey)
 * @param securityLevel @link(iota_generateKey)
 */
extern const char *iota_generateAddress(const char *seed, int keyIndex,
                                        int securityLevel);


#endif
