#ifndef _IOTA_CRYPTO_VALIDATE_H_
#define _IOTA_CRYPTO_VALIDATE_H_


/**
 * Validates trytes
 *
 * @param trytes trytes to validate
 * @return 0 if trytes is invalid
 * @return 1 if trytes is valid
 */
extern int iota_isValidTrytes(const char *trytes);


#endif
