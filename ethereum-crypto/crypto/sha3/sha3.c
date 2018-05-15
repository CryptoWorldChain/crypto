#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static const uint8_t rho[24] = {
    1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

static const uint8_t pi[24] = {
    10,  7, 11, 17, 18, 3,
    5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9, 6,  1
};

static const uint64_t RC[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e)    \
    v = 0;				 \
    REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static void keccakf(void* state)
{
    uint64_t* a = (uint64_t*)state;
    uint64_t b[5] = {0};
    uint64_t t = 0;
    uint8_t x, y, i;

    for (i = 0; i < 24; i++) {
        /* Theta */
        FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y]; ))
            FOR5(x, 1, FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
            /* Rho and pi */
            t = a[1];
        x = 0;
        REPEAT24(b[0] = a[pi[x]]; a[pi[x]] = rol(t, rho[x]); t = b[0]; x++; )
            /* Chi */
            FOR5(y, 5, FOR5(x, 1, b[x] = a[y + x];)
                    FOR5(x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
            /* Iota */
            a[0] ^= RC[i];
    }
}

/******** The FIPS202-defined functions. ********/

static void xorin(uint8_t *dst, const uint8_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

static void setout(const uint8_t* src, uint8_t* dst, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}


#define P keccakf
#define Plen 200

/* Fold P*F over the full blocks of an input. */
#define foldP(I, L, F)								\
        while (L >= rate) {							\
            F(a, I, rate);							\
            P(a);									\
            I += rate;								\
            L -= rate;								\
        }

/** The sponge-based hash construction. **/
static int hash(uint8_t* out, size_t outlen,
                const uint8_t* in, size_t inlen,
                size_t rate, uint8_t delim)
{
    uint8_t a[Plen] = {0};

    if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
        return 0;
    }

    /* Absorb input. */
    foldP(in, inlen, xorin);
    /* Xor in the DS and pad frame. */
    a[inlen] ^= delim;
    a[rate - 1] ^= 0x80;
    /* Xor in the last block. */
    xorin(a, in, inlen);
    /* Apply P */
    P(a);
    /* Squeeze output. */
    foldP(out, outlen, setout);
    setout(a, out, outlen);
    memset(a, 0, 200);

    return 1;
}


/*** FIPS202 SHA3 FOFs ***/

int sha3_256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (outlen > 32) {
        return 0;
    }

    return hash(out, outlen, in, inlen, 136, 0x01);
}


int sha3_512(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    if (outlen > 64) {
        return 0;
    }

    return hash(out, outlen, in, inlen, 72, 0x01);
}
