/* Diffie Hellman key exchange + HKDF */
#pragma once
#include <gmp.h>

/* convenience macros */
#define ISPRIME(x) mpz_probab_prime_p(x, 10)
#define NEWZ(x) \
    mpz_t x;    \
    mpz_init(x)
/* these will read/write integers from byte arrays where the
 * least significant byte is first (little endian bytewise). */
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, &len, -1, 1, 0, 0, x)

extern mpz_t q;             /** "small" prime; should be 256 bits or more */
extern mpz_t p;             /** "large" prime; should be 2048 bits or more, with q|(p-1) */
extern mpz_t g;             /** generator of the subgroup of order q */
extern size_t q_bit_length; /** length of q in bits */
extern size_t p_bit_length; /** length of p in bits */
extern size_t q_length;     /** length of q in bytes */
extern size_t p_length;     /** length of p in bytes */

#ifdef __cplusplus
extern "C"
{
#endif
    /* NOTE: you must call dh_load_params_from_file or dh_generate_new_params before doing anything else. */
    /** Try to read q,p,g from a file: */
    int dh_load_params_from_file(const char *filename);
    /** Generate fresh Diffie Hellman parameters.  This is a somewhat
     * expensive computation, so it's best to save and reuse params.
     * Prints generated parameters to stdout. */
    int dh_generate_new_params(size_t q_bit_length, size_t p_bit_length);
    /** set sk to a random exponent (this part is secret) and set
     * pk to g^(sk) mod p */
    int dh_generate_key_pair(mpz_t sk, mpz_t pk);
    /** given a secret (sk_mine say from dh_generate_key_pair above) and your friend's
     * public key (pk_yours), compute the diffie hellman value, and
     * apply a KDF to obtain buflen bytes of key, stored in keybuf */
    int dh_compute_shared_secret(mpz_t sk_mine, mpz_t pk_mine, mpz_t pk_yours, unsigned char *keybuf, size_t buflen);
/* NOTE: pk_mine is included just to avoid recomputing it from sk_mine */
#ifdef __cplusplus
}
#endif