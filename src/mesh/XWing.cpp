/* A C-style implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#include <Curve25519.h>
#include <cstdlib>
#include <cstring>

#include "XWing.h"

extern "C" {
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/kem.h"
#include "ml-kem-768/randombytes.h"
}

static const char XWING_LABEL[] = "\\.//^\\";

/**
 * Expand an XWING decapsulation key `sk` into its corresponding ML-KEM-768 and
 * X25519 keypairs.
 */
void xwing_expand_decapsulation_key(const uint8_t *sk, uint8_t *m_sk, uint8_t *x_sk, uint8_t *m_pk, uint8_t *x_pk)
{
    uint8_t *expanded = (uint8_t *)malloc(96);
    if (!expanded)
        return; // Handle malloc failure

    shake256(expanded, 96, sk, XWING_SK_BYTES);

    /* Use first 64 bytes for ML-KEM-768 key generation */
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(m_pk, m_sk, expanded);

    /* Read 32 bytes from offsets 64 to 96 */
    memcpy(x_sk, expanded + 64, 32);

    /* https://www.rfc-editor.org/rfc/rfc7748.html */
    /* Apply X25519 scalar clamping as per RFC 7748 */
    x_sk[0] &= 248;
    x_sk[31] &= 127;
    x_sk[31] |= 64;

    /* When given nullptr, `eval` uses the X25519 base point on the elliptic curve */
    Curve25519::eval(x_pk, x_sk, nullptr);

    free(expanded);
}

/**
 * Generates an XWING key pair using secure random bytes.
 */
int xwing_generate_keypair(uint8_t *secret_key, uint8_t *public_key)
{
    uint8_t *m_sk = (uint8_t *)malloc(M_SK_BYTES);
    uint8_t *x_sk = (uint8_t *)malloc(X_SK_BYTES);
    uint8_t *m_pk = (uint8_t *)malloc(M_PK_BYTES);
    uint8_t *x_pk = (uint8_t *)malloc(X_PK_BYTES);

    if (!m_sk || !x_sk || !m_pk || !x_pk) {
        free(m_sk);
        free(x_sk);
        free(m_pk);
        free(x_pk);
        return -1;
    }

    randombytes(secret_key, XWING_SK_BYTES);

    xwing_expand_decapsulation_key(secret_key, m_sk, x_sk, m_pk, x_pk);

    // Combine ML-KEM and X25519 public keys
    memcpy(public_key, m_pk, M_PK_BYTES);
    memcpy(public_key + M_PK_BYTES, x_pk, X_PK_BYTES);

    free(m_sk);
    free(x_sk);
    free(m_pk);
    free(x_pk);

    return 0;
}

/**
 * Generate an XWing keypair deterministically from seed
 */
int xwing_generate_keypair_derand(uint8_t *secret_key, uint8_t *public_key)
{
    uint8_t *m_sk = (uint8_t *)malloc(M_SK_BYTES);
    uint8_t *x_sk = (uint8_t *)malloc(X_SK_BYTES);
    uint8_t *m_pk = (uint8_t *)malloc(M_PK_BYTES);
    uint8_t *x_pk = (uint8_t *)malloc(X_PK_BYTES);

    if (!m_sk || !x_sk || !m_pk || !x_pk) {
        free(m_sk);
        free(x_sk);
        free(m_pk);
        free(x_pk);
        return -1;
    }

    xwing_expand_decapsulation_key(secret_key, m_sk, x_sk, m_pk, x_pk);

    // Combine ML-KEM and X25519 public keys
    memcpy(public_key, m_pk, M_PK_BYTES);
    memcpy(public_key + M_PK_BYTES, x_pk, X_PK_BYTES);

    free(m_sk);
    free(x_sk);
    free(m_pk);
    free(x_pk);
    return 0;
}

/**
 * Combines ML-KEM-768 and X25519 shared secrets with domain separation.
 */
void xwing_combiner(uint8_t *xwing_ss, const uint8_t *m_ss, const uint8_t *x_ss, const uint8_t *x_ct, const uint8_t *x_pk)
{
    uint8_t *buf = (uint8_t *)malloc(COMBINED_BYTES);
    if (!buf)
        return;

    uint8_t *ptr = buf;
    memcpy(ptr, m_ss, M_SS_BYTES);
    ptr += M_SS_BYTES;
    memcpy(ptr, x_ss, X_SS_BYTES);
    ptr += X_SS_BYTES;
    memcpy(ptr, x_ct, X_CT_BYTES);
    ptr += X_CT_BYTES;
    memcpy(ptr, x_pk, X_PK_BYTES);
    ptr += X_PK_BYTES;
    memcpy(ptr, XWING_LABEL, XWING_LABEL_BYTES);

    sha3_256(xwing_ss, buf, COMBINED_BYTES);
    free(buf);
}

/**
 * Encapsulate a shared secret
 */
int xwing_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key)
{
    uint8_t *m_pk = (uint8_t *)malloc(M_PK_BYTES);
    uint8_t *x_pk = (uint8_t *)malloc(X_PK_BYTES);
    uint8_t *x_ct = (uint8_t *)malloc(X_CT_BYTES);
    uint8_t *x_ss = (uint8_t *)malloc(X_SS_BYTES);
    uint8_t *m_ss = (uint8_t *)malloc(M_SS_BYTES);
    uint8_t *m_ct = (uint8_t *)malloc(M_CT_BYTES);
    uint8_t *ek_x = (uint8_t *)malloc(32);

    if (!m_pk || !x_pk || !x_ct || !x_ss || !m_ss || !m_ct || !ek_x) {
        free(m_pk);
        free(x_pk);
        free(x_ct);
        free(x_ss);
        free(m_ss);
        free(m_ct);
        free(ek_x);
        return -1;
    }

    randombytes(ek_x, 32);

    /* Apply X25519 scalar clamping as per RFC 7748 */
    ek_x[0] &= 248;
    ek_x[31] &= 127;
    ek_x[31] |= 64;

    memcpy(m_pk, public_key, M_PK_BYTES);
    memcpy(x_pk, public_key + M_PK_BYTES, X_PK_BYTES);

    /* As before, setting the second point to nullptr uses X25519_BASE implicitly */
    Curve25519::eval(x_ct, ek_x, nullptr);
    Curve25519::eval(x_ss, ek_x, x_pk);

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(m_ct, m_ss, m_pk);

    xwing_combiner(shared_secret, m_ss, x_ss, x_ct, x_pk);

    /* Concat operation */
    memcpy(ciphertext, m_ct, M_CT_BYTES);
    memcpy(ciphertext + M_CT_BYTES, x_ct, X_CT_BYTES);

    free(m_pk);
    free(x_pk);
    free(x_ct);
    free(x_ss);
    free(m_ss);
    free(m_ct);
    free(ek_x);
    return 0;
}

/**
 * Encapsulate a shared secret deterministically
 */
int xwing_encapsulate_derand(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *eseed)
{
    uint8_t *m_pk = (uint8_t *)malloc(M_PK_BYTES);
    uint8_t *x_pk = (uint8_t *)malloc(X_PK_BYTES);
    uint8_t *x_ct = (uint8_t *)malloc(X_CT_BYTES);
    uint8_t *x_ss = (uint8_t *)malloc(X_SS_BYTES);
    uint8_t *m_ss = (uint8_t *)malloc(M_SS_BYTES);
    uint8_t *m_ct = (uint8_t *)malloc(M_CT_BYTES);
    uint8_t *ek_X = (uint8_t *)malloc(32);
    uint8_t *ek_M = (uint8_t *)malloc(32);

    if (!m_pk || !x_pk || !x_ct || !x_ss || !m_ss || !m_ct || !ek_X || !ek_M) {
        free(m_pk);
        free(x_pk);
        free(x_ct);
        free(x_ss);
        free(m_ss);
        free(m_ct);
        free(ek_X);
        free(ek_M);
        return -1;
    }

    memcpy(ek_M, eseed, 32);
    memcpy(ek_X, eseed + 32, 32);

    /* Apply X25519 scalar clamping as per RFC 7748 */
    ek_X[0] &= 248;
    ek_X[31] &= 127;
    ek_X[31] |= 64;

    memcpy(m_pk, public_key, M_PK_BYTES);
    memcpy(x_pk, public_key + M_PK_BYTES, X_PK_BYTES);

    /* As before, setting the second point to nullptr uses X25519_BASE implicitly */
    Curve25519::eval(x_ct, ek_X, nullptr);
    Curve25519::eval(x_ss, ek_X, x_pk);

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(m_ct, m_ss, m_pk, ek_M);

    xwing_combiner(shared_secret, m_ss, x_ss, x_ct, x_pk);

    /* Concat operation */
    memcpy(ciphertext, m_ct, M_CT_BYTES);
    memcpy(ciphertext + M_CT_BYTES, x_ct, X_CT_BYTES);

    free(m_pk);
    free(x_pk);
    free(x_ct);
    free(x_ss);
    free(m_ss);
    free(m_ct);
    free(ek_X);
    free(ek_M);
    return 0;
}

/**
 * Decapsulate a shared secret
 */
int xwing_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key)
{
    uint8_t *m_ct = (uint8_t *)malloc(M_CT_BYTES);
    uint8_t *x_ct = (uint8_t *)malloc(X_CT_BYTES);
    uint8_t *m_ss = (uint8_t *)malloc(M_SS_BYTES);
    uint8_t *x_ss = (uint8_t *)malloc(X_SS_BYTES);
    uint8_t *m_sk = (uint8_t *)malloc(M_SK_BYTES);
    uint8_t *x_sk = (uint8_t *)malloc(X_SK_BYTES);
    uint8_t *m_pk = (uint8_t *)malloc(M_PK_BYTES);
    uint8_t *x_pk = (uint8_t *)malloc(X_PK_BYTES);

    if (!m_ct || !x_ct || !m_ss || !x_ss || !m_sk || !x_sk || !m_pk || !x_pk) {
        free(m_ct);
        free(x_ct);
        free(m_ss);
        free(x_ss);
        free(m_sk);
        free(x_sk);
        free(m_pk);
        free(x_pk);
        return -1;
    }

    xwing_expand_decapsulation_key(secret_key, m_sk, x_sk, m_pk, x_pk);

    memcpy(m_ct, ciphertext, M_CT_BYTES);
    memcpy(x_ct, ciphertext + M_CT_BYTES, X_CT_BYTES);

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(m_ss, m_ct, m_sk);

    Curve25519::eval(x_ss, x_sk, x_ct);

    xwing_combiner(shared_secret, m_ss, x_ss, x_ct, x_pk);

    free(m_ct);
    free(x_ct);
    free(m_ss);
    free(x_ss);
    free(m_sk);
    free(x_sk);
    free(m_pk);
    free(x_pk);
    return 0;
}