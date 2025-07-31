/* A C-style implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/* XWing constants */
#define XWING_LABEL_BYTES 6
#define X_SK_BYTES 32
#define X_PK_BYTES 32
#define X_CT_BYTES 32
#define X_SS_BYTES 32
#define M_SK_BYTES 2400
#define M_PK_BYTES 1184
#define M_CT_BYTES 1088
#define M_SS_BYTES 32
#define XWING_SK_BYTES 32
#define XWING_PK_BYTES 1216
#define XWING_CT_BYTES 1120
#define XWING_SS_BYTES 32
#define COMBINED_BYTES (M_SS_BYTES + X_SS_BYTES + X_CT_BYTES + X_PK_BYTES + XWING_LABEL_BYTES)

/* Core XWing functions - all use raw byte arrays */

/**
 * Generate an XWing keypair
 * @param secret_key Output buffer for secret key (XWING_SK_BYTES)
 * @param public_key Output buffer for public key (XWING_PK_BYTES)
 * @return 0 on success, -1 on failure
 */
int xwing_generate_keypair(uint8_t *secret_key, uint8_t *public_key);

/**
 * Generate an XWing keypair deterministically from seed
 * @param secret_key Input seed and output buffer for secret key (XWING_SK_BYTES)
 * @param public_key Output buffer for public key (XWING_PK_BYTES)
 * @return 0 on success, -1 on failure
 */
int xwing_generate_keypair_derand(uint8_t *secret_key, uint8_t *public_key);

/**
 * Encapsulate a shared secret
 * @param ciphertext Output buffer for ciphertext (XWING_CT_BYTES)
 * @param shared_secret Output buffer for shared secret (XWING_SS_BYTES)
 * @param public_key Input public key (XWING_PK_BYTES)
 * @return 0 on success, -1 on failure
 */
int xwing_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);

/**
 * Encapsulate a shared secret deterministically
 * @param ciphertext Output buffer for ciphertext (XWING_CT_BYTES)
 * @param shared_secret Output buffer for shared secret (XWING_SS_BYTES)
 * @param public_key Input public key (XWING_PK_BYTES)
 * @param eseed Input entropy seed (64 bytes)
 * @return 0 on success, -1 on failure
 */
int xwing_encapsulate_derand(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *eseed);

/**
 * Decapsulate a shared secret
 * @param shared_secret Output buffer for shared secret (XWING_SS_BYTES)
 * @param ciphertext Input ciphertext (XWING_CT_BYTES)
 * @param secret_key Input secret key (XWING_SK_BYTES)
 * @return 0 on success, -1 on failure
 */
int xwing_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

/* Helper functions */
void xwing_expand_decapsulation_key(const uint8_t *sk, uint8_t *m_sk, uint8_t *x_sk, uint8_t *m_pk, uint8_t *x_pk);
void xwing_combiner(uint8_t *xwing_ss, const uint8_t *m_ss, const uint8_t *x_ss, const uint8_t *x_ct, const uint8_t *x_pk);

#ifdef __cplusplus
}
#endif
