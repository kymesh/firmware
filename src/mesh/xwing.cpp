/* A C++-11 (Arduino compliant) implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#include <Curve25519.h>
#include <algorithm>

#include "ml-kem-768/api.h"
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/indcpa.h"
#include "ml-kem-768/randombytes.h"
#include "xwing.h"

const char *XWING_LABEL = "\.//^\\";

/**
 * The following schematic is recreated from the FIPS-203 definition for a simplified
 * key establishment process. The left boxes (KeyGen, Decaps) are implied to be Alice's
 * and the right box (Encaps) is implied to be Bob's. The encapsulation key is the public
 * key for this scheme, whereas the decapsulation key is the private key.
 *
 * In effect, Alice will generate both, pass the encapsulation key to parties looking to
 * establish shared keying material, and then receive some the ciphertext of this shared
 * keying material. Upon receiving, it will decapsulate it (decrypt), then using this
 * shared keying material in a symmetric scheme.
 *
 * In this specific file, we implement X-Wing (as of its 8th revision), which is a KEM that
 * uses a so-called 'belt and suspenders' approach to combine the use of X25519 (a well studied
 * but non-quantum-resistant elliptic curve algorithm) and ML-KEM-768 (a quantum resistant KEM).
 *
 * ┌──────────────────────┐
 * │                      │
 * │        KeyGen        │
 * │                      │
 * │                      │
 * └──────────────────────┘
 *            │
 *           ┌┴──────────────────────────────────┐
 *           ▼                                   ▼
 * ┌─────────────────┐                 ┌─────────────────┐
 * │Decapsulation Key│                 │Encapsulation Key│
 * └─────────────────┘                 └─────────────────┘
 *            │                                   │
 *            │                                   └────────┐
 *            ▼                                            ▼
 * ┌──────────────────────┐                     ┌──────────────────────┐
 * │                      │     ┌──────────┐    │                      │
 * │        Decaps        │  ┌──│Ciphertext│◀┐  │        Encaps        │
 * │                      │◀─┘  └──────────┘ └──│                      │
 * │                      │                     │                      │
 * └──────────────────────┘                     └──────────────────────┘
 *            │                                            │
 *            │                                            │
 *            ▼                                            ▼
 * ┌──────────────────────┐                     ┌──────────────────────┐
 * │    Alice's shared    │                     │     Bob's shared     │
 * │      secret key      │                     │      secret key      │
 * │                      │                     │                      │
 * └──────────────────────┘                     └──────────────────────┘
 */

/**
 * Expand an XWING decapsulation key `sk` into its corresponding ML-KEM-768 and
 * X25519 keypairs.
 */
std::tuple<MSecretKey, XSecretKey, MPublicKey, XPublicKey> expand_decapsulation_key(const XWingSecretKey &sk)
{
    std::array<uint8_t, 96> expanded;
    XSecretKey x_sk;
    XPublicKey x_pk;
    MSecretKey m_sk;
    MPublicKey m_pk;

    shake256(expanded.data(), 96, sk.b.data(), XWING_SK_BYTES);
    /* Implicitly reads 64 bytes from expanded */
    indcpa_keypair_derand(m_pk.b.data(), m_sk.b.data(), expanded.data());
    /* Read 32 bytes from offsets 64 to 96 */
    std::copy(expanded.begin() + 64, expanded.end(), x_sk.b.begin());
    /* When given nullptr, `eval` uses the X25519 base point on the elliptic curve */
    Curve25519::eval(x_pk.b.data(), x_sk.b.data(), nullptr);

    return {m_sk, x_sk, m_pk, x_pk};
}

/**
 * Generates an XWING key pair using secure random bytes.
 *
 * This function creates both secret and public keys for the XWING KEM by:
 * 1. Generating 32 random bytes for the secret key seed
 * 2. Expanding the seed into ML-KEM-768 and X25519 key pairs
 * 3. Combining the public keys into a single XWING public key
 *
 * @return A tuple containing (secret_key, public_key) for XWING operations
 */
std::tuple<XWingSecretKey, XWingPublicKey> generate_key_pair(void)
{
    XWingSecretKey xwing_sk;
    XWingPublicKey xwing_pk;
    XSecretKey x_sk;
    XPublicKey x_pk;
    MSecretKey m_sk;
    MPublicKey m_pk;

    randombytes(xwing_sk.b.data(), XWING_SK_BYTES);
    std::tie(m_sk, x_sk, m_pk, x_pk) = expand_decapsulation_key(xwing_sk);

    auto it = std::copy(m_pk.b.begin(), m_pk.b.end(), xwing_pk.b.begin());
    std::copy(x_pk.b.begin(), x_pk.b.end(), it);

    return {xwing_sk, xwing_pk};
}

/**
 * Combines ML-KEM-768 and X25519 shared secrets with domain separation.
 *
 * This function implements the XWING combiner that creates the final shared secret by:
 * 1. Concatenating ML-KEM shared secret, X25519 shared secret, X25519 ciphertext, and X25519 public key
 * 2. Appending the XWING domain separation label
 * 3. Hashing the combined data with SHA3-256 to produce the final shared secret
 *
 * The domain separation ensures that XWING shared secrets are distinct from
 * either ML-KEM-768 or X25519 alone, providing hybrid security.
 *
 * @param m_ss ML-KEM-768 shared secret
 * @param x_ss X25519 shared secret
 * @param x_ct X25519 ciphertext
 * @param x_pk X25519 public key
 * @return The final XWING shared secret
 */
XWingSharedSecret combiner(const MSharedSecret &m_ss, const XSharedSecret &x_ss, const XCipherText &x_ct, const XPublicKey &x_pk)
{
    XWingSharedSecret xwing_ss;
    std::array<uint8_t, COMBINED_BYTES> buf;

    auto it = buf.begin();

    it = std::copy(m_ss.b.begin(), m_ss.b.end(), it);
    it = std::copy(x_ss.b.begin(), x_ss.b.end(), it);
    it = std::copy(x_ct.b.begin(), x_ct.b.end(), it);
    it = std::copy(x_pk.b.begin(), x_pk.b.end(), it);
    std::copy(XWING_LABEL, XWING_LABEL + XWING_LABEL_BYTES, it);

    sha3_256(xwing_ss.b.data(), buf.data(), buf.size());

    return xwing_ss;
}

/**
 * Encapsulates a shared secret using an XWING public key.
 *
 * This function performs XWING encapsulation by:
 * 1. Splitting the public key into ML-KEM-768 and X25519 components
 * 2. Generating ephemeral X25519 key pair from random bytes
 * 3. Computing X25519 shared secret and ciphertext
 * 4. Performing ML-KEM-768 encapsulation
 * 5. Combining both shared secrets using the domain separator
 *
 * @param xwing_pk The XWING public key to encapsulate against
 * @return A tuple containing (shared_secret, ciphertext) for the recipient
 */
std::tuple<XWingSharedSecret, XWingCipherText> encapsulate(const XWingPublicKey &xwing_pk)
{
    MPublicKey m_pk;
    XPublicKey x_pk;
    XCipherText x_ct;
    XSharedSecret x_ss;
    MSharedSecret m_ss;
    MCipherText m_ct;
    XWingSharedSecret xwing_ss;
    XWingCipherText xwing_ct;
    std::array<uint8_t, 32> ek_x;

    std::copy(xwing_pk.b.begin(), xwing_pk.b.begin() + M_PK_BYTES, m_pk.b.begin());
    std::copy(xwing_pk.b.begin() + M_PK_BYTES, xwing_pk.b.begin() + M_PK_BYTES + X_PK_BYTES, x_pk.b.begin());

    /* Sample from the on-device entropy source */
    randombytes(ek_x.data(), 32);

    /* As before, setting the second point to nullptr uses X22519_BASE implicity */
    Curve25519::eval(x_ct.b.data(), ek_x.data(), nullptr);
    Curve25519::eval(x_ss.b.data(), ek_x.data(), x_pk.b.data());

    crypto_kem_enc(m_ct.b.data(), m_ss.b.data(), m_pk.b.data());

    xwing_ss = combiner(m_ss, x_ss, x_ct, x_pk);

    /* Concat operation */
    auto it = std::copy(m_ct.b.begin(), m_ct.b.end(), xwing_ct.b.begin());
    std::copy(x_ct.b.begin(), x_ct.b.end(), it);

    return {xwing_ss, xwing_ct};
}

/**
 * Decapsulates a shared secret using an XWING secret key and ciphertext.
 *
 * This function performs XWING decapsulation by:
 * 1. Expanding the secret key into ML-KEM-768 and X25519 key pairs
 * 2. Splitting the ciphertext into ML-KEM-768 and X25519 components
 * 3. Performing ML-KEM-768 decapsulation to recover shared secret
 * 4. Computing X25519 shared secret from secret key and ciphertext
 * 5. Combining both shared secrets using the domain separator
 *
 * @param xwing_ct The XWING ciphertext to decapsulate
 * @param xwing_sk The XWING secret key for decapsulation
 * @return The shared secret that matches the encapsulator's output
 */
XWingSharedSecret decapsulate(const XWingCipherText &xwing_ct, const XWingSecretKey &xwing_sk)
{
    MSecretKey m_sk;
    XSecretKey x_sk;
    MPublicKey m_pk;
    XPublicKey x_pk;
    MCipherText m_ct;
    XCipherText x_ct;
    MSharedSecret m_ss;
    XSharedSecret x_ss;

    std::tie(m_sk, x_sk, m_pk, x_pk) = expand_decapsulation_key(xwing_sk);

    std::copy(xwing_ct.b.begin(), xwing_ct.b.begin() + M_CT_BYTES, m_ct.b.begin());
    std::copy(xwing_ct.b.begin() + M_CT_BYTES, xwing_ct.b.begin() + M_CT_BYTES + X_CT_BYTES, x_ct.b.begin());

    crypto_kem_dec(m_ss.b.data(), m_ct.b.data(), m_sk.b.data());

    Curve25519::eval(x_ss.b.data(), x_sk.b.data(), x_ct.b.data());

    return combiner(m_ss, x_ss, x_ct, x_pk);
}

/**
 * Generates an XWING key pair deterministically from a given secret key seed.
 *
 * This function is intended for testing purposes and creates reproducible key pairs
 * by using a provided secret key seed instead of random bytes. The process is identical
 * to generate_key_pair() except it skips the random byte generation step.
 *
 * WARNING: This function should only be used for testing. Production code should
 * use generate_key_pair() which provides proper entropy.
 *
 * @param xwing_sk The 32-byte secret key seed to use for key generation
 * @return A tuple containing (secret_key, public_key) derived from the seed
 */
std::tuple<XWingSecretKey, XWingPublicKey> generate_key_pair_derand(const XWingSecretKey &xwing_sk)
{
    XWingPublicKey xwing_pk;
    XSecretKey x_sk;
    XPublicKey x_pk;
    MSecretKey m_sk;
    MPublicKey m_pk;

    std::tie(m_sk, x_sk, m_pk, x_pk) = expand_decapsulation_key(xwing_sk);

    auto it = std::copy(m_pk.b.begin(), m_pk.b.end(), xwing_pk.b.begin());
    std::copy(x_pk.b.begin(), x_pk.b.end(), it);

    return {xwing_sk, xwing_pk};
}

/* Note that we do not provide encapsulate_derand */
