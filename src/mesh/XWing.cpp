/* A C++-11 (Arduino compliant) implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#include <Curve25519.h>
#include <algorithm>

#include "XWing.h"

extern "C" {
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/kem.h"
#include "ml-kem-768/randombytes.h"
}

namespace XWing
{
const char *XWING_LABEL = "\\.//^\\";

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
    /* Use first 64 bytes for ML-KEM-768 key generation */
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(m_pk.b.data(), m_sk.b.data(), expanded.data());
    /* Read 32 bytes from offsets 64 to 96 */
    std::copy(expanded.begin() + 64, expanded.end(), x_sk.b.begin());

    /* https://www.rfc-editor.org/rfc/rfc7748.html */
    /* Apply X25519 scalar clamping as per RFC 7748 */
    x_sk.b[0] &= 248;
    x_sk.b[31] &= 127;
    x_sk.b[31] |= 64;

    /* When given nullptr, `eval` uses the X25519 base point on the elliptic curve */
    Curve25519::eval(x_pk.b.data(), x_sk.b.data(), nullptr);

    return {m_sk, x_sk, m_pk, x_pk};
}

/**
 * Generates an XWING key pair using secure random bytes.
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

    randombytes(ek_x.data(), 32);

    /* Apply X25519 scalar clamping as per RFC 7748 */
    ek_x[0] &= 248;
    ek_x[31] &= 127;
    ek_x[31] |= 64;

    std::copy(xwing_pk.b.begin(), xwing_pk.b.begin() + M_PK_BYTES, m_pk.b.begin());
    std::copy(xwing_pk.b.begin() + M_PK_BYTES, xwing_pk.b.begin() + M_PK_BYTES + X_PK_BYTES, x_pk.b.begin());

    /* As before, setting the second point to nullptr uses X22519_BASE implicity
     */
    Curve25519::eval(x_ct.b.data(), ek_x.data(), nullptr);
    Curve25519::eval(x_ss.b.data(), ek_x.data(), x_pk.b.data());

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(m_ct.b.data(), m_ss.b.data(), m_pk.b.data());

    xwing_ss = combiner(m_ss, x_ss, x_ct, x_pk);

    /* Concat operation */
    auto it = std::copy(m_ct.b.begin(), m_ct.b.end(), xwing_ct.b.begin());
    std::copy(x_ct.b.begin(), x_ct.b.end(), it);

    return {xwing_ss, xwing_ct};
}

/**
 * Encapsulates a shared secret using an XWING public key.
 *
 * @param xwing_pk The XWING public key to encapsulate against
 * @return A tuple containing (shared_secret, ciphertext) for the recipient
 */
std::tuple<XWingSharedSecret, XWingCipherText> encapsulate_derand(const XWingPublicKey &xwing_pk, std::array<uint8_t, 64> &eseed)
{
    MPublicKey m_pk;
    XPublicKey x_pk;
    XCipherText x_ct;
    XSharedSecret x_ss;
    MSharedSecret m_ss;
    MCipherText m_ct;
    XWingSharedSecret xwing_ss;
    XWingCipherText xwing_ct;

    std::array<uint8_t, 32> ek_X;
    std::array<uint8_t, 32> ek_M;
    std::copy(eseed.begin(), eseed.begin() + 32, ek_M.begin());
    std::copy(eseed.begin() + 32, eseed.end(), ek_X.begin());

    /* Apply X25519 scalar clamping as per RFC 7748 */
    ek_X[0] &= 248;
    ek_X[31] &= 127;
    ek_X[31] |= 64;

    std::copy(xwing_pk.b.begin(), xwing_pk.b.begin() + M_PK_BYTES, m_pk.b.begin());
    std::copy(xwing_pk.b.begin() + M_PK_BYTES, xwing_pk.b.begin() + M_PK_BYTES + X_PK_BYTES, x_pk.b.begin());

    /* As before, setting the second point to nullptr uses X22519_BASE implicity */
    Curve25519::eval(x_ct.b.data(), ek_X.data(), nullptr);
    Curve25519::eval(x_ss.b.data(), ek_X.data(), x_pk.b.data());

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(m_ct.b.data(), m_ss.b.data(), m_pk.b.data(), ek_M.data());

    xwing_ss = combiner(m_ss, x_ss, x_ct, x_pk);

    /* Concat operation */
    auto it = std::copy(m_ct.b.begin(), m_ct.b.end(), xwing_ct.b.begin());
    std::copy(x_ct.b.begin(), x_ct.b.end(), it);

    return {xwing_ss, xwing_ct};
}

/**
 * Decapsulates a shared secret using an XWING secret key and ciphertext.
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

    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(m_ss.b.data(), m_ct.b.data(), m_sk.b.data());

    Curve25519::eval(x_ss.b.data(), x_sk.b.data(), x_ct.b.data());

    return combiner(m_ss, x_ss, x_ct, x_pk);
}

/**
 * Generates an XWING key pair deterministically from a given secret key seed.
 *
 * @warning This function should only be used for testing. Production code
 * should use generate_key_pair() which provides proper entropy.
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
} // namespace XWing
