/* A C++-11 (Arduino compliant) implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#include <algorithm>

#include <Curve25519.h>

#include "ml-kem-768/api.h"
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/indcpa.h"
#include "ml-kem-768/randombytes.h"

#include "xwing.h"

/**
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

    std::copy(xwing_pk.b.begin(), xwing_pk.b.begin() + 1184, m_pk.b.begin());
    std::copy(xwing_pk.b.begin() + 1184, xwing_pk.b.begin() + 1216, x_pk.b.begin());

    /* Sample from the on-device entropy source */
    randombytes(ek_x.data(), 32);

    /* As before, setting the second point to nullptr uses X22519_BASE implicity */
    Curve25519::eval(x_ct.b.data(), x_ek.data(), nullptr);
    Curve25519::eval(x_ss.b.data(), x_ek.data(), x_pk.b.data());

    std::tie(m_ss)
}

// START OPTIONAL PIECES
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

// END OPTIONAL PIECES
