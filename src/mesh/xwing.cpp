// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html
// Aiden Fox Ivey (c) 2025

#include <array>
#include <cstdint>
#include <stdint.h>
#include <string>
#include <tuple>

#include <Curve25519.h>

#include "ml-kem-768/api.h"
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/indcpa.h"
#include "ml-kem-768/randombytes.h"

const char *XWING_LABEL = "\\.//^\\";
#define XWING_LABEL_BYTES 6

//  ┌──────────────────────┐
//  │                      │
//  │        KeyGen        │
//  │                      │
//  │                      │
//  └──────────────────────┘
//              │
//             ┌┴──────────────────────────────────┐
//             ▼                                   ▼
//    ┌─────────────────┐                 ┌─────────────────┐
//    │Decapsulation Key│                 │Encapsulation Key│
//    └─────────────────┘                 └─────────────────┘
//             │                                   │
//             │                                   └────────┐
//             ▼                                            ▼
// ┌──────────────────────┐                     ┌──────────────────────┐
// │                      │     ┌──────────┐    │                      │
// │        Decaps        │  ┌──│Ciphertext│◀┐  │        Encaps        │
// │                      │◀─┘  └──────────┘ └──│                      │
// │                      │                     │                      │
// └──────────────────────┘                     └──────────────────────┘
//             │                                            │
//             │                                            │
//             ▼                                            ▼
// ┌──────────────────────┐                     ┌──────────────────────┐
// │    Alice's shared    │                     │     Bob's shared     │
// │      secret key      │                     │      secret key      │
// │                      │                     │                      │
// └──────────────────────┘                     └──────────────────────┘

#define X_SK_BYTES 32
#define X_PK_BYTES 32
#define X_CT_BYTES 32
#define X_SS_BYTES 32

// Names are opaque since they are directly from ml-kem-768 implementation.
#define M_SK_BYTES 2400
#define M_PK_BYTES 1184
#define M_CT_BYTES 1088
#define M_SS_BYTES 32

#define XWING_SK_BYTES 32
#define XWING_PK_BYTES 1216
#define XWING_CT_BYTES 1120
#define XWING_SS_BYTES 32

#define COMBINED_BYTES (M_SS_BYTES + X_SS_BYTES + X_CT_BYTES + X_PK_BYTES + XWING_LABEL_BYTES)

// Sorry guys, I know better types are possible
struct MSecretKey {
    std::array<uint8_t, M_SK_BYTES> b;
};

struct MPublicKey {
    std::array<uint8_t, M_PK_BYTES> b;
};

struct MSharedSecret {
    std::array<uint8_t, M_SS_BYTES> b;
};

struct XWingSecretKey {
    std::array<uint8_t, XWING_SK_BYTES> b;
};

struct XWingPublicKey {
    std::array<uint8_t, XWING_PK_BYTES> b;
};

struct XWingSharedSecret {
    std::array<uint8_t, XWING_SS_BYTES> b;
};

struct XSecretKey {
    std::array<uint8_t, X_SK_BYTES> b;
};

struct XPublicKey {
    std::array<uint8_t, X_PK_BYTES> b;
};

struct XSharedSecret {
    std::array<uint8_t, X_SS_BYTES> b;
};

struct XCipherText {
    std::array<uint8_t, X_CT_BYTES> b;
}

std::tuple<MSecretKey, XSecretKey, MPublicKey, XPublicKey>
expand_decapsulation_key(const XWingSecretKey &sk)
{
    std::array<uint8_t, 96> expanded;
    XSecretKey x_sk;
    XPublicKey x_pk;
    MSecretKey m_sk;
    MPublicKey m_pk;

    shake256(expanded.data(), 96, sk.b.data(), XWING_SK_BYTES);
    // Implicitly reads 64 bytes from expanded.data()
    indcpa_keypair_derand(m_pk.b.data(), m_sk.b.data(), expanded.data());
    // Take from start + 64 bytes of expanded data
    memcpy(x_sk.b.data(), expanded.data() + 64, 32);
    // When given nullptr, `eval` uses the X25519 base point on the elliptic curve
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

    // Eat your lettuce!
    memcpy(xwing_pk.b.data(), m_pk.b.data(), M_PK_BYTES);
    memcpy(xwing_pk.b.data() + M_PK_BYTES, x_pk.b.data(), X_PK_BYTES);

    return {xwing_sk, xwing_pk};
}

// Deterministic version of key generation function.
// According to spec this is optional but not required
std::tuple<XWingSecretKey, XWingPublicKey> generate_key_pair_derand(XWingSecretKey xwing_sk)
{
    XWingPublicKey xwing_pk;
    XSecretKey x_sk;
    XPublicKey x_pk;
    MSecretKey m_sk;
    MPublicKey m_pk;

    std::tie(m_sk, x_sk, m_pk, x_pk) = expand_decapsulation_key(xwing_sk);

    // Eat your lettuce!
    memcpy(xwing_pk.b.data(), m_pk.b.data(), M_PK_BYTES);
    memcpy(xwing_pk.b.data() + M_PK_BYTES, x_pk.b.data(), X_PK_BYTES);

    return {xwing_sk, xwing_pk};
}

XWingSharedSecret combiner(MSharedSecret m_ss, XSharedSecret x_ss, XCipherText x_ct, XPublicKey x_pk)
{
    XWingSharedSecret xwing_ss;
    uint8_t buf[COMBINED_BYTES];

    // Concatenate to the buffer
    // Yes, I'm sorry it looks yucky
    memcpy(buf, m_ss.b.data(), M_SS_BYTES);
    memcpy(buf + M_SS_BYTES, x_ss.b.data(), X_SS_BYTES);
    memcpy(buf + M_SS_BYTES + X_SS_BYTES, x_ct.b.data(), X_CT_BYTES);
    memcpy(buf + M_SS_BYTES + X_SS_BYTES + X_CT_BYTES, x_pk.b.data(), X_PK_BYTES);
    memcpy(buf + M_SS_BYTES + X_SS_BYTES + X_CT_BYTES + X_PK_BYTES, XWING_LABEL, XWING_LABEL_BYTES);

    sha3_256(xwing_ss.b.data(), buf, COMBINED_BYTES);

    return xwing_ss;
}

std::tuple<XWingSharedSecret, XWingCipherText> encapsulate(XWingPublicKey)
{
    MPublicKey m_pk;
    XPublicKey x_pk;
    XCipherText x_ct;
    XSharedSecret x_ss;
    XWingSharedSecret xwing_ss;
    XWingCipherText xwing_ct;
    std::array<uint8_t, 32> ek;

    randombytes(ek.b.data(), 32);

    Curve25519::eval()
}
