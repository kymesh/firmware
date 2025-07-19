#include <array>
#include <cstdint>
#include <stdint.h>
#include <string>
#include <tuple>

// Not sure I'm even _allowed_ to use this.
#include <avr/pgmspace.h>

#include <Curve25519.h>

#include "ml-kem-768/api.h"
#include "ml-kem-768/fips202.h"
#include "ml-kem-768/indcpa.h"

// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html#section-5.3-2
// Aiden Fox Ivey (c) 2025

// Constants
const std::string XWING_LABEL = R"(\./\^/)";

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

/*
 * Within a KEM, the encapsulation key is the public key and the decapsulation
 * key is a private key. (FIPS203 uses ML-KEM)
 */

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

struct MSecretKey {
    std::array<uint8_t, M_SK_BYTES> b;
};

struct MPublicKey {
    std::array<uint8_t, M_PK_BYTES> b;
};

struct XWingSecretKey {
    std::array<uint8_t, XWING_SK_BYTES> b;
};

struct XWingPublicKey {
    std::array<uint8_t, XWING_PK_BYTES> b;
};

struct XSecretKey {
    std::array<uint8_t, X_SK_BYTES> b;
};

struct XPublicKey {
    std::array<uint8_t, X_PK_BYTES> b;
};

// std::chappal
std::tuple<MSecretKey, XSecretKey, MPublicKey, MSecretKey> expand_decapsulation_key(const XWingSecretKey &sk)
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
    // Pass 0 to represent X25519_BASE
    // VERIFY
    Curve25519::eval(x_pk.b.data(), x_sk.b.data(), 0);

    return {m_sk, x_sk, m_pk, m_sk};
}
