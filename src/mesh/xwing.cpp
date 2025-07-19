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

/**
 * Tests if a generated Curve25519 point is weak.
 *
 * @param k The point to check.
 * @returns zero if k is not weak, one else
 *
 * @note PROGMEM and pgm_read_byte are special. DuckDuckGo them.
 * @note Lovingly ripped from Arduino's crypto library. Please don't sue.
 */
uint8_t is_weak_point(const uint8_t k[32])
{
    // List of weak points from http://cr.yp.to/ecdh.html
    // That page lists some others but they are variants on these
    // of the form "point + i * (2^255 - 19)" for i = 0, 1, 2.
    // Here we mask off the high bit and eval() catches the rest.
    static const uint8_t points[5][32] PROGMEM = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
         0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00},
        {0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B,
         0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57},
        {0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}};

    // Check each of the weak points in turn.  We perform the
    // comparisons carefully so as not to reveal the value of "k"
    // in the instruction timing.  If "k" is indeed weak then
    // we still check everything so as not to reveal which
    // weak point it is.
    uint8_t result = 0;
    for (uint8_t posn = 0; posn < 5; ++posn) {
        const uint8_t *point = points[posn];
        uint8_t check = (pgm_read_byte(point + 31) ^ k[31]) & 0x7F;
        for (uint8_t index = 31; index > 0; --index)
            check |= (pgm_read_byte(point + index - 1) ^ k[index - 1]);
        result |= (uint8_t)((((uint16_t)0x0100) - check) >> 8);
    }

    // The "result" variable will be non-zero if there was a match.
    return result;
}

// Ensure to pass a valid secret key in
// Modified from
// https://github.com/kostko/arduino-crypto/blob/0e609138d59095d80de0300b3a72803c3462e5ce/Curve25519.cpp#L244
void X25519(XPublicKey &pk, XSecretKey &sk)
{
    do {
        sk.b.data()[0] &= 0xF8;
        sk.b.data()[31] = (sk.b.data()[31] & 0x7F) | 0x40;

        Curve25519::eval(pk.b.data(), sk.b.data(), 0);
    } while (is_weak_point(pk.b.data()));
}

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

    return {};
}
