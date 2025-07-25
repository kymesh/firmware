/* A C++-11 (Arduino compliant) implementation of XWING. */
/* https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-08.html */
/* Aiden Fox Ivey (c) 2025 */

#pragma once

#ifndef XWING_H
#define XWING_H

#include <array>
#include <cstdint>
#include <string>
#include <tuple>

extern const char *XWING_LABEL;
constexpr size_t XWING_LABEL_BYTES = 6;

constexpr size_t X_SK_BYTES = 32;
constexpr size_t X_PK_BYTES = 32;
constexpr size_t X_CT_BYTES = 32;
constexpr size_t X_SS_BYTES = 32;
constexpr size_t M_SK_BYTES = 2400;
constexpr size_t M_PK_BYTES = 1184;
constexpr size_t M_CT_BYTES = 1088;
constexpr size_t M_SS_BYTES = 32;
constexpr size_t XWING_SK_BYTES = 32;
constexpr size_t XWING_PK_BYTES = 1216;
constexpr size_t XWING_CT_BYTES = 1120;
constexpr size_t XWING_SS_BYTES = 32;
constexpr size_t COMBINED_BYTES = (M_SS_BYTES + X_SS_BYTES + X_CT_BYTES + X_PK_BYTES + XWING_LABEL_BYTES);

struct MSecretKey {
    std::array<uint8_t, M_SK_BYTES> b{};
};

struct MPublicKey {
    std::array<uint8_t, M_PK_BYTES> b{};
};

struct MSharedSecret {
    std::array<uint8_t, M_SS_BYTES> b{};
};

struct MCipherText {
    std::array<uint8_t, M_CT_BYTES> b{};
};

struct XWingSecretKey {
    std::array<uint8_t, XWING_SK_BYTES> b{};
};

struct XWingPublicKey {
    std::array<uint8_t, XWING_PK_BYTES> b{};
};

struct XWingSharedSecret {
    std::array<uint8_t, XWING_SS_BYTES> b{};
};

struct XWingCipherText {
    std::array<uint8_t, XWING_CT_BYTES> b{};
};

struct XSecretKey {
    std::array<uint8_t, X_SK_BYTES> b{};
};

struct XPublicKey {
    std::array<uint8_t, X_PK_BYTES> b{};
};

struct XSharedSecret {
    std::array<uint8_t, X_SS_BYTES> b{};
};

struct XCipherText {
    std::array<uint8_t, X_CT_BYTES> b{};
};

#endif
