#include "TRNGNoiseSensor.h"
#include "RNG.h"
#include "ChaCha.h"
#include "BLAKE2s.h"
/*
Base Class: TelemetrySensor

Key methods:
- setup() - configure your pins
- runOnce() - read the pins periodically
- getMetrics() - return the readings as telemetry data
- hasSensor() - return true if pins are available */

#if !MESHTASTIC_EXCLUDE_TRNG

#define BUFFER_LEN 255
#define HASH_LEN 32
#define CHACHA_BLOCK_SIZE 64
#define CHACHA_NONCE_SIZE 12
#define CHACHA_ROUNDS 10
#define CREDIT_BITS 192
#define MIN_ENTROPY_BYTES 24

BLAKE2s entropy_pool;
ChaCha chacha(CHACHA_ROUNDS);
uint8_t buffer[BUFFER_LEN];
uint8_t hash[HASH_LEN];
uint8_t chacha_out[CHACHA_BLOCK_SIZE];
uint8_t nonce[CHACHA_NONCE_SIZE];

TRNGNoiseSensor::TRNGNoiseSensor() : TelemetrySensor(meshtastic_TelemetrySensorType_TRNG, "TRNG")
{
    analogPin = A0;
    counter = 0;
    memset(noiseBuffer, 0, sizeof(noiseBuffer));}

TRNGNoiseSensor::~TRNGNoiseSensor()
{
    cleanup();
}

void TRNGNoiseSensor::setup()
{
    pinMode(analogPin, INPUT);
    RNG.addNoiseSource(*this);
}

void TRNGNoiseSensor::sample_noise(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = 0;
        for (int j = 0; j < 4; j++) {
        int val = analogRead(analogPin);
        uint8_t bit0 = val & 1;
        uint8_t bit4 = (val >> 4) & 1;
        uint8_t two_bits = (bit4 << 1) | bit0;
        buf[i] |= (two_bits << (j * 2));
        }
    }
}

void TRNGNoiseSensor::add_entropy()
{
    sample_noise(buffer, BUFFER_LEN);
    entropy_pool.update(buffer, BUFFER_LEN);
}

void TRNGNoiseSensor::init_entropy_pool()
{
    entropy_pool.reset();
    chacha.clear();
    
    add_entropy();
}

void TRNGNoiseSensor::extract_entropy()
{
    entropy_pool.finalize(hash, HASH_LEN);

    sample_noise(nonce, sizeof(nonce));
    sample_noise(chacha_out, CHACHA_BLOCK_SIZE);

    chacha.setIV(nonce, sizeof(nonce));
    chacha.setKey(hash, HASH_LEN);
    chacha.setCounter((uint8_t *)&counter, sizeof(counter));
    chacha.encrypt(chacha_out, chacha_out, CHACHA_BLOCK_SIZE);
    counter++;
}

void TRNGNoiseSensor::cleanup() 
{
    entropy_pool.reset();
    chacha.clear();
    memset(buffer, 0, sizeof(buffer));
    memset(hash, 0, sizeof(hash));
    memset(chacha_out, 0, sizeof(chacha_out));
    memset(noiseBuffer, 0, sizeof(noiseBuffer));
}

int32_t TRNGNoiseSensor::runOnce() 
{
    init_entropy_pool();
    extract_entropy();
    memcpy(noiseBuffer, chacha_out , sizeof(noiseBuffer));
    return DEFAULT_SENSOR_MINIMUM_WAIT_TIME_BETWEEN_READS;
}

bool TRNGNoiseSensor::getMetrics(meshtastic_Telemetry *measurement) {
    runOnce();
    return false;
}

void TRNGNoiseSensor::stir() 
{
    // Make sure there are at least 32 bytes of entropy available
    if (RNG.available(MIN_ENTROPY_BYTES)) {
        LOG_INFO("TRNGNoiseSensor: sufficient entropy available, skipping stir");
        return;
    }
    runOnce();
    output(noiseBuffer, sizeof(noiseBuffer), CREDIT_BITS);
    LOG_INFO("TRNGNoiseSensor: added %d bits of entropy", CREDIT_BITS);
    cleanup();
}

void TRNGNoiseSensor::added() 
{}

bool TRNGNoiseSensor::calibrating() const 
{
    return false; // always ready
}

#endif
