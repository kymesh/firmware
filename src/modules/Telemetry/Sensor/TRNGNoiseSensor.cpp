#include "TRNGNoiseSensor.h"
#include "RNG.h"
/*
Base Class: TelemetrySensor

Key methods:
- setup() - configure your pins
- runOnce() - read the pins periodically
- getMetrics() - return the readings as telemetry data
- hasSensor() - return true if pins are available */

#if !MESHTASTIC_EXCLUDE_TRNG

TRNGNoiseSensor::TRNGNoiseSensor() : TelemetrySensor(meshtastic_TelemetrySensorType_TRNG, "TRNG"), analogPin(A0), noiseValue(0)
{}

void TRNGNoiseSensor::setup()
{
    pinMode(analogPin, INPUT);
    RNG.addNoiseSource(*this);
}

int32_t TRNGNoiseSensor::runOnce() 
{
    noiseValue = 0;
    for (unsigned long i = 0; i < 16; ++i) {
        uint32_t noise = analogRead(analogPin);
        uint8_t bit0 = (noise >> 0) & 1;
        uint8_t bit4 = (noise >> 4) & 1;
        uint32_t twoBits = (bit4 << 1) | bit0;

        noiseValue |= (twoBits << (i * 2));
        // delayMicroseconds(20);
    }
    return DEFAULT_SENSOR_MINIMUM_WAIT_TIME_BETWEEN_READS;
}

bool TRNGNoiseSensor::getMetrics(meshtastic_Telemetry *measurement) {
    runOnce();
    return false;
}

void TRNGNoiseSensor::stir() 
{
    if (RNG.available(sizeof(noiseValue))) {
        return;
    }
    runOnce();
    output(reinterpret_cast<const uint8_t *>(&noiseValue), sizeof(noiseValue), 8);
}

void TRNGNoiseSensor::added() 
{}

bool TRNGNoiseSensor::calibrating() const 
{
    return false; // always ready
}

#endif
