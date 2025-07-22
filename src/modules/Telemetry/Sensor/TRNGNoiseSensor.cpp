

#include "TRNGNoiseSensor.h"
/*
Base Class: TelemetrySensor

Key methods:
- setup() - configure your pins
- runOnce() - read the pins periodically
- getMetrics() - return the readings as telemetry data
- hasSensor() - return true if pins are available */

#if !MESHTASTIC_EXCLUDE_TRNG

TRNGNoiseSensor::TRNGNoiseSensor() : TelemetrySensor(mesh_tastic_TelemetrySensorType_TRNG, "TRNG"), analogPin(A0), noiseValue(0)
{
}

int32_t TRNGNoiseSensor::runOnce() {}

void TRNGNoiseSensor::setup()
{
    pinMode(analogPin, INPUT);

    /* Should also add this as a noise source */
}

bool TRNGNoiseSensor::getMetrics(meshtastic_Telemetry *measurement) {}

#endif
