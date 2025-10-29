#pragma once

#include "TelemetrySensor.h"
#include "NoiseSource.h"

class TRNGNoiseSensor : public TelemetrySensor, public NoiseSource
{
  private:
    uint8_t analogPin;
    uint32_t noiseValue;
    
  public:
    TRNGNoiseSensor();
    virtual void setup() override;
    virtual int32_t runOnce() override;
    virtual bool getMetrics(meshtastic_Telemetry *measurement) override;

    // NoiseSource interface
    void stir() override;   // called by RNG to pull entropy
    void added() override;  // optional, called when added to RNG
    bool calibrating() const override;
};