#pragma once

#include "TelemetrySensor.h"

class TRNGNoiseSensor : public TelemetrySensor
{
  private:
    uint8_t analogPin;
    uint16_t noiseValue;

  public:
    TRNGNoiseSensor();
    virtual void setup() override;
    virtual int32_t runOnce() override;
    virtual bool getMetrics(meshtastic_Telemetry *measurement) override;
};