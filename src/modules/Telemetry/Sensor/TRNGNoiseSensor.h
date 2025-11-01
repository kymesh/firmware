#pragma once

#include "TelemetrySensor.h"
#include "NoiseSource.h"

class TRNGNoiseSensor : public TelemetrySensor, public NoiseSource
{
  private:
    uint8_t analogPin;
    uint8_t noiseBuffer[48];
    uint32_t counter;

    void sample_noise(uint8_t *buf, size_t len);
    void add_entropy();
    void init_entropy_pool();
    void extract_entropy();
    void cleanup();
    
  public:
    TRNGNoiseSensor();
    ~TRNGNoiseSensor();
    virtual void setup() override;
    virtual int32_t runOnce() override;
    virtual bool getMetrics(meshtastic_Telemetry *measurement) override;

    // NoiseSource interface
    void stir() override;
    void added() override;
    bool calibrating() const override;
};