package com.apishield.event.api;

import com.apishield.model.ThreatSignal;

/**
 * One detector's verdict within a {@link SecurityEventResponse}.
 */
public record ThreatSignalResponse(String detector, boolean detected, double severity, String description) {

    static ThreatSignalResponse from(ThreatSignal signal) {
        return new ThreatSignalResponse(signal.detectorName(), signal.threatDetected(), signal.severity(),
                signal.description());
    }
}
