#ifndef ENUMS_H
#define ENUMS_H

enum class ThreatLevel {
    SAFE,       // No threats detected
    LOW,        // Minor suspicious indicators
    MEDIUM,     // Several suspicious indicators
    HIGH,       // Strong indicators of phishing
    CRITICAL    // Confirmed malicious
};

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL_ERROR
};

enum class InputType {
    URL_ONLY,
    EMAIL,
    FULL_PAGE
};

#endif // ENUMS_H
