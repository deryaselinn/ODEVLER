#ifndef IANALYZER_H
#define IANALYZER_H

#include "../core/ScanInput.h"
#include "../core/ScanResult.h"
#include "../utils/Logger.h"
#include <string>

// Abstract Base Class / Interface
class IAnalyzer {
public:
    virtual ~IAnalyzer() = default;

    // Pure virtual functions that must be implemented by derived classes
    virtual ScanResult analyze(const ScanInput& input) = 0;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;

    // Template Method Pattern: Defines the skeleton of the algorithm
    // This is not virtual because the general flow should remain the same
    ScanResult run(const ScanInput& input) {
        Logger::getInstance().info("Starting analyzer: " + getName());
        
        try {
            ScanResult result = analyze(input);
            Logger::getInstance().info("Finished analyzer: " + getName() + 
                                     ". Phishing: " + (result.isPhishing() ? "Yes" : "No"));
            return result;
        } catch (const std::exception& e) {
            Logger::getInstance().error("Error in analyzer " + getName() + ": " + e.what());
            
            // Return a safe default on error
            ScanResult errorResult(getName());
            errorResult.addFinding("Analyzer failed to execute: " + std::string(e.what()));
            return errorResult;
        }
    }
};

#endif // IANALYZER_H
