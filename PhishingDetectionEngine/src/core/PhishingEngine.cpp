#include "../../include/core/PhishingEngine.h"
#include <algorithm>

PhishingEngine::PhishingEngine() {
    Logger::getInstance().info("Phishing Engine initialized.");
}

void PhishingEngine::addAnalyzer(std::unique_ptr<IAnalyzer> analyzer) {
    if (analyzer) {
        Logger::getInstance().info("Added analyzer: " + analyzer->getName());
        analyzers_.push_back(std::move(analyzer));
    }
}

void PhishingEngine::removeAnalyzer(const std::string& name) {
    auto it = std::remove_if(analyzers_.begin(), analyzers_.end(),
        [&name](const std::unique_ptr<IAnalyzer>& a) { return a->getName() == name; });
        
    if (it != analyzers_.end()) {
        analyzers_.erase(it, analyzers_.end());
        Logger::getInstance().info("Removed analyzer: " + name);
    }
}

void PhishingEngine::clearAnalyzers() {
    analyzers_.clear();
    Logger::getInstance().info("All analyzers cleared.");
}

ScanReport PhishingEngine::scan(const ScanInput& input) {
    Logger::getInstance().info("Starting new scan for URL: " + input.getUrl());
    
    ScanReport report(input);
    
    if (!input.isValid()) {
        Logger::getInstance().warning("Invalid scan input provided.");
        return report;
    }

    // Polymorphic execution of all registered analyzers
    for (const auto& analyzer : analyzers_) {
        // Run uses the Template Method pattern defined in IAnalyzer
        ScanResult result = analyzer->run(input);
        report.addResult(result);
        
        // Short-circuit if a critical threat is found
        if (result.getScore().getLevel() == ThreatLevel::CRITICAL) {
            Logger::getInstance().warning("CRITICAL threat found by " + analyzer->getName() + ". Short-circuiting scan.");
            break;
        }
    }
    
    report.finalizeReport();
    scanHistory_.push_back(report); // Store in history
    
    Logger::getInstance().info("Scan complete. Final verdict: " + 
        std::to_string(static_cast<int>(report.getFinalVerdict())));
        
    return report;
}
