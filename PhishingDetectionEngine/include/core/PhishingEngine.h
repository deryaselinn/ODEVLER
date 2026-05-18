#ifndef PHISHINGENGINE_H
#define PHISHINGENGINE_H

#include "ScanInput.h"
#include "ScanReport.h"
#include "../analyzers/IAnalyzer.h"
#include "../utils/Logger.h"
#include <vector>
#include <memory>

class PhishingEngine {
private:
    std::vector<std::unique_ptr<IAnalyzer>> analyzers_;
    std::vector<ScanReport> scanHistory_;

public:
    PhishingEngine();
    
    // Prevent copying of the engine (due to unique_ptr)
    PhishingEngine(const PhishingEngine&) = delete;
    PhishingEngine& operator=(const PhishingEngine&) = delete;

    void addAnalyzer(std::unique_ptr<IAnalyzer> analyzer);
    void removeAnalyzer(const std::string& name);
    void clearAnalyzers();

    ScanReport scan(const ScanInput& input);
    
    const std::vector<ScanReport>& getHistory() const { return scanHistory_; }
    void clearHistory() { scanHistory_.clear(); }
    
    size_t getAnalyzerCount() const { return analyzers_.size(); }
};

#endif // PHISHINGENGINE_H
