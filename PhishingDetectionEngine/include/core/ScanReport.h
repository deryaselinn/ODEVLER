#ifndef SCANREPORT_H
#define SCANREPORT_H

#include "ScanInput.h"
#include "ScanResult.h"
#include <vector>
#include <string>
#include <ostream>

class ScanReport {
private:
    ScanInput input_;
    std::vector<ScanResult> results_;
    ThreatScore totalScore_;
    std::time_t timestamp_;
    std::string scanId_;

    std::string generateScanId();

public:
    explicit ScanReport(const ScanInput& input);

    void addResult(const ScanResult& result);
    void finalizeReport();

    // Getters
    const ScanInput& getInput() const { return input_; }
    const std::vector<ScanResult>& getResults() const { return results_; }
    ThreatScore getTotalScore() const { return totalScore_; }
    std::time_t getTimestamp() const { return timestamp_; }
    std::string getScanId() const { return scanId_; }
    
    ThreatLevel getFinalVerdict() const { return totalScore_.getLevel(); }
    bool isPhishing() const { return totalScore_.isPhishing(); }

    // Save report to file
    void exportToFile(const std::string& directory = "logs/") const;

    // Overloaded output operator for console UI
    friend std::ostream& operator<<(std::ostream& os, const ScanReport& report);
};

#endif // SCANREPORT_H
