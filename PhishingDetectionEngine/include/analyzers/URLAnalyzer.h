#ifndef URLANALYZER_H
#define URLANALYZER_H

#include "IAnalyzer.h"
#include <vector>
#include <string>

class URLAnalyzer : public IAnalyzer {
private:
    std::vector<std::string> suspiciousChars_;
    
    // Helper analysis methods
    bool hasIPAddress(const std::string& url) const;
    bool hasSuspiciousChars(const std::string& url, int& count) const;
    bool isTooLong(const std::string& url) const;
    bool hasMultipleSubdomains(const std::string& url, int& depth) const;
    bool isHTTPS(const std::string& url) const;

public:
    URLAnalyzer();

    // Override pure virtual functions
    ScanResult analyze(const ScanInput& input) override;
    std::string getName() const override { return "URL Structure Analyzer"; }
    std::string getDescription() const override { return "Analyzes URL lexical structure for phishing indicators."; }
};

#endif // URLANALYZER_H
