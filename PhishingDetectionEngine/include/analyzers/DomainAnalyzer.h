#ifndef DOMAINANALYZER_H
#define DOMAINANALYZER_H

#include "IAnalyzer.h"
#include <string>
#include <set>

class DomainAnalyzer : public IAnalyzer {
private:
    std::set<std::string> suspiciousTLDs_;
    
    std::string extractDomain(const std::string& url) const;
    int levenshteinDistance(const std::string& s1, const std::string& s2) const;
    bool isSuspiciousTLD(const std::string& domain) const;
    std::string checkTyposquatting(const std::string& domain) const;

public:
    DomainAnalyzer();

    ScanResult analyze(const ScanInput& input) override;
    std::string getName() const override { return "Domain Reputation Analyzer"; }
    std::string getDescription() const override { return "Checks domain reputation, TLDs, and typosquatting."; }
};

#endif // DOMAINANALYZER_H
