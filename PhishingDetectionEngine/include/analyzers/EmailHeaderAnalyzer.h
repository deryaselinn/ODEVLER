#ifndef EMAILHEADERANALYZER_H
#define EMAILHEADERANALYZER_H

#include "IAnalyzer.h"
#include <string>

class EmailHeaderAnalyzer : public IAnalyzer {
private:
    std::string extractHeaderValue(const std::string& header, const std::string& key) const;
    bool hasAuthenticationFailures(const std::string& authResults) const;
    bool isReplyToMismatched(const std::string& from, const std::string& replyTo) const;

public:
    EmailHeaderAnalyzer() = default;

    ScanResult analyze(const ScanInput& input) override;
    std::string getName() const override { return "Email Header Analyzer"; }
    std::string getDescription() const override { return "Analyzes SPF, DKIM, DMARC, and sender mismatches in email headers."; }
};

#endif // EMAILHEADERANALYZER_H
