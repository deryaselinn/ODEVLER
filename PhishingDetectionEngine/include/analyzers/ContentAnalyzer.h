#ifndef CONTENTANALYZER_H
#define CONTENTANALYZER_H

#include "IAnalyzer.h"
#include "../utils/Database.h"

class ContentAnalyzer : public IAnalyzer {
private:
    Database<std::string> keywordsDB_;

    int countKeywords(const std::string& content) const;
    bool hasLoginForms(const std::string& content) const;
    bool hasHiddenIframes(const std::string& content) const;

public:
    ContentAnalyzer(const std::string& keywordFile = "data/phishing_keywords.txt");

    ScanResult analyze(const ScanInput& input) override;
    std::string getName() const override { return "Content Analysis"; }
    std::string getDescription() const override { return "Analyzes page source code for malicious patterns."; }
};

#endif // CONTENTANALYZER_H
