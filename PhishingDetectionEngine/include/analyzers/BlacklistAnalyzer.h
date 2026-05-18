#ifndef BLACKLISTANALYZER_H
#define BLACKLISTANALYZER_H

#include "IAnalyzer.h"
#include "../utils/Database.h"

class BlacklistAnalyzer : public IAnalyzer {
private:
    Database<std::string> blacklistDB_;
    Database<std::string> whitelistDB_;
    
    std::string extractDomain(const std::string& url) const;

public:
    BlacklistAnalyzer(const std::string& blacklistFile = "data/blacklist.txt", 
                      const std::string& whitelistFile = "data/whitelist.txt");

    ScanResult analyze(const ScanInput& input) override;
    std::string getName() const override { return "Blacklist Analyzer"; }
    std::string getDescription() const override { return "Checks URLs and domains against known threat databases."; }
};

#endif // BLACKLISTANALYZER_H
