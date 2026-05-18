#include "../../include/analyzers/BlacklistAnalyzer.h"

BlacklistAnalyzer::BlacklistAnalyzer(const std::string& blacklistFile, const std::string& whitelistFile) 
    : blacklistDB_("BlacklistDB"), whitelistDB_("WhitelistDB") {
    
    try {
        blacklistDB_.loadFromFile(blacklistFile);
        Logger::getInstance().info("Loaded blacklist database. Size: " + std::to_string(blacklistDB_.size()));
    } catch (const DatabaseException& e) {
        Logger::getInstance().error("Failed to load blacklist: " + std::string(e.what()));
    }

    try {
        whitelistDB_.loadFromFile(whitelistFile);
        Logger::getInstance().info("Loaded whitelist database. Size: " + std::to_string(whitelistDB_.size()));
    } catch (const DatabaseException& e) {
        Logger::getInstance().warning("Failed to load whitelist: " + std::string(e.what()));
    }
}

std::string BlacklistAnalyzer::extractDomain(const std::string& url) const {
    size_t start = url.find("://");
    if (start != std::string::npos) start += 3;
    else start = 0;

    size_t end = url.find('/', start);
    if (end == std::string::npos) end = url.length();
    
    size_t port_pos = url.find(':', start);
    if (port_pos != std::string::npos && port_pos < end) {
        end = port_pos;
    }

    return url.substr(start, end - start);
}

ScanResult BlacklistAnalyzer::analyze(const ScanInput& input) {
    ScanResult result(getName());
    
    if (input.getType() == InputType::EMAIL && input.getUrl().empty()) {
        return result; // Can't analyze URL if there is none
    }

    std::string url = input.getUrl();
    std::string domain = extractDomain(url);

    // Whitelist check first
    if (whitelistDB_.contains(domain)) {
        result.addFinding("Domain is in the trusted whitelist. Safe.");
        result.setScore(ThreatScore(0.0, 100.0));
        return result;
    }

    // Blacklist check
    if (blacklistDB_.contains(domain) || blacklistDB_.contains(url)) {
        result.addFinding("DANGER: This URL or Domain was found in the known phishing blacklist!");
        result.setScore(ThreatScore(100.0, 100.0)); // Immediate critical score
        return result;
    }

    // Default safe if not in either list
    result.setScore(ThreatScore(0.0, 100.0));
    return result;
}
