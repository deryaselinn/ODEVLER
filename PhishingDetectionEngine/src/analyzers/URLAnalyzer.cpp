#include "../../include/analyzers/URLAnalyzer.h"
#include <regex>
#include <iostream>

URLAnalyzer::URLAnalyzer() {
    suspiciousChars_ = {"@", "-", "_", "~"};
}

bool URLAnalyzer::hasIPAddress(const std::string& url) const {
    // Basic regex for IPv4
    std::regex ipRegex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    return std::regex_search(url, ipRegex);
}

bool URLAnalyzer::hasSuspiciousChars(const std::string& url, int& count) const {
    count = 0;
    for (char c : url) {
        if (c == '@' || c == '-') count++;
    }
    return count > 2; // Threshold
}

bool URLAnalyzer::isTooLong(const std::string& url) const {
    return url.length() > 75;
}

bool URLAnalyzer::hasMultipleSubdomains(const std::string& url, int& depth) const {
    // Simplified: count dots in the domain part
    size_t start = url.find("://");
    if (start != std::string::npos) start += 3;
    else start = 0;

    size_t end = url.find('/', start);
    if (end == std::string::npos) end = url.length();

    std::string domainPart = url.substr(start, end - start);
    
    depth = 0;
    for (char c : domainPart) {
        if (c == '.') depth++;
    }
    
    return depth > 3; // e.g., a.b.c.example.com has 4 dots, 5 parts
}

bool URLAnalyzer::isHTTPS(const std::string& url) const {
    return url.find("https://") == 0;
}

ScanResult URLAnalyzer::analyze(const ScanInput& input) {
    ScanResult result(getName());
    
    if (input.getType() == InputType::EMAIL) {
        // Nothing to do if it's just an email header
        return result;
    }

    std::string url = input.getUrl();
    double score = 0.0;
    
    // Rule 1: IP Address in URL
    if (hasIPAddress(url)) {
        score += 40.0;
        result.addFinding("URL uses an IP address instead of a domain name.");
    }
    
    // Rule 2: Suspicious Characters
    int charCount = 0;
    if (hasSuspiciousChars(url, charCount)) {
        score += 15.0;
        result.addFinding("URL contains multiple suspicious characters (@, -). Count: " + std::to_string(charCount));
    }
    
    // Rule 3: URL Length
    if (isTooLong(url)) {
        score += 10.0;
        result.addFinding("URL is abnormally long (" + std::to_string(url.length()) + " chars).");
    }
    
    // Rule 4: Subdomain Depth
    int depth = 0;
    if (hasMultipleSubdomains(url, depth)) {
        score += 25.0;
        result.addFinding("Deeply nested subdomains detected. Depth: " + std::to_string(depth));
    }
    
    // Rule 5: Missing HTTPS
    if (!isHTTPS(url) && url.find("http://") == 0) {
        score += 10.0;
        result.addFinding("Connection is not secure (HTTP instead of HTTPS).");
    }

    result.setScore(ThreatScore(score, 100.0));
    return result;
}
