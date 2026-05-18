#include "../../include/analyzers/ContentAnalyzer.h"
#include <algorithm>

ContentAnalyzer::ContentAnalyzer(const std::string& keywordFile) : keywordsDB_("KeywordsDB") {
    try {
        keywordsDB_.loadFromFile(keywordFile);
    } catch (const DatabaseException& e) {
        Logger::getInstance().warning("Could not load keywords from " + keywordFile + ". Using default.");
        keywordsDB_.add("login");
        keywordsDB_.add("verify");
        keywordsDB_.add("suspend");
        keywordsDB_.add("urgent");
        keywordsDB_.add("update billing");
    }
}

int ContentAnalyzer::countKeywords(const std::string& content) const {
    int count = 0;
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    for (const auto& keyword : keywordsDB_) {
        // Simple search.
        size_t pos = lowerContent.find(keyword);
        while (pos != std::string::npos) {
            count++;
            pos = lowerContent.find(keyword, pos + keyword.length());
        }
    }
    return count;
}

bool ContentAnalyzer::hasLoginForms(const std::string& content) const {
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
    
    bool hasPasswordInput = lowerContent.find("type=\"password\"") != std::string::npos ||
                            lowerContent.find("type='password'") != std::string::npos;
    bool hasForm = lowerContent.find("<form") != std::string::npos;
    
    return hasForm && hasPasswordInput;
}

bool ContentAnalyzer::hasHiddenIframes(const std::string& content) const {
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
    
    return lowerContent.find("<iframe") != std::string::npos && 
           (lowerContent.find("visibility:hidden") != std::string::npos || 
            lowerContent.find("display:none") != std::string::npos ||
            lowerContent.find("width=\"0\"") != std::string::npos ||
            lowerContent.find("height=\"0\"") != std::string::npos);
}

ScanResult ContentAnalyzer::analyze(const ScanInput& input) {
    ScanResult result(getName());
    if (input.getType() == InputType::URL_ONLY) {
        // Need content to analyze content
        return result;
    }

    std::string content = input.getContent();
    if (content.empty()) return result;

    double score = 0.0;

    // Check 1: Keywords
    int keywordCount = countKeywords(content);
    if (keywordCount > 3) {
        score += 30.0;
        result.addFinding("High concentration of phishing-related keywords found. Count: " + std::to_string(keywordCount));
    }

    // Check 2: Login Forms
    if (hasLoginForms(content)) {
        score += 20.0; // Finding a login form isn't inherently bad, but adds weight to other bad indicators
        result.addFinding("Page contains a password input form.");
    }

    // Check 3: Hidden Iframes
    if (hasHiddenIframes(content)) {
        score += 40.0;
        result.addFinding("Page contains hidden iframes (often used for malicious payloads or invisible forms).");
    }

    result.setScore(ThreatScore(score, 100.0));
    return result;
}
