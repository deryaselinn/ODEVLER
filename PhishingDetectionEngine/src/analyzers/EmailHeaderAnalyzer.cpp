#include "../../include/analyzers/EmailHeaderAnalyzer.h"
#include <algorithm>

std::string EmailHeaderAnalyzer::extractHeaderValue(const std::string& header, const std::string& key) const {
    std::string lowerHeader = header;
    std::string lowerKey = key;
    std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);
    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    
    size_t pos = lowerHeader.find(lowerKey + ":");
    if (pos == std::string::npos) return "";

    pos += key.length() + 1; // Skip "key:"
    
    // Skip whitespace
    while (pos < header.length() && (header[pos] == ' ' || header[pos] == '\t')) {
        pos++;
    }

    size_t endPos = header.find('\n', pos);
    if (endPos == std::string::npos) endPos = header.length();

    // Check for multi-line headers (folding)
    while (endPos + 1 < header.length() && (header[endPos + 1] == ' ' || header[endPos + 1] == '\t')) {
        endPos = header.find('\n', endPos + 1);
        if (endPos == std::string::npos) {
            endPos = header.length();
            break;
        }
    }

    return header.substr(pos, endPos - pos);
}

bool EmailHeaderAnalyzer::hasAuthenticationFailures(const std::string& authResults) const {
    std::string lowerAuth = authResults;
    std::transform(lowerAuth.begin(), lowerAuth.end(), lowerAuth.begin(), ::tolower);
    
    return lowerAuth.find("spf=fail") != std::string::npos || 
           lowerAuth.find("spf=softfail") != std::string::npos ||
           lowerAuth.find("dkim=fail") != std::string::npos ||
           lowerAuth.find("dmarc=fail") != std::string::npos;
}

bool EmailHeaderAnalyzer::isReplyToMismatched(const std::string& from, const std::string& replyTo) const {
    if (replyTo.empty()) return false;
    
    // Simple check to see if the domains differ
    auto extractDomain = [](const std::string& addr) {
        size_t atPos = addr.find('@');
        if (atPos == std::string::npos) return std::string("");
        size_t endPos = addr.find('>', atPos);
        if (endPos == std::string::npos) endPos = addr.length();
        return addr.substr(atPos + 1, endPos - atPos - 1);
    };

    std::string fromDomain = extractDomain(from);
    std::string replyDomain = extractDomain(replyTo);

    return !fromDomain.empty() && !replyDomain.empty() && fromDomain != replyDomain;
}

ScanResult EmailHeaderAnalyzer::analyze(const ScanInput& input) {
    ScanResult result(getName());
    
    if (input.getType() != InputType::EMAIL && input.getEmailHeader().empty()) {
        return result;
    }

    std::string header = input.getEmailHeader();
    double score = 0.0;

    std::string authResults = extractHeaderValue(header, "Authentication-Results");
    std::string from = extractHeaderValue(header, "From");
    std::string replyTo = extractHeaderValue(header, "Reply-To");

    // Check 1: Authentication Failures
    if (hasAuthenticationFailures(authResults)) {
        score += 50.0;
        result.addFinding("Email failed SPF, DKIM, or DMARC authentication checks.");
    }

    // Check 2: Missing Authentication
    if (authResults.empty()) {
        score += 20.0;
        result.addFinding("No Authentication-Results header found. The email may be spoofed.");
    }

    // Check 3: Reply-To Mismatch
    if (isReplyToMismatched(from, replyTo)) {
        score += 35.0;
        result.addFinding("The 'Reply-To' domain does not match the 'From' domain.");
    }

    result.setScore(ThreatScore(score, 100.0));
    return result;
}
