#include "../../include/analyzers/DomainAnalyzer.h"
#include <algorithm>
#include <vector>

DomainAnalyzer::DomainAnalyzer() {
    suspiciousTLDs_ = {".tk", ".xyz", ".top", ".club", ".info", ".online", ".site"};
}

std::string DomainAnalyzer::extractDomain(const std::string& url) const {
    size_t start = url.find("://");
    if (start != std::string::npos) start += 3;
    else start = 0;

    size_t end = url.find('/', start);
    if (end == std::string::npos) end = url.length();
    
    // Strip port if present
    size_t port_pos = url.find(':', start);
    if (port_pos != std::string::npos && port_pos < end) {
        end = port_pos;
    }

    return url.substr(start, end - start);
}

int DomainAnalyzer::levenshteinDistance(const std::string& s1, const std::string& s2) const {
    const size_t len1 = s1.size(), len2 = s2.size();
    std::vector<std::vector<int>> d(len1 + 1, std::vector<int>(len2 + 1));

    for(size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for(size_t i = 0; i <= len2; ++i) d[0][i] = i;

    for(size_t i = 1; i <= len1; ++i) {
        for(size_t j = 1; j <= len2; ++j) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            d[i][j] = std::min({ d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost });
        }
    }
    return d[len1][len2];
}

bool DomainAnalyzer::isSuspiciousTLD(const std::string& domain) const {
    size_t lastDot = domain.find_last_of('.');
    if (lastDot != std::string::npos) {
        std::string tld = domain.substr(lastDot);
        // Convert to lowercase
        std::transform(tld.begin(), tld.end(), tld.begin(), ::tolower);
        return suspiciousTLDs_.find(tld) != suspiciousTLDs_.end();
    }
    return false;
}

std::string DomainAnalyzer::checkTyposquatting(const std::string& domain) const {
    // Hardcoded list for demonstration. 
    // In reality, this would check against a Database<std::string>
    std::vector<std::string> popularDomains = {"google.com", "paypal.com", "amazon.com", "apple.com", "microsoft.com", "netflix.com"};
    
    for (const auto& target : popularDomains) {
        // Don't flag exact matches
        if (domain == target) continue;
        
        // Check if the domain contains the target word (e.g. login-paypal.com)
        std::string targetWord = target.substr(0, target.find('.'));
        if (domain.find(targetWord) != std::string::npos && domain != target) {
            return target;
        }

        // Check Levenshtein distance for typos (e.g. g00gle.com)
        int dist = levenshteinDistance(domain, target);
        if (dist > 0 && dist <= 2) { 
            return target;
        }
    }
    return "";
}

ScanResult DomainAnalyzer::analyze(const ScanInput& input) {
    ScanResult result(getName());
    if (input.getType() == InputType::EMAIL) return result;

    std::string url = input.getUrl();
    std::string domain = extractDomain(url);
    double score = 0.0;

    // Check 1: Suspicious TLD
    if (isSuspiciousTLD(domain)) {
        score += 20.0;
        result.addFinding("Domain uses a suspicious or cheap TLD often associated with spam.");
    }

    // Check 2: Typosquatting / Brand impersonation
    std::string impersonated = checkTyposquatting(domain);
    if (!impersonated.empty()) {
        score += 60.0;
        result.addFinding("High probability of typosquatting. Impersonating: " + impersonated);
    }

    result.setScore(ThreatScore(score, 100.0));
    return result;
}
