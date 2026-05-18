#ifndef SCANRESULT_H
#define SCANRESULT_H

#include "ThreatScore.h"
#include <string>
#include <vector>

class ScanResult {
private:
    std::string analyzerName_;
    ThreatScore score_;
    std::vector<std::string> findings_;
    bool isPhishing_;

public:
    // Constructors
    ScanResult(const std::string& analyzerName = "Unknown");
    
    // Copy Constructor & Assignment Operator (Copy Semantics)
    ScanResult(const ScanResult& other);
    ScanResult& operator=(const ScanResult& other);

    // Move Constructor & Assignment Operator (Move Semantics)
    ScanResult(ScanResult&& other) noexcept;
    ScanResult& operator=(ScanResult&& other) noexcept;

    // Setters
    void setScore(const ThreatScore& score) { score_ = score; isPhishing_ = score.isPhishing(); }
    void addFinding(const std::string& finding) { findings_.push_back(finding); }
    void setPhishing(bool isPhishing) { isPhishing_ = isPhishing; }

    // Getters
    std::string getAnalyzerName() const { return analyzerName_; }
    ThreatScore getScore() const { return score_; }
    const std::vector<std::string>& getFindings() const { return findings_; }
    bool isPhishing() const { return isPhishing_; }

    // Merge another result into this one
    void merge(const ScanResult& other);
};

#endif // SCANRESULT_H
