#include "../../include/core/ScanResult.h"

ScanResult::ScanResult(const std::string& analyzerName) 
    : analyzerName_(analyzerName), score_(ThreatScore()), isPhishing_(false) {}

// Copy Constructor
ScanResult::ScanResult(const ScanResult& other)
    : analyzerName_(other.analyzerName_), 
      score_(other.score_), 
      findings_(other.findings_), 
      isPhishing_(other.isPhishing_) {}

// Copy Assignment
ScanResult& ScanResult::operator=(const ScanResult& other) {
    if (this != &other) {
        analyzerName_ = other.analyzerName_;
        score_ = other.score_;
        findings_ = other.findings_;
        isPhishing_ = other.isPhishing_;
    }
    return *this;
}

// Move Constructor
ScanResult::ScanResult(ScanResult&& other) noexcept
    : analyzerName_(std::move(other.analyzerName_)),
      score_(std::move(other.score_)),
      findings_(std::move(other.findings_)),
      isPhishing_(other.isPhishing_) {
    other.isPhishing_ = false;
}

// Move Assignment
ScanResult& ScanResult::operator=(ScanResult&& other) noexcept {
    if (this != &other) {
        analyzerName_ = std::move(other.analyzerName_);
        score_ = std::move(other.score_);
        findings_ = std::move(other.findings_);
        isPhishing_ = other.isPhishing_;
        other.isPhishing_ = false;
    }
    return *this;
}

void ScanResult::merge(const ScanResult& other) {
    score_ += other.score_; // Uses ThreatScore overloaded +=
    
    // Merge findings
    findings_.insert(findings_.end(), other.findings_.begin(), other.findings_.end());
    
    if (other.isPhishing_) {
        isPhishing_ = true;
    }
}
