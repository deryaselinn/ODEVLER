#include "../../include/core/ThreatScore.h"
#include <algorithm>

ThreatScore::ThreatScore(double score, double maxScore) : score_(score), maxScore_(maxScore) {
    if (score_ < 0) score_ = 0;
    if (score_ > maxScore_) score_ = maxScore_;
}

ThreatScore::ThreatScore(const ThreatScore& other) : score_(other.score_), maxScore_(other.maxScore_) {}

ThreatLevel ThreatScore::getLevel() const {
    double percentage = (score_ / maxScore_) * 100.0;
    
    if (percentage == 0) return ThreatLevel::SAFE;
    if (percentage < 25) return ThreatLevel::LOW;
    if (percentage < 50) return ThreatLevel::MEDIUM;
    if (percentage < 75) return ThreatLevel::HIGH;
    return ThreatLevel::CRITICAL;
}

bool ThreatScore::isPhishing() const {
    return (score_ / maxScore_) >= 0.5; // 50% threshold
}

void ThreatScore::normalize() {
    if (maxScore_ != 100.0) {
        score_ = (score_ / maxScore_) * 100.0;
        maxScore_ = 100.0;
    }
}

// Operator Overloading Implementation
ThreatScore ThreatScore::operator+(const ThreatScore& other) const {
    // When adding scores, we cap at the maximum
    double newMax = std::max(maxScore_, other.maxScore_);
    double newScore = std::min(score_ + other.score_, newMax);
    return ThreatScore(newScore, newMax);
}

ThreatScore& ThreatScore::operator+=(const ThreatScore& other) {
    score_ += other.score_;
    if (score_ > maxScore_) score_ = maxScore_;
    return *this;
}

bool ThreatScore::operator>(const ThreatScore& other) const {
    return (score_ / maxScore_) > (other.score_ / other.maxScore_);
}

bool ThreatScore::operator<(const ThreatScore& other) const {
    return (score_ / maxScore_) < (other.score_ / other.maxScore_);
}

bool ThreatScore::operator==(const ThreatScore& other) const {
    return (score_ / maxScore_) == (other.score_ / other.maxScore_);
}

// Friend function implementation
std::ostream& operator<<(std::ostream& os, const ThreatScore& ts) {
    os << ts.score_ << "/" << ts.maxScore_ << " (";
    
    switch (ts.getLevel()) {
        case ThreatLevel::SAFE: os << "SAFE"; break;
        case ThreatLevel::LOW: os << "LOW"; break;
        case ThreatLevel::MEDIUM: os << "MEDIUM"; break;
        case ThreatLevel::HIGH: os << "HIGH"; break;
        case ThreatLevel::CRITICAL: os << "CRITICAL"; break;
    }
    
    os << ")";
    return os;
}
