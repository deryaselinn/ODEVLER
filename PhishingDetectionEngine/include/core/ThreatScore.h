#ifndef THREATSCORE_H
#define THREATSCORE_H

#include "../utils/Enums.h"
#include <iostream>

class ThreatScore {
private:
    double score_;
    double maxScore_;

public:
    // Constructors
    ThreatScore(double score = 0.0, double maxScore = 100.0);
    
    // Copy Constructor
    ThreatScore(const ThreatScore& other);

    // Getters
    double getScore() const { return score_; }
    double getMaxScore() const { return maxScore_; }
    
    // Determine the threat level based on score
    ThreatLevel getLevel() const;
    
    // Determine if it's considered phishing (score > 50)
    bool isPhishing() const;

    // Normalize score to 0-100 range
    void normalize();

    // Operator Overloading
    
    // Add two scores together
    ThreatScore operator+(const ThreatScore& other) const;
    
    // Add score to existing
    ThreatScore& operator+=(const ThreatScore& other);
    
    // Compare scores
    bool operator>(const ThreatScore& other) const;
    bool operator<(const ThreatScore& other) const;
    bool operator==(const ThreatScore& other) const;

    // Friend function for easy output
    friend std::ostream& operator<<(std::ostream& os, const ThreatScore& ts);
};

#endif // THREATSCORE_H
