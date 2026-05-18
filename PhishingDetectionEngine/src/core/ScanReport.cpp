#include "../../include/core/ScanReport.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>

ScanReport::ScanReport(const ScanInput& input) 
    : input_(input), timestamp_(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {
    scanId_ = generateScanId();
}

std::string ScanReport::generateScanId() {
    std::stringstream ss;
    ss << "SCAN-" << timestamp_;
    return ss.str();
}

void ScanReport::addResult(const ScanResult& result) {
    results_.push_back(result); // Will use copy constructor
}

void ScanReport::finalizeReport() {
    // Calculate total score using operator overloading
    ThreatScore combinedScore(0.0, 100.0);
    
    for (const auto& res : results_) {
        // Simple addition of scores. In a real engine, you'd weight them.
        combinedScore += res.getScore(); 
    }
    
    combinedScore.normalize();
    totalScore_ = combinedScore;
}

void ScanReport::exportToFile(const std::string& directory) const {
    // Create filename
    std::string filename = directory + scanId_ + ".txt";
    
    // Since we don't have C++17 std::filesystem included strictly in this snippet to make dir
    // We will just try to write. (In a full prod, use std::filesystem::create_directories)
    std::ofstream file(filename);
    if (file.is_open()) {
        file << *this; // Use overloaded << operator
        file.close();
    }
}

std::ostream& operator<<(std::ostream& os, const ScanReport& report) {
    os << "==================================================\n";
    os << "               PHISHING SCAN REPORT               \n";
    os << "==================================================\n";
    os << "Scan ID   : " << report.scanId_ << "\n";
    
    std::stringstream time_ss;
    time_ss << std::put_time(std::localtime(&report.timestamp_), "%Y-%m-%d %H:%M:%S");
    os << "Date      : " << time_ss.str() << "\n";
    
    os << "Target URL: " << report.input_.getUrl() << "\n";
    os << "Verdict   : ";
    
    switch (report.getFinalVerdict()) {
        case ThreatLevel::SAFE: os << "[SAFE]"; break;
        case ThreatLevel::LOW: os << "[LOW RISK]"; break;
        case ThreatLevel::MEDIUM: os << "[MEDIUM RISK]"; break;
        case ThreatLevel::HIGH: os << "[HIGH RISK - PHISHING LIKELY]"; break;
        case ThreatLevel::CRITICAL: os << "[CRITICAL - CONFIRMED PHISHING]"; break;
    }
    os << "\n";
    os << "Score     : " << report.totalScore_ << "\n";
    os << "--------------------------------------------------\n";
    
    os << "Detailed Findings:\n";
    for (const auto& res : report.results_) {
        os << "  > " << res.getAnalyzerName() << " (" << res.getScore() << ")\n";
        for (const auto& finding : res.getFindings()) {
            os << "    - " << finding << "\n";
        }
    }
    
    os << "==================================================\n";
    return os;
}
