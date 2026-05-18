#include "../../include/utils/Logger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

Logger* Logger::instance_ = nullptr;
std::mutex Logger::mutex_;

Logger::Logger() : minLogLevel_(LogLevel::INFO) {
    logFile_.open("phishing_engine.log", std::ios::app);
    if (!logFile_.is_open()) {
        std::cerr << "Failed to open log file!" << std::endl;
    }
}

Logger::~Logger() {
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

Logger& Logger::getInstance() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = new Logger();
    }
    return *instance_;
}

void Logger::setLogLevel(LogLevel level) {
    minLogLevel_ = level;
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL_ERROR: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < minLogLevel_) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string logEntry = "[" + getCurrentTime() + "] [" + levelToString(level) + "] " + message;
    
    // Write to file
    if (logFile_.is_open()) {
        logFile_ << logEntry << std::endl;
    }
    
    // Write to console for warning and above
    if (level >= LogLevel::WARNING) {
        std::cerr << logEntry << std::endl;
    }
}
