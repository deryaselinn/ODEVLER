#ifndef LOGGER_H
#define LOGGER_H

#include "Enums.h"
#include <string>
#include <fstream>
#include <mutex>

// Singleton pattern for logging
class Logger {
private:
    static Logger* instance_;
    static std::mutex mutex_;
    
    std::ofstream logFile_;
    LogLevel minLogLevel_;

    // Private constructor for Singleton
    Logger();
    ~Logger();

    // Prevent copying and assignment
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string levelToString(LogLevel level) const;
    std::string getCurrentTime() const;

public:
    static Logger& getInstance();

    void setLogLevel(LogLevel level);
    void log(LogLevel level, const std::string& message);
    
    // Convenience methods
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warning(const std::string& message) { log(LogLevel::WARNING, message); }
    void error(const std::string& message) { log(LogLevel::ERROR, message); }
    void critical(const std::string& message) { log(LogLevel::CRITICAL_ERROR, message); }
};

#endif // LOGGER_H
