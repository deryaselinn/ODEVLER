#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <stdexcept>
#include <string>

// Base exception class for the engine
class PhishingEngineException : public std::runtime_error {
public:
    explicit PhishingEngineException(const std::string& message) 
        : std::runtime_error("PhishingEngine Error: " + message) {}
};

// Exception for invalid input data
class InvalidInputException : public PhishingEngineException {
public:
    explicit InvalidInputException(const std::string& message)
        : PhishingEngineException("Invalid Input: " + message) {}
};

// Exception for database/file errors
class DatabaseException : public PhishingEngineException {
public:
    explicit DatabaseException(const std::string& message)
        : PhishingEngineException("Database Error: " + message) {}
};

// Exception for analyzer execution errors
class AnalyzerException : public PhishingEngineException {
public:
    explicit AnalyzerException(const std::string& message)
        : PhishingEngineException("Analyzer Error: " + message) {}
};

#endif // EXCEPTIONS_H
