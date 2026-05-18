#ifndef SCANINPUT_H
#define SCANINPUT_H

#include "../utils/Enums.h"
#include <string>
#include <ctime>

class ScanInput {
private:
    InputType type_;
    std::string url_;
    std::string content_;
    std::string emailHeader_;
    std::time_t timestamp_;

public:
    // Constructors for different input types
    ScanInput(const std::string& url); // URL only
    ScanInput(const std::string& url, const std::string& content); // URL + Content
    
    // Named constructor (static factory method) for Email
    static ScanInput createEmailInput(const std::string& emailHeader, const std::string& body = "");

    // Getters
    InputType getType() const { return type_; }
    std::string getUrl() const { return url_; }
    std::string getContent() const { return content_; }
    std::string getEmailHeader() const { return emailHeader_; }
    std::time_t getTimestamp() const { return timestamp_; }

    // Validation
    bool isValid() const;
};

#endif // SCANINPUT_H
