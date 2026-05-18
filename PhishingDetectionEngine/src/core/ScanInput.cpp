#include "../../include/core/ScanInput.h"
#include <chrono>

ScanInput::ScanInput(const std::string& url) 
    : type_(InputType::URL_ONLY), url_(url), content_(""), emailHeader_("") {
    timestamp_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

ScanInput::ScanInput(const std::string& url, const std::string& content)
    : type_(InputType::FULL_PAGE), url_(url), content_(content), emailHeader_("") {
    timestamp_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

ScanInput ScanInput::createEmailInput(const std::string& emailHeader, const std::string& body) {
    ScanInput input(""); // Temp URL
    input.type_ = InputType::EMAIL;
    input.emailHeader_ = emailHeader;
    input.content_ = body;
    input.timestamp_ = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    return input;
}

bool ScanInput::isValid() const {
    if (type_ == InputType::URL_ONLY || type_ == InputType::FULL_PAGE) {
        return !url_.empty();
    } else if (type_ == InputType::EMAIL) {
        return !emailHeader_.empty();
    }
    return false;
}
