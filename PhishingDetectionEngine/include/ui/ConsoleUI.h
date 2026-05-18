#ifndef CONSOLEUI_H
#define CONSOLEUI_H

#include "../core/PhishingEngine.h"

class ConsoleUI {
private:
    PhishingEngine& engine_;

    void displayHeader() const;
    void displayMenu() const;
    void handleURLScan();
    void handleEmailScan();
    void handleContentScan();
    void displayHistory() const;
    void handleExportReport() const;
    
    std::string readMultilineInput() const;

public:
    explicit ConsoleUI(PhishingEngine& engine);
    void run();
};

#endif // CONSOLEUI_H
