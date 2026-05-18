#include "../include/core/PhishingEngine.h"
#include "../include/analyzers/URLAnalyzer.h"
#include "../include/analyzers/DomainAnalyzer.h"
#include "../include/analyzers/ContentAnalyzer.h"
#include "../include/analyzers/EmailHeaderAnalyzer.h"
#include "../include/analyzers/BlacklistAnalyzer.h"
#include "../include/ui/ConsoleUI.h"
#include "../include/utils/Logger.h"

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
#ifdef _WIN32
    // Enable ANSI escape codes for Windows console
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    SetConsoleOutputCP(CP_UTF8);
#endif

    // Setup logging
    Logger::getInstance().setLogLevel(LogLevel::INFO);
    Logger::getInstance().info("Application starting...");

    try {
        // Initialize Core Engine
        PhishingEngine engine;

        // Register Analyzers (Composition & Polymorphism)
        engine.addAnalyzer(std::make_unique<URLAnalyzer>());
        engine.addAnalyzer(std::make_unique<DomainAnalyzer>());
        engine.addAnalyzer(std::make_unique<ContentAnalyzer>("data/phishing_keywords.txt"));
        engine.addAnalyzer(std::make_unique<EmailHeaderAnalyzer>());
        engine.addAnalyzer(std::make_unique<BlacklistAnalyzer>("data/blacklist.txt", "data/whitelist.txt"));

        // Initialize and run UI
        ConsoleUI ui(engine);
        ui.run();

    } catch (const std::exception& e) {
        Logger::getInstance().critical("Fatal error: " + std::string(e.what()));
        return 1;
    }

    Logger::getInstance().info("Application shutting down gracefully.");
    return 0;
}
