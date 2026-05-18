#include "../../include/ui/ConsoleUI.h"
#include <iostream>
#include <string>

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"

ConsoleUI::ConsoleUI(PhishingEngine& engine) : engine_(engine) {}

void ConsoleUI::displayHeader() const {
    std::cout << CYAN << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║         🛡️  PHISHING DETECTION ENGINE v1.0  🛡️          ║\n";
    std::cout << "║              Security Analysis Tool                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n" << RESET;
}

void ConsoleUI::displayMenu() const {
    std::cout << "\n";
    std::cout << "   [1] " << YELLOW << "🔍 URL Tarama (Scan URL)" << RESET << "\n";
    std::cout << "   [2] " << YELLOW << "📧 E-posta Analizi (Email Analysis)" << RESET << "\n";
    std::cout << "   [3] " << YELLOW << "📄 Sayfa İçerik Analizi (Content Analysis)" << RESET << "\n";
    std::cout << "   [4] " << YELLOW << "📊 Tarama Geçmişi (Scan History)" << RESET << "\n";
    std::cout << "   [5] " << YELLOW << "📋 Rapor Dışa Aktar (Export Report)" << RESET << "\n";
    std::cout << "   [6] " << RED << "❌ Çıkış (Exit)" << RESET << "\n";
    std::cout << "\n";
    std::cout << "   Aktif Analyzer Sayısı: " << engine_.getAnalyzerCount() 
              << "  |  Toplam Tarama: " << engine_.getHistory().size() << "\n\n";
    std::cout << "Seçiminiz > ";
}

std::string ConsoleUI::readMultilineInput() const {
    std::string result, line;
    std::cout << "(Type 'END' on a new line to finish input):\n";
    while (std::getline(std::cin, line)) {
        if (line == "END") break;
        result += line + "\n";
    }
    return result;
}

void ConsoleUI::handleURLScan() {
    std::string url;
    std::cout << "\nAnaliz edilecek URL'yi girin (Örn: http://paypal.com): ";
    std::getline(std::cin, url);

    if (url.empty()) return;

    std::cout << "\n" << BLUE << "Analiz yapılıyor..." << RESET << "\n";
    ScanInput input(url);
    ScanReport report = engine_.scan(input);
    
    std::cout << "\n" << report << "\n";
}

void ConsoleUI::handleEmailScan() {
    std::cout << "\nE-posta Başlıklarını (Headers) yapıştırın:\n";
    std::string header = readMultilineInput();

    if (header.empty()) return;

    std::cout << "\n" << BLUE << "Analiz yapılıyor..." << RESET << "\n";
    ScanInput input = ScanInput::createEmailInput(header);
    ScanReport report = engine_.scan(input);
    
    std::cout << "\n" << report << "\n";
}

void ConsoleUI::handleContentScan() {
    std::string url;
    std::cout << "\nAnaliz edilen sayfanın URL'sini girin: ";
    std::getline(std::cin, url);

    std::cout << "\nWeb sayfasının HTML içeriğini yapıştırın:\n";
    std::string content = readMultilineInput();

    if (content.empty()) return;

    std::cout << "\n" << BLUE << "Analiz yapılıyor..." << RESET << "\n";
    ScanInput input(url, content);
    ScanReport report = engine_.scan(input);
    
    std::cout << "\n" << report << "\n";
}

void ConsoleUI::displayHistory() const {
    const auto& history = engine_.getHistory();
    if (history.empty()) {
        std::cout << "\nTarama geçmişi boş.\n";
        return;
    }

    std::cout << "\n--- TARAMA GEÇMİŞİ ---\n";
    for (size_t i = 0; i < history.size(); ++i) {
        std::cout << "[" << i + 1 << "] " << history[i].getScanId() 
                  << " | URL: " << history[i].getInput().getUrl() 
                  << " | Score: " << history[i].getTotalScore().getScore() << "\n";
    }
    
    std::string choice;
    std::cout << "\nDetayını görmek istediğiniz taramanın numarasını girin (İptal için Enter): ";
    std::getline(std::cin, choice);
    
    if (!choice.empty()) {
        try {
            size_t index = std::stoul(choice) - 1;
            if (index < history.size()) {
                std::cout << "\n" << history[index] << "\n";
            }
        } catch (...) {
            std::cout << "Geçersiz giriş.\n";
        }
    }
}

void ConsoleUI::handleExportReport() const {
    const auto& history = engine_.getHistory();
    if (history.empty()) {
        std::cout << "\nDışa aktarılacak rapor yok.\n";
        return;
    }

    const auto& lastReport = history.back();
    std::string filename = lastReport.getScanId() + ".txt";
    
    // We just export to current directory for simplicity
    lastReport.exportToFile(""); 
    
    std::cout << "\n" << GREEN << "Son rapor kaydedildi: " << filename << RESET << "\n";
}

void ConsoleUI::run() {
    displayHeader();
    std::string choice;

    while (true) {
        displayMenu();
        std::getline(std::cin, choice);

        if (choice == "1") handleURLScan();
        else if (choice == "2") handleEmailScan();
        else if (choice == "3") handleContentScan();
        else if (choice == "4") displayHistory();
        else if (choice == "5") handleExportReport();
        else if (choice == "6") {
            std::cout << "Çıkış yapılıyor...\n";
            break;
        }
        else {
            std::cout << RED << "Geçersiz seçim!" << RESET << "\n";
        }
    }
}
