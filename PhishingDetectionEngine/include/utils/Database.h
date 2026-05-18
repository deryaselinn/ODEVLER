#ifndef DATABASE_H
#define DATABASE_H

#include "Exceptions.h"
#include <set>
#include <string>
#include <fstream>
#include <iostream>
#include <algorithm>

// Template Database class for storing and checking items (like domains, IPs, keywords)
template<typename T>
class Database {
private:
    std::set<T> entries_;
    std::string name_;

public:
    explicit Database(const std::string& name = "GenericDB") : name_(name) {}

    void add(const T& entry) {
        entries_.insert(entry);
    }

    void remove(const T& entry) {
        entries_.erase(entry);
    }

    bool contains(const T& entry) const {
        return entries_.find(entry) != entries_.end();
    }

    size_t size() const {
        return entries_.size();
    }
    
    std::string getName() const {
        return name_;
    }

    // Load from file (specialized or relies on operator>>)
    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw DatabaseException("Could not open file: " + filename);
        }

        T item;
        while (file >> item) {
            entries_.insert(item);
        }
    }

    // Save to file (specialized or relies on operator<<)
    void saveToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) {
            throw DatabaseException("Could not create file: " + filename);
        }

        for (const auto& item : entries_) {
            file << item << "\n";
        }
    }

    // Iterator support to use with range-based for loops and STL algorithms
    auto begin() const { return entries_.begin(); }
    auto end() const { return entries_.end(); }
};

// Partial specialization for string to handle spaces if needed (though >> by default stops at whitespace)
// In a real scenario, you might want getline for strings
template<>
inline void Database<std::string>::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw DatabaseException("Could not open file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') { // Ignore empty lines and comments
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (!line.empty()) {
                entries_.insert(line);
            }
        }
    }
}

#endif // DATABASE_H
