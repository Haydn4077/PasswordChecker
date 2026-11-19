#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int main(int argc, char* argv[]) {
    string filePath;
    if (argc > 1) {
        filePath = argv[1];
    }
    else {
        cout << "Enter path to sample/test credential file: ";
        getline(cin, filePath);
    }

    ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        cerr << "Error: Could not open file '" << filePath << "'.\n";
        return 1;
    }

    vector<string> lines;
    string line;
    while (getline(inputFile, line)) {
        lines.push_back(line);
    }

    cout << "Password & Credential Hygiene Auditor (Week 11 Baseline)\n";
    cout << "Loaded " << lines.size() << " line(s) from '" << filePath << "'.\n";
}
