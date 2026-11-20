#include "Auditor.h"
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

    CredentialAuditor auditor;
    AuditReport report = auditor.auditEntries(lines);

    cout << "\n=== Credential Hygiene Audit Summary (No Raw Passwords Logged) ===\n";
    cout << "Lines read:       " << report.totalLinesRead << "\n";
    cout << "Empty skipped:    " << report.skippedEmptyLines << "\n";
    cout << "High risk:        " << report.highRiskCount << "\n";
    cout << "Medium risk:      " << report.mediumRiskCount << "\n";
    cout << "Low risk:         " << report.lowRiskCount << "\n";
    cout << "Reused entries:   " << report.reusedEntryCount << "\n\n";

    for (const auto& item : report.findings) {
        cout << "[" << CredentialAuditor::riskToString(item.risk) << "] " << item.label;
        if (!item.reasons.empty()) {
            cout << " -> ";
            for (size_t i = 0; i < item.reasons.size(); ++i) {
                if (i > 0) cout << "; ";
                cout << item.reasons[i];
            }
        }
        cout << "\n";
    }
}