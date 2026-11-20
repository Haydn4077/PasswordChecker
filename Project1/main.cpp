#include "Auditor.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace std;

namespace {

    string toLowerCopy(const string& s) {
        string out = s;
        for (char& ch : out) {
            ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
        }
        return out;
    }

    string trimWhitespaceCopy(const string& s) {
        size_t start = 0;
        while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) {
            ++start;
        }
        size_t end = s.size();
        while (end > start && isspace(static_cast<unsigned char>(s[end - 1]))) {
            --end;
        }
        return s.substr(start, end - start);
    }

    string profileName(PolicyProfile profile) {
        return (profile == PolicyProfile::HighPrivilege)
            ? "High-Privilege / High Access"
            : "Standard";
    }

    bool askYesNo(const string& prompt) {
        while (true) {
            cout << prompt;
            string answer;
            if (!getline(cin, answer)) {
                return false;
            }

            string cleaned = toLowerCopy(trimWhitespaceCopy(answer));
            if (cleaned == "y" || cleaned == "yes") {
                return true;
            }
            if (cleaned == "n" || cleaned == "no") {
                return false;
            }

            cout << "Invalid choice. Please enter 'y' or 'n'.\n";
        }
    }

    PolicyProfile askPolicyProfile(PolicyProfile defaultProfile = PolicyProfile::Standard) {
        while (true) {
            cout << "\n------------------------------------------------------------\n";
            cout << "Select Account Policy Profile\n";
            cout << "  1. Standard (normal baseline)\n";
            cout << "  2. High-Privilege / High Access (strictest - LOW risk only)\n";
            cout << "Choice [default " << (defaultProfile == PolicyProfile::HighPrivilege ? "2" : "1") << "]: ";

            string line;
            if (!getline(cin, line)) {
                return defaultProfile;
            }

            string cleaned = trimWhitespaceCopy(line);
            if (cleaned.empty()) {
                return defaultProfile;
            }
            if (cleaned == "1") {
                return PolicyProfile::Standard;
            }
            if (cleaned == "2") {
                return PolicyProfile::HighPrivilege;
            }

            cout << "Invalid selection. Enter 1, 2, or press Enter for default.\n";
        }
    }

    bool askNextPasswordMode(PolicyProfile currentProfile, PolicyProfile& nextProfile) {
        while (true) {
            cout << "\n------------------------------------------------------------\n";
            cout << "Test Another Password?\n";
            cout << "  1. Yes - Standard profile\n";
            cout << "  2. Yes - High-Privilege profile\n";
            cout << "  n. No - return / exit\n";
            cout << "Choice [default " << (currentProfile == PolicyProfile::HighPrivilege ? "2" : "1") << "]: ";

            string answer;
            if (!getline(cin, answer)) {
                return false;
            }

            string cleaned = toLowerCopy(trimWhitespaceCopy(answer));
            if (cleaned.empty()) {
                nextProfile = currentProfile;
                return true;
            }
            if (cleaned == "1" || cleaned == "s" || cleaned == "standard" || cleaned == "normal") {
                nextProfile = PolicyProfile::Standard;
                return true;
            }
            if (cleaned == "2" || cleaned == "h" || cleaned == "high" || cleaned == "high-privilege") {
                nextProfile = PolicyProfile::HighPrivilege;
                return true;
            }
            if (cleaned == "n" || cleaned == "no") {
                return false;
            }

            cout << "Invalid selection. Enter 1, 2, or 'n'.\n";
        }
    }

    int askDisplayFilter() {
        while (true) {
            cout << "\n------------------------------------------------------------\n";
            cout << "Select Findings Display Filter\n";
            cout << "  1. All findings (HIGH, MEDIUM, LOW)\n";
            cout << "  2. HIGH and MEDIUM risk only\n";
            cout << "  3. HIGH risk only\n";
            cout << "Filter [default 1]: ";

            string line;
            if (!getline(cin, line)) {
                return 1;
            }

            string cleaned = trimWhitespaceCopy(line);
            if (cleaned.empty() || cleaned == "1") {
                return 1;
            }
            if (cleaned == "2") {
                return 2;
            }
            if (cleaned == "3") {
                return 3;
            }

            cout << "Invalid filter. Enter 1, 2, 3, or press Enter for default 1.\n";
        }
    }

    void printFindingBlock(ostream& out, const AuditFinding& item, bool showAccessPolicy) {
        string status = (item.risk == RiskLevel::Low) ? "PASS (LOW RISK)" : "FLAGGED (WEAKNESS DETECTED)";
        out << "  " << item.label << "\n";
        out << "    Risk Level : " << CredentialAuditor::riskToString(item.risk) << "\n";
        out << "    Status     : " << status << "\n";

        if (showAccessPolicy) {
            if (item.risk == RiskLevel::Low) {
                out << "    Access     : ALLOWED (meets High-Privilege LOW-risk requirement)\n";
            }
            else {
                out << "    Access     : REJECTED (only LOW-risk credentials allowed for High-Privilege access)\n";
            }
        }

        if (!item.reasons.empty()) {
            out << "    Details    :\n";
            for (const string& reason : item.reasons) {
                out << "      - " << reason << "\n";
            }
        }
    }

    void writeSanitizedReportToFile(const string& outputPath, const string& sourceFile, const AuditReport& report) {
        ofstream outFile(outputPath);
        if (!outFile.is_open()) {
            cerr << "Error: Unable to write report to '" << outputPath << "'.\n";
            return;
        }

        outFile << "============================================================\n";
        outFile << "        CREDENTIAL HYGIENE AUDIT REPORT (SANITIZED)        \n";
        outFile << "        Raw Passwords Excluded | Assessment Findings Only   \n";
        outFile << "============================================================\n";
        outFile << "Source File      : " << sourceFile << "\n";
        outFile << "Lines Read       : " << report.totalLinesRead << "\n";
        outFile << "Empty Skipped    : " << report.skippedEmptyLines << "\n";
        outFile << "High Risk        : " << report.highRiskCount << "\n";
        outFile << "Medium Risk      : " << report.mediumRiskCount << "\n";
        outFile << "Low Risk         : " << report.lowRiskCount << "\n";
        outFile << "Reused Entries   : " << report.reusedEntryCount << "\n";
        outFile << "------------------------------------------------------------\n";
        outFile << "FINDINGS & WEAKNESS ANALYSIS\n";
        outFile << "------------------------------------------------------------\n";

        if (report.findings.empty()) {
            outFile << "  No non-empty credentials found to evaluate.\n";
        }
        else {
            for (const auto& item : report.findings) {
                printFindingBlock(outFile, item, false);
                outFile << "\n";
            }
        }

        outFile << "============================================================\n";
        cout << "\nSaved formatted report to '" << outputPath << "' (raw passwords excluded).\n";
    }

    void promptSaveReportFile(const string& sourceFile, const AuditReport& report) {
        if (!askYesNo("\nSave a formatted report (with status and weakness reasons) to a file? (y/n): ")) {
            return;
        }

        while (true) {
            cout << "Output file path [default: audit_report.txt]: ";
            string outPath;
            if (!getline(cin, outPath)) {
                return;
            }

            string cleaned = trimWhitespaceCopy(outPath);
            if (cleaned.empty()) {
                cleaned = "audit_report.txt";
            }

            ofstream testWrite(cleaned, ios::app);
            if (testWrite.is_open()) {
                testWrite.close();
                writeSanitizedReportToFile(cleaned, sourceFile, report);
                return;
            }

            cerr << "Error: Cannot write to '" << cleaned << "'.\n";
            if (!askYesNo("Try a different output path? (y/n): ")) {
                return;
            }
        }
    }

    string generateLowRiskPassword(const CredentialAuditor& auditor, PolicyProfile profile, size_t length = 16) {
        static const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        static const string lower = "abcdefghijkmnopqrstuvwxyz";
        static const string digits = "23456789";
        static const string symbols = "!@#$%^&*()-_=+";
        static const string allChars = upper + lower + digits + symbols;

        random_device rd;
        mt19937 rng(rd());

        for (int attempt = 0; attempt < 50; ++attempt) {
            string pwd;
            pwd.reserve(length);

            auto pickFrom = [&](const string& pool) {
                uniform_int_distribution<size_t> dist(0, pool.size() - 1);
                return pool[dist(rng)];
                };

            pwd.push_back(pickFrom(upper));
            pwd.push_back(pickFrom(lower));
            pwd.push_back(pickFrom(digits));
            pwd.push_back(pickFrom(symbols));

            while (pwd.size() < length) {
                pwd.push_back(pickFrom(allChars));
            }

            shuffle(pwd.begin(), pwd.end(), rng);

            AuditReport check = auditor.auditEntries({ pwd }, profile);
            if (!check.findings.empty() && check.findings.front().risk == RiskLevel::Low) {
                return pwd;
            }
        }

        return "K9#mP2$vL8@xQ4!nZ7";
    }

    void runInteractivePasswordCheck(CredentialAuditor& auditor) {
        cout << "\n============================================================\n";
        cout << "        INTERACTIVE PASSWORD ASSESSMENT (NO LOGGING)        \n";
        cout << "============================================================\n";
        PolicyProfile profile = askPolicyProfile();

        while (true) {
            cout << "\nActive Profile: " << profileName(profile) << "\n";
            cout << "Enter password to evaluate: ";
            string input;
            if (!getline(cin, input)) {
                return;
            }

            AuditReport report = auditor.auditEntries({ input }, profile);
            if (report.findings.empty()) {
                cout << "\nNotice: Input was empty or whitespace-only; nothing evaluated.\n";
            }
            else {
                const AuditFinding& item = report.findings.front();
                cout << "\n--- Assessment Result ---\n";
                printFindingBlock(cout, item, profile == PolicyProfile::HighPrivilege);

                if (item.risk != RiskLevel::Low) {
                    if (askYesNo("\nGenerate a suggested LOW-risk password? (y/n): ")) {
                        string suggestion = generateLowRiskPassword(auditor, profile);
                        cout << "\n  Suggested Password : " << suggestion << "\n";
                        cout << "  Privacy Note       : Shown once on screen only; never logged or saved.\n";
                    }
                }
            }

            PolicyProfile nextProfile = profile;
            if (!askNextPasswordMode(profile, nextProfile)) {
                cout << "\nExiting password assessment.\n";
                return;
            }
            profile = nextProfile;
        }
    }

    int runFileAudit(CredentialAuditor& auditor, int argc, char* argv[], bool allowMenuReturn, bool& returnToMenu) {
        returnToMenu = false;
        bool useCliArg = (argc > 1);

        while (true) {
            ifstream inputFile;
            string filePath;
            bool opened = false;

            while (true) {
                if (useCliArg) {
                    filePath = argv[1];
                    useCliArg = false;
                }
                else {
                    cout << "\nEnter path to credential file: ";
                    if (!getline(cin, filePath)) {
                        return 1;
                    }
                }

                inputFile.clear();
                inputFile.open(filePath);
                if (inputFile.is_open()) {
                    opened = true;
                    break;
                }

                cerr << "\nError: Could not open file '" << filePath << "'.\n";
                if (!askYesNo("Try another file path? (y/n): ")) {
                    if (allowMenuReturn && askYesNo("Return to main menu? (y/n): ")) {
                        returnToMenu = true;
                        return 0;
                    }
                    return 1;
                }
            }

            if (!opened) {
                return 1;
            }

            vector<string> lines;
            string line;
            while (getline(inputFile, line)) {
                lines.push_back(line);
            }

            AuditReport report = auditor.auditEntries(lines);

            cout << "\n============================================================\n";
            cout << "        CREDENTIAL HYGIENE AUDIT SUMMARY (NO LOGGING)        \n";
            cout << "============================================================\n";
            cout << "  Source File    : " << filePath << "\n";
            cout << "  Lines Read     : " << report.totalLinesRead << "\n";
            cout << "  Empty Skipped  : " << report.skippedEmptyLines << "\n";
            cout << "  High Risk      : " << report.highRiskCount << "\n";
            cout << "  Medium Risk    : " << report.mediumRiskCount << "\n";
            cout << "  Low Risk       : " << report.lowRiskCount << "\n";
            cout << "  Reused Entries : " << report.reusedEntryCount << "\n";

            if (report.findings.empty()) {
                cout << "\nNo non-empty credentials found to display.\n";
            }
            else {
                int filterChoice = askDisplayFilter();
                cout << "\n--- Detailed Findings ---\n";

                int shownCount = 0;
                for (const auto& item : report.findings) {
                    if (filterChoice == 3 && item.risk != RiskLevel::High) {
                        continue;
                    }
                    if (filterChoice == 2 && item.risk == RiskLevel::Low) {
                        continue;
                    }

                    printFindingBlock(cout, item, false);
                    cout << "\n";
                    ++shownCount;
                }

                if (shownCount == 0) {
                    cout << "  No findings matched the selected filter.\n";
                }
            }

            promptSaveReportFile(filePath, report);

            if (!askYesNo("\nAudit another file? (y/n): ")) {
                if (allowMenuReturn && askYesNo("Return to main menu? (y/n): ")) {
                    returnToMenu = true;
                }
                return 0;
            }
        }
    }

}

int main(int argc, char* argv[]) {
    CredentialAuditor auditor;

    if (argc > 1) {
        bool returnToMenu = false;
        return runFileAudit(auditor, argc, argv, false, returnToMenu);
    }

    while (true) {
        cout << "\n============================================================\n";
        cout << "        PASSWORD & CREDENTIAL HYGIENE AUDITOR              \n";
        cout << "============================================================\n";
        cout << "  1. Audit credentials from a file\n";
        cout << "  2. Check password strength level\n";
        cout << "Choice: ";

        int choice = 0;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            cerr << "\nInvalid selection.\n";
            if (!askYesNo("Try selecting a mode again? (y/n): ")) {
                return 1;
            }
            continue;
        }

        cin.ignore(10000, '\n');

        if (choice == 2) {
            runInteractivePasswordCheck(auditor);
            if (!askYesNo("\nReturn to main menu? (y/n): ")) {
                return 0;
            }
        }
        else if (choice == 1) {
            bool returnToMenu = false;
            int status = runFileAudit(auditor, argc, argv, true, returnToMenu);
            if (status != 0) {
                return status;
            }
            if (!returnToMenu) {
                return 0;
            }
        }
        else {
            cerr << "\nUnknown option.\n";
            if (!askYesNo("Try selecting a mode again? (y/n): ")) {
                return 1;
            }
        }
    }
}