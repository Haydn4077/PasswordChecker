#include "Auditor.h"
#include <algorithm>
#include <cctype>
#include <unordered_map>

using namespace std;

string CredentialAuditor::trimLine(const string& line) {
    string cleaned = line;
    if (!cleaned.empty() && cleaned.back() == '\r') {
        cleaned.pop_back();
    }

    size_t start = 0;
    while (start < cleaned.size() && isspace(static_cast<unsigned char>(cleaned[start]))) {
        ++start;
    }

    size_t end = cleaned.size();
    while (end > start && isspace(static_cast<unsigned char>(cleaned[end - 1]))) {
        --end;
    }

    return cleaned.substr(start, end - start);
}

bool CredentialAuditor::containsCommonPattern(const string& lowerPwd) {
    static const vector<string> commonTokens = {
        "password", "passwd", "123456", "12345678", "qwerty", "admin", "letmein", "welcome"
    };

    for (const auto& token : commonTokens) {
        if (lowerPwd.find(token) != string::npos) {
            return true;
        }
    }
    return false;
}

bool CredentialAuditor::hasRepeatedRun(const string& pwd, int runLength) {
    if (runLength <= 1 || pwd.size() < static_cast<size_t>(runLength)) {
        return false;
    }

    int currentRun = 1;
    for (size_t i = 1; i < pwd.size(); ++i) {
        if (pwd[i] == pwd[i - 1]) {
            ++currentRun;
            if (currentRun >= runLength) {
                return true;
            }
        }
        else {
            currentRun = 1;
        }
    }
    return false;
}

string CredentialAuditor::riskToString(RiskLevel level) {
    switch (level) {
    case RiskLevel::High:   return "HIGH";
    case RiskLevel::Medium: return "MEDIUM";
    case RiskLevel::Low:
    default:                return "LOW";
    }
}

AuditReport CredentialAuditor::auditEntries(const vector<string>& rawLines) const {
    AuditReport report;
    vector<string> normalizedEntries;
    unordered_map<string, int> frequencyMap;

    for (const auto& raw : rawLines) {
        ++report.totalLinesRead;
        string trimmed = trimLine(raw);
        if (trimmed.empty()) {
            ++report.skippedEmptyLines;
            continue;
        }
        normalizedEntries.push_back(trimmed);
        ++frequencyMap[trimmed];
    }

    for (size_t i = 0; i < normalizedEntries.size(); ++i) {
        const string& pwd = normalizedEntries[i];
        string lowerPwd = pwd;
        transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(),
            [](unsigned char c) { return static_cast<char>(tolower(c)); });

        AuditFinding finding;
        finding.label = "Credential #" + to_string(i + 1) + " (length=" + to_string(pwd.size()) + ")";
        finding.reuseCount = frequencyMap[pwd];

        bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
        for (unsigned char c : pwd) {
            if (isupper(c)) hasUpper = true;
            else if (islower(c)) hasLower = true;
            else if (isdigit(c)) hasDigit = true;
            else hasSymbol = true;
        }

        int classCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

        if (pwd.size() < 8) {
            finding.reasons.push_back("Short length (< 8 chars)");
        }
        else if (pwd.size() < 12) {
            finding.reasons.push_back("Moderate length (< 12 chars)");
        }

        if (classCount < 3) {
            finding.reasons.push_back("Limited character variety");
        }

        if (containsCommonPattern(lowerPwd)) {
            finding.reasons.push_back("Matches common weak pattern");
        }

        if (hasRepeatedRun(pwd)) {
            finding.reasons.push_back("Contains repeated character run");
        }

        if (finding.reuseCount > 1) {
            finding.reasons.push_back("Reused across entries (x" + to_string(finding.reuseCount) + ")");
            ++report.reusedEntryCount;
        }

        if (containsCommonPattern(lowerPwd) || pwd.size() < 8 || finding.reuseCount >= 3) {
            finding.risk = RiskLevel::High;
            ++report.highRiskCount;
        }
        else if (!finding.reasons.empty()) {
            finding.risk = RiskLevel::Medium;
            ++report.mediumRiskCount;
        }
        else {
            finding.risk = RiskLevel::Low;
            finding.reasons.push_back("Strong password: good length, variety, and no common issues detected");
            ++report.lowRiskCount;
        }

        report.findings.push_back(move(finding));
    }

    return report;
}