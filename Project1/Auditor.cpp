#include "Auditor.h"
#include <algorithm>
#include <cctype>
#include <unordered_map>

using namespace std;

namespace {

    string normalizeLeetspeakLower(const string& s) {
        string out;
        out.reserve(s.size());
        for (unsigned char raw : s) {
            char ch = static_cast<char>(tolower(raw));
            switch (ch) {
            case '@': out.push_back('a'); break;
            case '0': out.push_back('o'); break;
            case '1':
            case '!': out.push_back('i'); break;
            case '3': out.push_back('e'); break;
            case '$': out.push_back('s'); break;
            default:  out.push_back(ch); break;
            }
        }
        return out;
    }

    bool hasSeasonalOrYearHabit(const string& text) {
        static const vector<string> seasons = {
            "spring", "summer", "fall", "autumn", "winter"
        };
        static const vector<string> years = {
            "2020", "2021", "2022", "2023", "2024", "2025", "2026"
        };

        for (const string& season : seasons) {
            if (text.find(season) != string::npos) {
                return true;
            }
        }
        for (const string& year : years) {
            if (text.find(year) != string::npos) {
                return true;
            }
        }
        return false;
    }

    bool hasPredictableSuffix(const string& entry) {
        if (entry.size() < 3) {
            return false;
        }

        size_t pos = entry.size();

        size_t punctCount = 0;
        while (pos > 0 && punctCount < 2 &&
            (entry[pos - 1] == '!' || entry[pos - 1] == '.' || entry[pos - 1] == '?')) {
            --pos;
            ++punctCount;
        }

        size_t digitCount = 0;
        while (pos > 0 && digitCount < 4 &&
            isdigit(static_cast<unsigned char>(entry[pos - 1]))) {
            --pos;
            ++digitCount;
        }

        if (digitCount == 0 && punctCount == 0) {
            return false;
        }
        if (pos < 2) {
            return false;
        }

        size_t alphaPrefix = 0;
        for (size_t i = 0; i < pos; ++i) {
            if (isalpha(static_cast<unsigned char>(entry[i]))) {
                ++alphaPrefix;
            }
        }

        return alphaPrefix >= 2;
    }

}

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

AuditReport CredentialAuditor::auditEntries(const vector<string>& rawLines, PolicyProfile profile) const {
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

    const bool highPriv = (profile == PolicyProfile::HighPrivilege);
    const size_t minHighLen = highPriv ? 14 : 8;
    const size_t minMedLen = highPriv ? 14 : 12;
    const int minClasses = highPriv ? 4 : 3;

    for (size_t i = 0; i < normalizedEntries.size(); ++i) {
        const string& pwd = normalizedEntries[i];
        string lowerPwd = pwd;
        transform(lowerPwd.begin(), lowerPwd.end(), lowerPwd.begin(),
            [](unsigned char c) { return static_cast<char>(tolower(c)); });
        string leetPwd = normalizeLeetspeakLower(pwd);

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

        if (pwd.size() < minHighLen) {
            finding.reasons.push_back("Short length (< " + to_string(minHighLen) + " chars)");
        }
        else if (pwd.size() < minMedLen) {
            finding.reasons.push_back("Moderate length (< " + to_string(minMedLen) + " chars)");
        }

        if (classCount < minClasses) {
            finding.reasons.push_back(highPriv
                ? "High-privilege profile requires all 4 character classes (Pp1!)"
                : "Limited character variety");
        }

        bool commonHit = containsCommonPattern(lowerPwd) || containsCommonPattern(leetPwd);
        if (commonHit) {
            finding.reasons.push_back("Matches common or substituted pattern");
        }

        if (hasSeasonalOrYearHabit(lowerPwd) || hasSeasonalOrYearHabit(leetPwd)) {
            finding.reasons.push_back("Predictable seasonal or year pattern");
        }

        if (hasPredictableSuffix(pwd)) {
            finding.reasons.push_back("Predictable suffix pattern");
        }

        if (hasRepeatedRun(pwd)) {
            finding.reasons.push_back("Contains repeated character run");
        }

        if (finding.reuseCount > 1) {
            finding.reasons.push_back("Reused across entries (x" + to_string(finding.reuseCount) + ")");
            ++report.reusedEntryCount;
        }

        bool isHighRisk = commonHit || pwd.size() < minHighLen || finding.reuseCount >= 3 ||
            (highPriv && !finding.reasons.empty());

        if (isHighRisk) {
            finding.risk = RiskLevel::High;
            ++report.highRiskCount;
        }
        else if (!finding.reasons.empty()) {
            finding.risk = RiskLevel::Medium;
            ++report.mediumRiskCount;
        }
        else {
            finding.risk = RiskLevel::Low;
            finding.reasons.push_back(highPriv
                ? "Approved for high-privilege access: meets strict length, variety, and pattern checks"
                : "Strong password: good length, variety, and no common issues detected");
            ++report.lowRiskCount;
        }

        report.findings.push_back(move(finding));
    }

    return report;
}