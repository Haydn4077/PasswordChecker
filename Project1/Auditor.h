#pragma once
#include <string>
#include <vector>

using namespace std;

enum class RiskLevel {
    Low,
    Medium,
    High
};

enum class PolicyProfile {
    Standard,
    HighPrivilege
};

struct AuditFinding {
    string label;
    RiskLevel risk = RiskLevel::Low;
    int reuseCount = 1;
    vector<string> reasons;
};

struct AuditReport {
    int totalLinesRead = 0;
    int skippedEmptyLines = 0;
    int highRiskCount = 0;
    int mediumRiskCount = 0;
    int lowRiskCount = 0;
    int reusedEntryCount = 0;
    vector<AuditFinding> findings;
};

class CredentialAuditor {
public:
    AuditReport auditEntries(const vector<string>& rawLines,
        PolicyProfile profile = PolicyProfile::Standard) const;
    static string riskToString(RiskLevel level);
    static string trimLine(const string& line);

private:
    static bool containsCommonPattern(const string& lowerPwd);
    static bool hasRepeatedRun(const string& pwd, int runLength = 3);
};