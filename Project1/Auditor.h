#pragma once
#include <string>
#include <vector>

using namespace std;

enum class RiskLevel {
    Low,
    Medium,
    High
};

struct AuditFinding {
    string label;
    RiskLevel risk = RiskLevel::Low;
    int reuseCount = 1;
    vector<string> reasons;
};

struct AuditReport {
    int totalLinesRead = 0;
    int highRiskCount = 0;
    int mediumRiskCount = 0;
    int lowRiskCount = 0;
    int reusedEntryCount = 0;
    vector<AuditFinding> findings;
};

class CredentialAuditor {
public:
    AuditReport auditEntries(const vector<string>& rawLines) const;
    static string riskToString(RiskLevel level);

private:
    static bool containsCommonPattern(const string& lowerPwd);
    static bool hasRepeatedRun(const string& pwd, int runLength = 3);
};