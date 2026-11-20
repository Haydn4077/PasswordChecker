Password & Credential Hygiene Auditor
A local, offline C++ command-line tool that audits credential lists or single passwords against risk policies, 
flags predictable human and attack patterns,
and exports sanitized reports—without storing or logging raw passwords.


The Challenge It Addresses
Many weak credentials are not completely random, they rely on predictable human habits like leetspeak substitutions (P@ssw0rd1), 
seasonal/year strings (Spring2026!), trailing numbers and punctuation (Welcome1!), 
repeated character runs, or password reuse. 
At the same time, security teams need stricter bars for privileged or high-access accounts than standard user accounts, 
and audit outputs must highlight risks clearly without exposing raw credentials in logs or saved reports.


What It Does
Evaluates credentials locally: 
Audits password files or checks individual passwords interactively with zero external APIs or network calls.

Applies policy profiles: 
Supports Standard and High-Privilege / High Access profiles (where only LOW-risk credentials are allowed for high-access checks).

Detects common weakness patterns: 
Checks length, character variety, repeated character runs, reuse across entries, leetspeak/common tokens, 
seasonal/year habits, and predictable trailing suffixes.

Suggests stronger passwords & exports reports: 
Generates on-the-fly LOW-risk password suggestions in interactive mode (shown once on screen only) and saves formatted, 
sanitized .txt reports with weakness reasons and no raw passwords.

Adapts to the terminal: 
Uses ANSI colors on interactive consoles and falls back cleanly when output is redirected or written to report files.


How to Run It
Build in Visual Studio (or your C++ compiler): 
Compile main.cpp and Auditor.cpp together as a C++ console application (C++17 or newer recommended).

Launch interactive mode: 
Run the compiled executable with no arguments to choose between 
1. Audit credentials from a file 
or 
2. Check password strength level.

Audit a file directly from the CLI: 
Pass a credential file path as a command-line argument (Can be any txt file you have the directory to, or you can use provided one: data/sample_credentials.txt), 
review the summary and filtered findings, 
and optionally save a sanitized report (audit_report.txt by default). (This should show up in the root folder of the project when saved)

Check password strength level:
When on PASSWORD & CREDENTIAL HYGIENE AUDITOR (first menu) press 2
when in menu INTERACTIVE PASSWORD ASSESSMENT (NO LOGGING) pick between Standard passwords (can have weak passwords)
OR
High-Privilege / High Access (LOW risk passwords only)
if your password is flagged and or denied access you can hit y/n to allow the system to generate a low-risk password for you.
