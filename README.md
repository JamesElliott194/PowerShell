What the Script Covers (Overview)
Pre-requisites & Module Installations:

Checks for and installs: MSOnline, Microsoft.Graph, AzureADPreview, ExchangeOnlineManagement, PSBlackListChecker.

Core Functionalities:

Blocks sign-ins for a compromised account.

Revokes Azure AD refresh tokens.

Collects Azure AD Sign-In and Unified Audit logs.

Checks if an IP/domain is blacklisted.

Blocks IPs in Exchange Online.

Inspects and optionally removes inbox rules, forwarding, and auto-replies.

Runs Compliance searches and purges matching emails.

Optionally resets password and re-enables the compromised account.

Security & Compliance Center Connection:

Connects to Security & Compliance Center (SCC).

Adds admin to eDiscovery roles.

Performs targeted Compliance searches and optionally purges emails.

Unified Audit Logging (Organization-wide):

Optional, intensive operation to retrieve logs for all users over a chosen time range.

✅ Pros (Strengths)
Interactive: Step-by-step prompts allow full control.

Modular: Each step is optional.

Thorough: Covers sign-ins, audit logs, inbox rules, blacklists, compliance searches.

Good Logging: Transcripts and CSV exports for most data outputs.

