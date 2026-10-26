# RateMyAzureSQL

Find every Azure SQL database in a tenant, grade each one **A to F** on **security** and **backups**, and see exactly which change lifts the grade — with ready-to-review scripts for the backup changes.

RateMyAzureSQL is a read-only Blazor Server app with two separate flows, one per product:

| Flow | What it rates |
|---|---|
| **SQL Databases** | Logical servers and the databases on them (elastic pools included). Server settings — public access, firewall rules, TLS, Microsoft Entra admin, Defender for SQL, auditing, encryption key — count for every database on the server. |
| **Managed Instances** | SQL Managed Instances and their databases. Public data endpoint, TLS, Entra admin, Defender, instance-level backup storage redundancy, zone redundancy and instance failover groups. |

Each flow is three steps: **Scope** (tenant and subscriptions) → **Grades** (A–F per database, findings with fixes, server inventory, Word reports) → **Backups** (pick a target backup plan, see what would change per database, generate the PowerShell or Azure CLI script, list the long-term backups that actually exist).

## Scoring model

100 points per database — 50 for security and 50 for backups — mapped to a letter, with hard caps.

| Area | Category | Points | What earns it |
|---|---|---|---|
| Security | Network exposure | 15 | Public access disabled 15 · public endpoint with narrow firewall rules 8 (+2 with a private endpoint; −3 "Allow Azure services"; −2 broad rules) · a rule covering the whole internet 0 |
| Security | Identity & access | 10 | Microsoft Entra admin 5 · Entra-only authentication 5 |
| Security | Threat protection & auditing | 15 | Defender for SQL 6 · vulnerability assessment 3 · auditing 6 (managed instances: Defender 9, VA 6; auditing lives in T-SQL and is not assessed) |
| Security | Encryption | 10 | Transparent data encryption 7 · minimum TLS 1.2 3 |
| Backups | Point-in-time restore | 15 | 35 days 15 · 28 days 13 · 14 days 11 · 7 days 8 · less pro-rated (Basic tier: 7 days is the maximum and earns 15) |
| Backups | Long-term retention | 15 | Weekly 5 · monthly 5 · yearly 5 |
| Backups | Backup storage redundancy | 10 | Geo / geo-zone 10 · zone 5 · local 0 |
| Backups | Geo & zone resilience | 10 | Failover group 6 (geo-replica without a group 4) · zone redundant 4 |

Grade bands: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 45 · **E** ≥ 30 · **F** below.

Caps: open to the whole internet (0.0.0.0–255.255.255.255 firewall rule) → at most **D** · TDE off → at most **D** · locally redundant backup storage → at most **C** · no long-term retention, no Defender for SQL or no Microsoft Entra admin → at most **B**.

Every improvement is listed with the points it gains and the grade it would produce, so the biggest win is always visible. Geo-secondary replicas and dedicated SQL pools (Data Warehouse) are listed but not rated.

## The Backups step

The third step is built for one question: *what should my backups look like, and what do I run to get there?*

- Three presets — **Baseline**, **Recommended** (35-day PITR, differential backups every 12 h, weekly × 12 weeks, monthly × 12 months, yearly × 7 years, geo-zone-redundant storage, zone redundancy, failover group) and **Compliance** — or set every value yourself.
- Every rated database shows its current PITR, long-term retention, backup storage redundancy, geo/zone state and backup score, plus the exact changes the plan would make (with tier caveats: Basic tier PITR cap, Hyperscale redundancy needs a copy, pooled databases take zone redundancy from the pool).
- Select databases (those needing changes are pre-selected) and generate a **PowerShell (Az.Sql)** or **Azure CLI** script, per server, with each option toggleable. Copy or download it; review it; run it yourself.
- "List the backups that exist" reads the long-term retention backups Azure actually holds for a database, so a policy that was configured yesterday is not mistaken for years of restore points.
- Cost notes explain what each choice does to the bill (backup storage redundancy multipliers, LTR GB-months, failover group compute).

## Running it

Prerequisites: .NET 10 SDK, Azure CLI, and a signed-in account with Reader access to the subscriptions you want to scan.

```powershell
az login                       # optionally: az login --tenant <tenant-id>
cd src/RateMyAzureSql
dotnet run
```

Open <http://localhost:5220>. Pick a flow, choose the subscriptions (only those containing that product are highlighted), scan, and read the grades.

No Azure access? Click **Try with sample data** on the home page. Both flows then run on a realistic built-in estate that covers every grade band, without calling Azure.

### Authentication

> [!WARNING]
> **RateMyAzureSQL has no login of its own.** Every visitor to the site uses the same Azure credential the app was started with, and one shared token cache serves them all. Run it on your own workstation, or put it behind authentication you control (for example App Service Easy Auth or a reverse proxy). If you host it on App Service with a managed identity and no auth in front, **anyone who can reach the URL can read every subscription that identity has access to.**

The app uses `AzureCliCredential` by default. To run it somewhere without the Azure CLI (App Service, a container with a managed identity), set `Azure:Credential` to `Default` in `appsettings.json` or as the environment variable `Azure__Credential=Default` to use `DefaultAzureCredential`.

The credential needs **Reader** on the subscriptions. Reading firewall rules, auditing settings and the Defender plan also works with Reader; if any setting cannot be read the scan says so and awards partial points for it rather than failing.

### What the scan reads

Everything is read-only, through Azure Resource Graph and ARM `GET` calls (API version 2021-11-01):

- Logical servers / managed instances: public network access or public data endpoint, private endpoint connections, minimum TLS version, firewall rules, Microsoft Entra admin and Entra-only authentication, Defender for SQL (server policy and subscription plan), vulnerability assessment (express and classic), auditing settings and where the audit log goes (master database diagnostic settings), encryption protector (service- or customer-managed key), failover groups / instance failover groups
- Databases: tier and SKU, elastic pool (and the pool's zone redundancy), zone redundancy, backup storage redundancy, earliest restore point, point-in-time retention and differential backup interval, long-term retention policy, transparent data encryption state, geo-replication links
- On demand in the Backups step: the long-term retention backups that exist for a database

RateMyAzureSQL never modifies a resource. The scripts it generates are PowerShell / bash you review and run yourself.

## Tests

```powershell
dotnet test
```

The suite covers the rating engine (reference cases per category, caps, improvement points), JSON parsing of the Azure shapes (Resource Graph rows, firewall rules, failover groups, replication links, LTR policies, audit diagnostics), findings, the backup plan deltas and generated scripts, Word/HTML reports, the sample estate, and the Blazor components (bUnit).

## Project layout

```
src/RateMyAzureSql/
  Components/Pages       Home, SqlDatabasePage, ManagedInstancePage
  Components/Shared      SqlFlow (wizard), ScopeStep, GradesStep, BackupsStep, ServerDetail, BackupPlanModal, ReportModal, badges
  Services/
    SqlRatingService     The A–F engine (shared by both products)
    SqlDiscoveryService  Resource Graph / ARM discovery of servers, instances, databases and their settings
    SqlFindingsBuilder   Findings with remediation guidance
    BackupPlanService    Presets, per-database change deltas, PowerShell / Azure CLI script generation, cost notes
    SqlReportService     Summary and detailed-findings reports (docx + HTML preview)
    DemoDataService      The sample estate
tests/RateMyAzureSql.Tests    xUnit + bUnit
```

### Browser walkthrough

`tests/e2e/walkthrough.mjs` drives the running app in headless Chromium through both flows on sample data (scan, grades, findings, server detail, reports, backup plan, script generation, reload, dark theme, mobile) and fails on any browser error:

```powershell
dotnet run --project src/RateMyAzureSql        # in one terminal
cd tests/e2e; npm install; npx playwright install chromium; npm test
```

Set `PW_EXE` to a Chromium executable to use an existing browser instead of the one Playwright downloads.
