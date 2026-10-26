using RateMyAzureSql.Models;
using RateMyAzureSql.Services.Reports;

namespace RateMyAzureSql.Services;

/// <summary>Everything the reports need that isn't in the scan result itself.</summary>
public sealed class SqlReportContext
{
    public SqlFlowKind Flow { get; init; }
    public string CustomerName { get; init; } = "";
    public string TenantName { get; init; } = "";
    public string ReportAuthor { get; init; } = "";
    public DateTime ScanDate { get; init; } = DateTime.Now;
    public List<string> SubscriptionLines { get; init; } = new();
    public SqlScanResult? Scan { get; init; }
}

/// <summary>Builds the summary and detailed-findings reports (as a ReportDoc) for one flow.</summary>
public static class SqlReportService
{
    public static byte[] SummaryDocx(SqlReportContext ctx) => DocxReportRenderer.Render(BuildSummary(ctx));
    public static byte[] FindingsDocx(SqlReportContext ctx) => DocxReportRenderer.Render(BuildFindings(ctx));
    public static string SummaryHtml(SqlReportContext ctx) => HtmlReportRenderer.Render(BuildSummary(ctx));
    public static string FindingsHtml(SqlReportContext ctx) => HtmlReportRenderer.Render(BuildFindings(ctx));

    public static string FileName(SqlReportContext ctx, bool findings)
    {
        var scope = ctx.Flow == SqlFlowKind.SqlDatabase ? "SqlDatabase" : "ManagedInstance";
        var customer = string.Concat((ctx.CustomerName ?? "").Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
        if (string.IsNullOrEmpty(customer)) customer = "AzureSQL";
        return $"{customer}-{scope}-{(findings ? "Findings" : "Summary")}-{ctx.ScanDate:yyyyMMdd}.docx";
    }

    // ── Summary report ───────────────────────────────────────────────────────

    public static ReportDoc BuildSummary(SqlReportContext ctx)
    {
        var product = ctx.Flow.Label();
        var scan = ctx.Scan;
        var servers = scan?.Servers ?? [];
        var dbs = scan?.Databases ?? [];
        var rated = scan?.RatableDatabases.ToList() ?? [];
        var findings = scan?.Findings ?? [];

        int noLtr = rated.Count(d => d.LtrRead && !d.HasLtr);
        int localBackups = rated.Count(d => d.BackupStorageRedundancy.Equals("Local", StringComparison.OrdinalIgnoreCase));
        int noGeo = rated.Count(d => !d.HasGeoReplica);
        int publicHosts = servers.Count(s => s.PublicNetworkAccess == true);
        int openHosts = servers.Count(s => s.OpenToInternet);
        int noDefender = servers.Count(s => s.DefenderEnabled == false);
        int noEntra = servers.Count(s => !s.HasEntraAdmin);

        var doc = new ReportDoc { Title = $"Azure {product} — Security & Backup Summary" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1("2. Executive summary");
        if (scan is null)
        {
            doc.P("No scan data was available when this report was generated — run a scan to populate the estate sections.");
        }
        else
        {
            var high = findings.Count(f => f.Severity == "High");
            var medium = findings.Count(f => f.Severity == "Medium");
            var info = findings.Count(f => f.Severity == "Info");
            doc.P($"The scan covered {ctx.SubscriptionLines.Count} subscription(s) and found {servers.Count} {ctx.Flow.HostPluralLabel()} " +
                  $"with {dbs.Count} database(s), of which {rated.Count} were rated. " +
                  $"It produced {findings.Count} finding(s): {high} High, {medium} Medium and {info} Info.");
            var concerns = new List<string>();
            if (openHosts > 0) concerns.Add($"{openHosts} {ctx.Flow.HostLabel()}(s) are open to the whole internet");
            if (noDefender > 0) concerns.Add($"{noDefender} {ctx.Flow.HostLabel()}(s) have no Microsoft Defender for SQL");
            if (noEntra > 0) concerns.Add($"{noEntra} {ctx.Flow.HostLabel()}(s) rely on SQL authentication only");
            if (localBackups > 0) concerns.Add($"{localBackups} database(s) keep their backups in locally redundant storage");
            if (noLtr > 0) concerns.Add($"{noLtr} database(s) have no long-term retention");
            if (noGeo > 0) concerns.Add($"{noGeo} database(s) have no geo-replica or failover group");
            if (concerns.Count > 0) doc.P($"The most significant gaps: {string.Join("; ", concerns)}.");
        }
        doc.Note("This report is the output of a read-only scan; no changes were made to any Azure resource.");

        doc.H1($"3. {product} security & backup rating");
        RatingSection(doc, ctx);

        doc.H1("4. Estate overview");
        doc.Table(["Metric", "Value"],
        [
            [Capitalise(ctx.Flow.HostPluralLabel()), Count(scan, servers.Count)],
            ["Databases (rated)", scan is null ? "—" : $"{dbs.Count} ({rated.Count})"],
            [$"{Capitalise(ctx.Flow.HostPluralLabel())} with a public endpoint", Count(scan, publicHosts)],
            [$"{Capitalise(ctx.Flow.HostPluralLabel())} open to the internet", Count(scan, openHosts)],
            [$"{Capitalise(ctx.Flow.HostPluralLabel())} without Defender for SQL", Count(scan, noDefender)],
            [$"{Capitalise(ctx.Flow.HostPluralLabel())} without a Microsoft Entra admin", Count(scan, noEntra)],
            ["Databases with locally redundant backups", Count(scan, localBackups)],
            ["Databases without long-term retention", Count(scan, noLtr)],
            ["Databases without a geo-replica / failover group", Count(scan, noGeo)],
            ["Total findings", Count(scan, findings.Count)],
        ], "No scan data available.");

        doc.H1("5. Findings summary");
        doc.Table(["Severity", "Area", "Category", "Finding", "Resource"],
            findings.OrderBy(f => SqlFindingsBuilder.SeverityOrder(f.Severity)).Select(f => new[] { f.Severity, f.Area, f.Category, f.Message, f.ResourceName }).ToList(),
            scan is null ? "No scan data available." : "No findings — the estate matches the checks performed.",
            findings.Select(f => new string?[] { SeverityColor(f.Severity), null, null, null, null }).ToList());

        doc.H1("6. Backup posture per database");
        doc.Table(["Database", "Tier", "PITR", "Long-term retention", "Backup storage", "Geo / zone"],
            dbs.OrderBy(d => d.ServerName, StringComparer.OrdinalIgnoreCase).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase).Select(d => new[]
            {
                $"{d.ServerName}/{d.Name}", d.TierLabel,
                d.IsDataWarehouse ? "n/a" : d.PitrRetentionDays is { } p ? $"{p} days{(d.DiffBackupIntervalHours is { } h ? $", diff {h} h" : "")}" : "unknown",
                d.IsDataWarehouse ? "n/a" : d.LtrRead ? BackupPlanService.LtrLabel(d.WeeklyRetention, d.MonthlyRetention, d.YearlyRetention) : "unknown",
                BackupPlanService.RedundancyLabel(d.BackupStorageRedundancy),
                $"{(d.HasFailoverGroup ? $"failover group {d.FailoverGroupName}" : d.GeoReplicas.Count > 0 ? "geo-replica" : "no geo-replica")}, {(d.ZoneRedundant ? "zone redundant" : "single zone")}"
            }).ToList(),
            scan is null ? "No scan data available." : "No databases in scope.");

        doc.H1($"7. Network & identity per {ctx.Flow.HostLabel()}");
        doc.Table(["Server", "Public access", "Min TLS", "Entra admin", "Entra-only", "Defender", "Auditing"],
            servers.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Select(s => new[]
            {
                s.Name,
                s.PublicNetworkAccess switch { false => "disabled", true => s.OpenToInternet ? "OPEN TO INTERNET" : s.AllowAzureServices ? "enabled + Azure services" : "enabled", _ => "unknown" } + (s.PrivateEndpointCount > 0 ? $", {s.PrivateEndpointCount} private endpoint(s)" : ""),
                string.IsNullOrEmpty(s.MinimalTlsVersion) ? "none" : s.MinimalTlsVersion,
                s.HasEntraAdmin ? s.EntraAdminLogin : "none",
                s.HasEntraAdmin ? YesNo(s.EntraOnlyAuthentication) : "n/a",
                YesNo(s.DefenderEnabled) + (s.DefenderEnabled == true ? $" (VA {YesNo(s.VulnerabilityAssessmentEnabled)})" : ""),
                s.Kind == SqlFlowKind.ManagedInstance ? "T-SQL (not assessed)" : YesNo(s.AuditingEnabled) + (s.AuditDestinations.Count > 0 ? $" → {string.Join(", ", s.AuditDestinations)}" : "")
            }).ToList(),
            scan is null ? "No scan data available." : $"No {ctx.Flow.HostPluralLabel()} in scope.");

        doc.H1("8. Recommendations");
        var recs = new List<string>();
        foreach (var f in findings.Where(f => f.Severity == "High").Take(5))
            recs.Add($"{f.Message} ({f.ResourceName})");
        if (localBackups > 0)
            recs.Add($"Move the {localBackups} database(s) with locally redundant backups to geo-redundant or geo-zone-redundant backup storage.");
        if (noLtr > 0)
            recs.Add($"Configure long-term retention on the {noLtr} database(s) that have none — weekly for 12 weeks, monthly for 12 months and yearly for 7 years is a sound default.");
        if (rated.Any(d => d.PitrRetentionDays is < 14 && !d.IsBasicTier))
            recs.Add("Raise point-in-time retention to 14–35 days on production databases.");
        if (noGeo > 0)
            recs.Add($"Add the {noGeo} database(s) without a geo-replica to failover groups with a partner in the paired region.");
        if (noDefender > 0)
            recs.Add($"Enable Microsoft Defender for SQL on the {noDefender} {ctx.Flow.HostLabel()}(s) without it.");
        if (noEntra > 0)
            recs.Add($"Set a Microsoft Entra admin on the {noEntra} {ctx.Flow.HostLabel()}(s) that only have SQL authentication, then move to Entra-only authentication.");
        if (recs.Count == 0)
            recs.Add("No immediate actions required — continue periodic scans to maintain the current posture.");
        doc.Bullets(recs.Distinct().Take(10));
        doc.Note("All recommendations are advisory. RateMyAzureSQL does not modify servers, databases, backup policies or security settings.");

        return doc;
    }

    // ── Detailed findings report ─────────────────────────────────────────────

    public static ReportDoc BuildFindings(SqlReportContext ctx)
    {
        var product = ctx.Flow.Label();
        var scan = ctx.Scan;
        var doc = new ReportDoc { Title = $"Azure {product} — Detailed Findings" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1($"2. {product} security & backup rating");
        RatingSection(doc, ctx);

        doc.H1("3. Detailed findings");
        if (scan is null)
            doc.P("No scan data was available when this report was generated.");
        else if (scan.Findings.Count == 0)
            doc.P("No findings — the estate matches the checks performed.");
        else
            foreach (var group in scan.Findings.GroupBy(f => f.Severity).OrderBy(g => SqlFindingsBuilder.SeverityOrder(g.Key)))
            {
                doc.P($"{group.Key} ({group.Count()})", bold: true, color: SeverityColor(group.Key));
                doc.Bullets(group.Select(f => $"[{f.Area}] {f.Category}: {f.Message} — {f.ResourceName}. Fix: {f.Fix}"));
            }

        doc.H1($"4. {Capitalise(ctx.Flow.HostLabel())} inventory");
        if (scan is null) doc.P("No scan data available.");
        else if (scan.Servers.Count == 0) doc.P($"No {ctx.Flow.HostPluralLabel()} in scope.");
        else
            foreach (var s in scan.Servers.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
            {
                doc.P($"{s.Name} ({s.KindLabel}, {s.Location})", bold: true);
                var lines = new List<string>
                {
                    $"Public network access: {(s.PublicNetworkAccess switch { true => "enabled", false => "disabled", _ => "unknown" })}" +
                        (s.PrivateEndpointCount > 0 ? $" • {s.PrivateEndpointCount} private endpoint(s)" : "") +
                        (string.IsNullOrEmpty(s.MinimalTlsVersion) ? " • no minimum TLS" : $" • minimum TLS {s.MinimalTlsVersion}"),
                    $"Admin: SQL login '{Fallback(s.SqlAdminLogin, "n/a")}' • Entra admin: {(s.HasEntraAdmin ? $"{s.EntraAdminLogin} ({s.EntraAdminType})" : "none")} • Entra-only: {YesNo(s.EntraOnlyAuthentication)}",
                    $"Defender for SQL: {YesNo(s.DefenderEnabled)} • Vulnerability assessment: {YesNo(s.VulnerabilityAssessmentEnabled)}" +
                        (s.Kind == SqlFlowKind.SqlDatabase ? $" • Auditing: {YesNo(s.AuditingEnabled)}{(s.AuditDestinations.Count > 0 ? $" → {string.Join(", ", s.AuditDestinations)}" : "")}" : ""),
                    $"TDE protector: {Fallback(s.EncryptionProtector, "unknown")}",
                };
                if (s.FirewallRules is { Count: > 0 })
                    lines.Add($"Firewall rules ({s.FirewallRules.Count}): {string.Join("; ", s.FirewallRules.Take(8).Select(r => $"{r.Name} = {r.Display}"))}{(s.FirewallRules.Count > 8 ? "; …" : "")}");
                if (s.Kind == SqlFlowKind.ManagedInstance)
                    lines.Add($"Tier: {s.Tier} {s.VCores} vCores • zone redundant: {(s.ZoneRedundant ? "yes" : "no")} • backup storage: {BackupPlanService.RedundancyLabel(s.BackupStorageRedundancy)}");
                if (s.FailoverGroups.Count > 0)
                    lines.Add($"Failover groups: {string.Join(", ", s.FailoverGroups.Select(f => $"{f.Name} → {f.PartnerServer} ({f.FailoverPolicy})"))}");
                doc.Bullets(lines);
            }

        doc.H1("5. Database inventory & backup details");
        if (scan is null) doc.P("No scan data available.");
        else if (scan.Databases.Count == 0) doc.P("No databases in scope.");
        else
            foreach (var d in scan.Databases.OrderBy(d => d.ServerName, StringComparer.OrdinalIgnoreCase).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase))
            {
                var rating = scan.Ratings.FirstOrDefault(r => r.TargetId.Equals(d.Id, StringComparison.OrdinalIgnoreCase));
                doc.P($"{d.ServerName}/{d.Name} — {d.TierLabel}{(d.MaxSizeBytes is not null ? $", {d.MaxSizeLabel}" : "")}{(rating is null ? " (not rated)" : $" — grade {rating.Grade}, {rating.Score}/100")}",
                    bold: true, color: rating is null ? null : SqlRatingService.ColorForGrade(rating.Grade));
                if (d.IsDataWarehouse) { doc.P("Dedicated SQL pool — not rated."); continue; }
                if (d.IsGeoSecondary) { doc.P("Read-only geo-secondary — not rated (backups are taken on the primary)."); continue; }
                doc.Bullets(
                [
                    $"Point-in-time restore: {(d.PitrRetentionDays is { } p ? $"{p} days" : "unknown")}{(d.DiffBackupIntervalHours is { } h ? $", differential every {h} h" : "")}{(d.EarliestRestoreDate is { } e ? $", earliest restore point {e:yyyy-MM-dd HH:mm} UTC" : "")}",
                    $"Long-term retention: {(d.LtrRead ? BackupPlanService.LtrLabel(d.WeeklyRetention, d.MonthlyRetention, d.YearlyRetention) : "unknown")}",
                    $"Backup storage redundancy: {BackupPlanService.RedundancyLabel(d.BackupStorageRedundancy)}",
                    $"Resilience: {(d.HasFailoverGroup ? $"failover group '{d.FailoverGroupName}'" : d.GeoReplicas.Count > 0 ? $"geo-replica on {string.Join(", ", d.GeoReplicas.Select(g => g.PartnerServer))}" : "no geo-replica")}; {(d.ZoneRedundant ? "zone redundant" : "not zone redundant")}",
                    $"Encryption: TDE {YesNo(d.TdeEnabled)}{(d.IsLedgerOn ? " • ledger on" : "")}",
                ]);
            }

        doc.H1("6. Backup improvement plan");
        var withBackupImprovements = scan?.Ratings.Where(r => r.BackupImprovements.Any()).OrderBy(r => r.BackupScore).ToList() ?? [];
        if (scan is null) doc.P("No scan data available.");
        else if (withBackupImprovements.Count == 0) doc.P("Every rated database already earns full marks for backups.");
        else
        {
            doc.P("Per database, the backup changes that gain the most points, largest first. Scripts for these changes can be generated in the Backups step of the app.");
            foreach (var r in withBackupImprovements)
            {
                doc.P($"{r.ServerName}/{r.TargetName} — backups {r.BackupScore}/{SqlRatingService.BackupPts}", bold: true);
                doc.Bullets(r.BackupImprovements.Select(i => $"+{i.PointsGained} pts — {i.Action}"));
            }
        }
        doc.Note("Cost reminder: " + string.Join(" ", BackupPlanService.CostNotes.Take(3)));

        return doc;
    }

    // ── Shared sections ──────────────────────────────────────────────────────

    private static void DocInfo(ReportDoc doc, SqlReportContext ctx) =>
        doc.Table(null,
        [
            ["Customer", Fallback(ctx.CustomerName, "Unknown")],
            ["Prepared by", Fallback(ctx.ReportAuthor, "RateMyAzureSQL")],
            ["Scan date", ctx.ScanDate.ToString("yyyy-MM-dd HH:mm")],
            ["Tenant", Fallback(ctx.TenantName, "Unknown")],
            ["Subscriptions in scope", ctx.SubscriptionLines.Count > 0 ? string.Join("\n", ctx.SubscriptionLines) : "None"],
            ["Generated by", $"RateMyAzureSQL — {ctx.Flow.Label()} security & backup assessment (read-only)"],
        ], "", firstColHeader: true);

    private static void RatingSection(ReportDoc doc, SqlReportContext ctx)
    {
        var ratings = ctx.Scan?.Ratings ?? [];
        if (ratings.Count == 0)
        {
            doc.P(ctx.Scan is null ? "No scan data available." : "No ratable databases in scope — no rating produced.");
            doc.Legend();
            return;
        }

        var worst = SqlRatingService.Worst(ratings)!;
        var avg = (int)Math.Round(ratings.Average(r => r.Score));
        var avgSec = (int)Math.Round(ratings.Average(r => r.SecurityScore));
        var avgBak = (int)Math.Round(ratings.Average(r => r.BackupScore));
        doc.Grade(worst.Grade, worst.GradeLabel, ratings.Count == 1
            ? $"Database '{worst.ServerName}/{worst.TargetName}' scores {worst.Score}/100 (security {worst.SecurityScore}/{SqlRatingService.SecurityPts}, backups {worst.BackupScore}/{SqlRatingService.BackupPts})." + (worst.CapReason is null ? "" : $" Grade capped: {worst.CapReason}")
            : $"Set by the weakest database '{worst.ServerName}/{worst.TargetName}' ({worst.Score}/100). Average {avg}/100 across {ratings.Count} databases: security {avgSec}/{SqlRatingService.SecurityPts}, backups {avgBak}/{SqlRatingService.BackupPts}.");

        var rows = new List<string[]>();
        var colors = new List<string?[]>();
        foreach (var r in ratings.OrderBy(r => r.ServerName, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.TargetName, StringComparer.OrdinalIgnoreCase))
        {
            rows.Add([$"{r.ServerName}/{r.TargetName}", $"{r.Grade} — {r.GradeLabel}", $"{r.Score}/100", $"{r.SecurityScore}/{SqlRatingService.SecurityPts}", $"{r.BackupScore}/{SqlRatingService.BackupPts}", r.CapReason ?? r.Improvements.FirstOrDefault()?.Action ?? "No gaps identified."]);
            var c = SqlRatingService.ColorForGrade(r.Grade);
            colors.Add([null, c, c, null, null, null]);
        }
        doc.Table(["Database", "Grade", "Score", "Security", "Backups", "Biggest gap"], rows, "", colors);

        doc.P("Scoring model: security 50 (network exposure 15 · identity & access 10 · threat protection & auditing 15 · encryption 10) + backups 50 (point-in-time restore 15 · long-term retention 15 · backup storage redundancy 10 · geo & zone resilience 10). " +
              "Grade bands: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F < 30. Caps: open to the internet = max D; TDE off = max D; locally redundant backups = max C; no long-term retention, no Defender for SQL or no Entra admin = max B.");
        doc.Legend();

        var any = false;
        foreach (var r in ratings.OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.TargetName, StringComparer.OrdinalIgnoreCase))
        {
            if (r.Improvements.Count == 0) continue;
            any = true;
            doc.P($"{r.ServerName}/{r.TargetName} (grade {r.Grade}, {r.Score}/100)", bold: true, color: SqlRatingService.ColorForGrade(r.Grade));
            doc.Bullets(r.Improvements.Select(i => $"+{i.PointsGained} pts [{i.Area}] — {i.Action}" +
                (SqlRatingService.WorstGrade(i.ResultingGrade, r.Grade) != i.ResultingGrade ? $" (raises the grade to {i.ResultingGrade})" : "")));
        }
        if (!any) doc.P("No improvements required — every database in scope earns full marks.");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string Fallback(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;
    private static string Count(SqlScanResult? scan, int count) => scan is null ? "—" : count.ToString();
    private static string YesNo(bool? value) => value switch { true => "yes", false => "no", null => "unknown" };
    private static string Capitalise(string s) => string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];

    public static string SeverityColor(string severity) => severity switch
    {
        "High" => "#D32F2F",
        "Medium" => "#F57C00",
        _ => "#1976D2"
    };
}
