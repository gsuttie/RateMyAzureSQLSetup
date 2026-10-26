using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>
/// Pure, deterministic A-F rating calculator for one database's security and backup setup, taking the
/// settings of its logical server / managed instance into account.
///
/// 100 points: 50 for security (network exposure 15, identity 10, threat protection 15, encryption 10)
/// and 50 for backups (point-in-time restore 15, long-term retention 15, backup storage redundancy 10,
/// geo and zone resilience 10), mapped to grades (A >= 90, B >= 75, C >= 60, D >= 45, E >= 30, F below)
/// with hard caps: open to the whole internet = max D; TDE off = max D; locally redundant backups = max C;
/// no long-term retention = max B; Defender for SQL off = max B; no Microsoft Entra admin = max B.
/// </summary>
public static class SqlRatingService
{
    // Category weights (security 50 + backups 50 = 100).
    public const int NetworkPts    = 15;
    public const int IdentityPts   = 10;
    public const int ThreatPts     = 15;
    public const int EncryptionPts = 10;
    public const int PitrPts       = 15;
    public const int LtrPts        = 15;
    public const int RedundancyPts = 10;
    public const int ResiliencePts = 10;
    public const int SecurityPts   = NetworkPts + IdentityPts + ThreatPts + EncryptionPts;
    public const int BackupPts     = PitrPts + LtrPts + RedundancyPts + ResiliencePts;

    public const string NetworkCategory    = "Network exposure";
    public const string IdentityCategory   = "Identity & access";
    public const string ThreatCategory     = "Threat protection & auditing";
    public const string EncryptionCategory = "Encryption";
    public const string PitrCategory       = "Point-in-time restore";
    public const string LtrCategory        = "Long-term retention";
    public const string RedundancyCategory = "Backup storage redundancy";
    public const string ResilienceCategory = "Geo & zone resilience";

    /// <summary>Computes and stores one rating per ratable database on the scan result.</summary>
    public static void RateAll(SqlScanResult result) =>
        result.Ratings = result.RatableDatabases
            .Select(db => Rate(db, result.Server(db.ServerId)))
            .ToList();

    /// <summary>Grade letter for a raw 0-100 score, before caps.</summary>
    public static string GradeForScore(int score) => score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 45 => "D",
        >= 30 => "E",
        _ => "F"
    };

    public static string LabelForGrade(string grade) => grade switch
    {
        "A" => "Excellent",
        "B" => "Good",
        "C" => "Average",
        "D" => "Below Average",
        "E" => "Poor",
        _ => "Unacceptable"
    };

    /// <summary>Traffic-light colour for a grade (hex, with leading '#'). Green to dark red.</summary>
    public static string ColorForGrade(string grade) => grade switch
    {
        "A" => "#388E3C",
        "B" => "#7CB342",
        "C" => "#FBC02D",
        "D" => "#F57C00",
        "E" => "#E64A19",
        _ => "#C62828"
    };

    /// <summary>The A-F legend shown in the app and in the reports.</summary>
    public static readonly (string Grade, string Label, string Description)[] Legend =
    [
        ("A", "EXCELLENT", "Outstanding — exceeds expectations"),
        ("B", "GOOD", "Above average — meets most expectations"),
        ("C", "AVERAGE", "Satisfactory — meets basic expectations"),
        ("D", "BELOW AVERAGE", "Below expectations — needs improvement"),
        ("E", "POOR", "Far below expectations — significant improvement needed"),
        ("F", "UNACCEPTABLE", "Unacceptable — does not meet minimum requirements"),
    ];

    /// <summary>The worse (further down the alphabet) of two grades.</summary>
    public static string WorstGrade(string a, string b) =>
        string.CompareOrdinal(a, b) >= 0 ? a : b;

    /// <summary>Overall grade for a set of ratings: the weakest database sets the grade.</summary>
    public static SqlRating? Worst(IEnumerable<SqlRating> ratings) =>
        ratings.OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.Score).FirstOrDefault();

    public static bool TlsIsModern(string tls) =>
        tls.Equals("1.2", StringComparison.Ordinal) || tls.Equals("1.3", StringComparison.Ordinal);

    // ── The engine ───────────────────────────────────────────────────────────

    public static SqlRating Rate(SqlDatabaseInfo db, SqlServerInfo? server)
    {
        var isMi = db.Kind == SqlFlowKind.ManagedInstance;
        var host = server?.Name ?? db.ServerName;
        var hostLabel = db.Kind.HostLabel();

        var rating = new SqlRating
        {
            TargetKind = db.Kind,
            TargetId = db.Id,
            TargetName = db.Name,
            ServerId = db.ServerId,
            ServerName = db.ServerName,
            SubscriptionId = db.SubscriptionId
        };

        // Caps collected as (key, max grade, reason); improvements may lift one by key.
        var caps = new List<(string Key, string MaxGrade, string Reason)>();
        var improvements = new List<(SqlImprovement Item, string? LiftsCapKey)>();

        void Improve(string area, string action, int points, string? liftsCapKey = null)
        {
            if (points > 0)
                improvements.Add((new SqlImprovement { Area = area, Action = action, PointsGained = points }, liftsCapKey));
        }

        static SqlRatingCategory Cat(string name, string area, int possible) => new() { Name = name, Area = area, Possible = possible };

        // ── 1. Network exposure (15) ─────────────────────────────────────────
        var net = Cat(NetworkCategory, RatingArea.Security, NetworkPts);
        if (server is null || server.PublicNetworkAccess is null)
        {
            net.Earned = 8;
            net.Details.Add("Public network access could not be determined — partial points awarded.");
        }
        else if (server.PublicNetworkAccess == false)
        {
            net.Earned = NetworkPts;
            net.Details.Add(isMi
                ? "The public data endpoint is disabled — the instance is reachable only inside its virtual network."
                : $"Public network access is disabled{(server.PrivateEndpointCount > 0 ? $"; {server.PrivateEndpointCount} private endpoint(s) provide access" : " (no private endpoint found — access is only possible via connectivity you add)")}.");
        }
        else if (isMi)
        {
            net.Earned = 6;
            net.Details.Add("The public data endpoint is enabled (TCP 3342) — the instance is reachable from outside its virtual network.");
            Improve(RatingArea.Security, $"Disable the public data endpoint on '{host}' and connect through the virtual network (VPN / ExpressRoute / peering) instead.", NetworkPts - net.Earned);
        }
        else
        {
            var earned = 8;
            net.Details.Add("Public network access is enabled — the server listens on a public endpoint.");
            if (server.PrivateEndpointCount > 0)
            {
                earned += 2;
                net.Details.Add($"{server.PrivateEndpointCount} private endpoint(s) exist alongside the public endpoint.");
            }

            if (server.FirewallRules is null)
            {
                net.Details.Add("Firewall rules could not be read.");
            }
            else
            {
                var deductions = 0;
                var allowAzure = server.AllowAzureServices;
                var broad = server.BroadRules.ToList();
                if (allowAzure)
                {
                    deductions += 3;
                    net.Details.Add("'Allow Azure services and resources to access this server' is on — any Azure tenant's resources can reach the endpoint.");
                }
                if (broad.Count > 0)
                {
                    deductions += 2;
                    net.Details.Add($"{broad.Count} broad firewall rule(s) cover more than 256 addresses: {string.Join(", ", broad.Take(3).Select(r => $"{r.Name} ({r.Display})"))}.");
                }
                var afterDeductions = Math.Max(0, earned - deductions);

                if (server.OpenToInternet)
                {
                    var open = server.FirewallRules.Where(r => r.IsOpenToInternet).Select(r => r.Name).ToList();
                    net.Details.Add($"Firewall rule(s) {string.Join(", ", open)} allow every IPv4 address (0.0.0.0–255.255.255.255).");
                    caps.Add(("internet", "D", $"A firewall rule on '{host}' allows every IPv4 address — the server is open to the whole internet."));
                    Improve(RatingArea.Security, $"Delete the firewall rule(s) {string.Join(", ", open)} on '{host}' that allow 0.0.0.0–255.255.255.255.", afterDeductions, "internet");
                    earned = 0;
                }
                else
                {
                    earned = afterDeductions;
                    if (allowAzure)
                        Improve(RatingArea.Security, $"Turn off 'Allow Azure services and resources to access this server' on '{host}'; use private endpoints, virtual network rules or specific IP ranges instead.", 3);
                    if (broad.Count > 0)
                        Improve(RatingArea.Security, $"Narrow the broad firewall rule(s) {string.Join(", ", broad.Take(3).Select(r => r.Name))} on '{host}' to the addresses that really need access.", 2);
                    if (server.FirewallRules.Count == 0 && !allowAzure)
                        net.Details.Add("No firewall rules are defined, so nothing can connect over the public endpoint yet.");
                }
            }
            net.Earned = earned;
            Improve(RatingArea.Security, $"Disable public network access on '{host}' and connect through private endpoints only.", NetworkPts - net.Earned, server.OpenToInternet ? "internet" : null);
        }
        rating.Categories.Add(net);

        // ── 2. Identity & access (10) ────────────────────────────────────────
        var identity = Cat(IdentityCategory, RatingArea.Security, IdentityPts);
        if (server is null)
        {
            identity.Earned = 5;
            identity.Details.Add("Administrator settings could not be determined — partial points awarded.");
        }
        else
        {
            if (server.HasEntraAdmin)
            {
                identity.Earned += 5;
                identity.Details.Add($"Microsoft Entra admin: {server.EntraAdminLogin}{(string.IsNullOrEmpty(server.EntraAdminType) ? "" : $" ({server.EntraAdminType})")}.");
            }
            else
            {
                identity.Details.Add("No Microsoft Entra admin — only SQL authentication (username and password) is possible.");
                caps.Add(("noentra", "B", $"No Microsoft Entra admin is set on '{host}' — only SQL authentication is possible."));
                Improve(RatingArea.Security, $"Set a Microsoft Entra admin on '{host}' (an Entra group is best practice).", 5, "noentra");
            }

            var entraOnly = server.HasEntraAdmin ? server.EntraOnlyAuthentication : false;
            switch (entraOnly)
            {
                case true:
                    identity.Earned += 5;
                    identity.Details.Add("Microsoft Entra-only authentication is on — SQL logins are disabled.");
                    break;
                case null:
                    identity.Earned += 2;
                    identity.Details.Add("Entra-only authentication state could not be determined.");
                    break;
                default:
                    identity.Details.Add($"SQL authentication is still enabled{(string.IsNullOrEmpty(server.SqlAdminLogin) ? "" : $" (admin login '{server.SqlAdminLogin}')")}.");
                    Improve(RatingArea.Security, $"Enable Microsoft Entra-only authentication on '{host}' so SQL logins{(string.IsNullOrEmpty(server.SqlAdminLogin) ? "" : $" (including '{server.SqlAdminLogin}')")} stop working.", 5);
                    break;
            }
        }
        rating.Categories.Add(identity);

        // ── 3. Threat protection & auditing (15) ─────────────────────────────
        var threat = Cat(ThreatCategory, RatingArea.Security, ThreatPts);
        var defenderPts = isMi ? 9 : 6;
        var vaPts = isMi ? 6 : 3;
        var auditPts = isMi ? 0 : 6;
        if (server is null)
        {
            threat.Earned = ThreatPts / 2;
            threat.Details.Add("Threat protection settings could not be determined — half points awarded.");
        }
        else
        {
            switch (server.DefenderEnabled)
            {
                case true:
                    threat.Earned += defenderPts;
                    threat.Details.Add("Microsoft Defender for SQL is enabled.");
                    break;
                case null:
                    threat.Earned += defenderPts / 2;
                    threat.Details.Add("Defender for SQL state could not be determined — half points awarded.");
                    break;
                default:
                    threat.Details.Add("Microsoft Defender for SQL is off — no threat detection, no vulnerability assessment.");
                    caps.Add(("nodefender", "B", $"Microsoft Defender for SQL is off on '{host}' — threats like SQL injection and brute-force logins go unnoticed."));
                    Improve(RatingArea.Security, $"Enable Microsoft Defender for SQL on '{host}' (server setting, or the subscription-level Defender plan).", defenderPts + vaPts, "nodefender");
                    break;
            }

            if (server.DefenderEnabled == false)
            {
                threat.Details.Add("Vulnerability assessment needs Defender for SQL.");
            }
            else switch (server.VulnerabilityAssessmentEnabled)
            {
                case true:
                    threat.Earned += vaPts;
                    threat.Details.Add("Vulnerability assessment is enabled.");
                    break;
                case null:
                    threat.Earned += vaPts / 2;
                    threat.Details.Add("Vulnerability assessment state could not be determined.");
                    break;
                default:
                    threat.Details.Add("Vulnerability assessment is not enabled.");
                    Improve(RatingArea.Security, $"Enable SQL vulnerability assessment (express configuration) on '{host}' so misconfigurations are scanned weekly.", vaPts);
                    break;
            }

            if (isMi)
            {
                threat.Details.Add("Auditing on managed instances is configured in T-SQL and is not assessed here.");
            }
            else switch (server.AuditingEnabled)
            {
                case true:
                    threat.Earned += auditPts;
                    threat.Details.Add($"Auditing is enabled{(server.AuditDestinations.Count > 0 ? $" → {string.Join(", ", server.AuditDestinations)}" : "")}.");
                    break;
                case null:
                    threat.Earned += auditPts / 2;
                    threat.Details.Add("Auditing state could not be determined — half points awarded.");
                    break;
                default:
                    threat.Details.Add("Auditing is disabled — logins and queries leave no trail.");
                    Improve(RatingArea.Security, $"Enable auditing on '{host}' and send the audit log to a Log Analytics workspace.", auditPts);
                    break;
            }
        }
        rating.Categories.Add(threat);

        // ── 4. Encryption (10) ───────────────────────────────────────────────
        var enc = Cat(EncryptionCategory, RatingArea.Security, EncryptionPts);
        var keyLabel = server is null ? "" : server.UsesCustomerManagedKey ? " with a customer-managed key (Key Vault)" : " with a service-managed key";
        if (isMi)
        {
            enc.Earned += 7;
            enc.Details.Add($"Transparent data encryption is always on for managed instance databases{keyLabel}.");
        }
        else switch (db.TdeEnabled)
        {
            case true:
                enc.Earned += 7;
                enc.Details.Add($"Transparent data encryption is enabled{keyLabel}.");
                break;
            case null:
                enc.Earned += 4;
                enc.Details.Add("TDE state could not be determined — partial points awarded.");
                break;
            default:
                enc.Details.Add("Transparent data encryption is DISABLED — data files and backups are stored unencrypted.");
                caps.Add(("notde", "D", $"Transparent data encryption is disabled on '{db.Name}'."));
                Improve(RatingArea.Security, $"Enable transparent data encryption on '{db.Name}'.", 7, "notde");
                break;
        }

        if (server is null)
        {
            enc.Earned += 1;
            enc.Details.Add("Minimum TLS version could not be determined.");
        }
        else if (TlsIsModern(server.MinimalTlsVersion))
        {
            enc.Earned += 3;
            enc.Details.Add($"Minimum TLS version {server.MinimalTlsVersion}.");
        }
        else
        {
            enc.Details.Add(string.IsNullOrEmpty(server.MinimalTlsVersion) || server.MinimalTlsVersion.Equals("None", StringComparison.OrdinalIgnoreCase)
                ? "No minimum TLS version is enforced — clients may connect with TLS 1.0 or 1.1."
                : $"Minimum TLS version {server.MinimalTlsVersion} allows weak protocols.");
            Improve(RatingArea.Security, $"Set the minimum TLS version on '{host}' to 1.2.", 3);
        }
        rating.Categories.Add(enc);

        // ── 5. Point-in-time restore (15) ────────────────────────────────────
        var pitr = Cat(PitrCategory, RatingArea.Backups, PitrPts);
        if (db.PitrRetentionDays is not { } days)
        {
            pitr.Earned = 8;
            pitr.Details.Add("Point-in-time retention could not be read — partial points awarded.");
        }
        else if (db.IsBasicTier)
        {
            pitr.Earned = days >= 7 ? PitrPts : (int)Math.Round(PitrPts * days / 7.0);
            pitr.Details.Add($"{days} day(s) of point-in-time restore (the Basic tier allows at most 7).");
            if (days < 7)
                Improve(RatingArea.Backups, $"Raise point-in-time retention on '{db.Name}' to 7 days (the Basic tier maximum).", PitrPts - pitr.Earned);
        }
        else
        {
            pitr.Earned = days switch { >= 35 => 15, >= 28 => 13, >= 14 => 11, >= 7 => 8, _ => (int)Math.Round(8 * days / 7.0) };
            pitr.Details.Add($"{days} day(s) of point-in-time restore (up to 35 available).");
            if (days < 35)
                Improve(RatingArea.Backups, $"Raise point-in-time retention on '{db.Name}' from {days} to 35 days{(days < 14 ? " (14 days is the usual minimum for production)" : "")}.", PitrPts - pitr.Earned);
        }
        if (db.DiffBackupIntervalHours is { } diff)
            pitr.Details.Add(diff <= 12
                ? "Differential backups every 12 h."
                : "Differential backups every 24 h — a 12 h interval halves the worst-case restore time.");
        if (db.EarliestRestoreDate is { } earliest)
            pitr.Details.Add($"Earliest restore point: {earliest:yyyy-MM-dd HH:mm} UTC.");
        rating.Categories.Add(pitr);

        // ── 6. Long-term retention (15) ──────────────────────────────────────
        var ltr = Cat(LtrCategory, RatingArea.Backups, LtrPts);
        if (!db.LtrRead)
        {
            ltr.Earned = 8;
            ltr.Details.Add("The long-term retention policy could not be read — partial points awarded.");
        }
        else if (!db.HasLtr)
        {
            ltr.Details.Add("No long-term retention policy — nothing older than the point-in-time window can be restored.");
            caps.Add(("noltr", "B", $"No long-term retention on '{db.Name}' — nothing older than {db.PitrRetentionDays ?? 7} days can be restored."));
            Improve(RatingArea.Backups, $"Configure long-term retention on '{db.Name}' (for example weekly backups kept 12 weeks, monthly 12 months, yearly 7 years).", LtrPts, "noltr");
        }
        else
        {
            ltr.Details.Add($"Weekly {SqlDatabaseInfo.DurationLabel(db.WeeklyRetention)} · monthly {SqlDatabaseInfo.DurationLabel(db.MonthlyRetention)} · yearly {SqlDatabaseInfo.DurationLabel(db.YearlyRetention)}{(db.HasYearlyLtr && db.WeekOfYear is > 0 ? $" (week {db.WeekOfYear})" : "")}.");
            if (db.HasWeeklyLtr) ltr.Earned += 5;
            else Improve(RatingArea.Backups, $"Add weekly backups to the long-term retention policy of '{db.Name}' (for example keep 12 weeks).", 5);
            if (db.HasMonthlyLtr) ltr.Earned += 5;
            else Improve(RatingArea.Backups, $"Add monthly backups to the long-term retention policy of '{db.Name}' (for example keep 12 months).", 5);
            if (db.HasYearlyLtr) ltr.Earned += 5;
            else Improve(RatingArea.Backups, $"Add yearly backups to the long-term retention policy of '{db.Name}' (for example keep 7 years).", 5);
        }
        rating.Categories.Add(ltr);

        // ── 7. Backup storage redundancy (10) ────────────────────────────────
        var red = Cat(RedundancyCategory, RatingArea.Backups, RedundancyPts);
        var redundancy = db.BackupStorageRedundancy;
        var redTarget = isMi ? $"on '{host}' (instance-level setting)" : $"on '{db.Name}'";
        switch (redundancy.ToLowerInvariant())
        {
            case "geozone":
                red.Earned = RedundancyPts;
                red.Details.Add("Geo-zone-redundant backup storage — copies in three zones and in the paired region.");
                break;
            case "geo":
                red.Earned = RedundancyPts;
                red.Details.Add("Geo-redundant backup storage — a copy is kept in the paired region.");
                break;
            case "zone":
                red.Earned = 5;
                red.Details.Add("Zone-redundant backup storage — survives a datacenter failure but not a regional outage.");
                Improve(RatingArea.Backups, $"Change backup storage redundancy {redTarget} from zone-redundant to geo-zone-redundant so backups survive a regional outage.", 5);
                break;
            case "local":
                red.Details.Add("Locally redundant backup storage — a regional outage would take the database AND every backup with it.");
                caps.Add(("lrs", "C", $"Backups of '{db.Name}' are locally redundant — a regional outage would lose the database and every backup."));
                Improve(RatingArea.Backups, $"Change backup storage redundancy {redTarget} to geo-redundant (or geo-zone-redundant).", RedundancyPts, "lrs");
                break;
            default:
                red.Earned = 5;
                red.Details.Add("Backup storage redundancy could not be determined — half points awarded.");
                break;
        }
        rating.Categories.Add(red);

        // ── 8. Geo & zone resilience (10) ────────────────────────────────────
        var res = Cat(ResilienceCategory, RatingArea.Backups, ResiliencePts);
        var fog = server?.FailoverGroups.FirstOrDefault(f => f.Name.Equals(db.FailoverGroupName, StringComparison.OrdinalIgnoreCase));
        if (db.HasFailoverGroup)
        {
            res.Earned += 6;
            res.Details.Add($"Failover group '{db.FailoverGroupName}'{(fog is null ? "" : $" ({fog.FailoverPolicy.ToLowerInvariant()} failover, partner {fog.PartnerServer}{(string.IsNullOrEmpty(fog.PartnerLocation) ? "" : $" in {fog.PartnerLocation}")})")}.");
        }
        else if (db.GeoReplicas.Count > 0)
        {
            res.Earned += 4;
            res.Details.Add($"Active geo-replica: {string.Join(", ", db.GeoReplicas.Select(g => $"{g.PartnerServer}{(string.IsNullOrEmpty(g.PartnerLocation) ? "" : $" ({g.PartnerLocation})")}"))}.");
            Improve(RatingArea.Backups, $"Put the geo-replica of '{db.Name}' into a failover group for automatic failover and a stable listener endpoint.", 2);
        }
        else
        {
            res.Details.Add("No geo-replica or failover group — a regional outage means restoring from geo-backup (RPO up to 1 h, RTO hours).");
            Improve(RatingArea.Backups, isMi
                ? $"Create an instance failover group for '{host}' with a partner instance in the paired region."
                : $"Add '{db.Name}' to a failover group with a partner server in the paired region.", 6);
        }

        if (db.ZoneRedundant)
        {
            res.Earned += 4;
            res.Details.Add(isMi ? "The instance is zone redundant."
                : db.ZoneRedundancyFromPool ? $"Zone redundant (via elastic pool '{db.ElasticPoolName}')."
                : "The database is zone redundant.");
        }
        else if (db.SupportsZoneRedundancy)
        {
            res.Details.Add(isMi ? "The instance is not zone redundant." : "Not zone redundant — a datacenter failure means downtime.");
            Improve(RatingArea.Backups, isMi
                ? $"Enable zone redundancy on '{host}'."
                : db.ElasticPoolId is not null
                    ? $"Enable zone redundancy on elastic pool '{db.ElasticPoolName}' (applies to '{db.Name}')."
                    : $"Enable zone redundancy on '{db.Name}'.", 4);
        }
        else
        {
            res.Details.Add($"Zone redundancy is not available on the {db.TierLabel} tier.");
            Improve(RatingArea.Backups, $"Move '{db.Name}' from {db.Tier} to General Purpose (or higher) to make zone redundancy available.", 4);
        }
        rating.Categories.Add(res);

        // ── Score, caps and grade ────────────────────────────────────────────
        rating.Score = rating.Categories.Sum(c => c.Earned);
        rating.SecurityScore = rating.Categories.Where(c => c.Area == RatingArea.Security).Sum(c => c.Earned);
        rating.BackupScore = rating.Categories.Where(c => c.Area == RatingArea.Backups).Sum(c => c.Earned);

        var scoreGrade = GradeForScore(rating.Score);
        var finalGrade = caps.Aggregate(scoreGrade, (g, cap) => WorstGrade(g, cap.MaxGrade));

        rating.Grade = finalGrade;
        rating.GradeLabel = LabelForGrade(finalGrade);
        rating.CapReason = finalGrade != scoreGrade
            ? caps.Where(c => c.MaxGrade == finalGrade).Select(c => c.Reason).FirstOrDefault()
            : null;

        // ── Resulting grade per improvement (score + points, minus any lifted cap) ──
        foreach (var (item, liftsCapKey) in improvements)
        {
            var newScore = Math.Min(100, rating.Score + item.PointsGained);
            var remainingCaps = caps.Where(c => c.Key != liftsCapKey);
            item.ResultingGrade = remainingCaps.Aggregate(GradeForScore(newScore), (g, cap) => WorstGrade(g, cap.MaxGrade));
        }
        rating.Improvements = improvements
            .Select(i => i.Item)
            .OrderByDescending(i => i.PointsGained)
            .ThenBy(i => i.Area == RatingArea.Backups ? 0 : 1)
            .ToList();

        return rating;
    }
}
