using System.Text;
using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>A target backup configuration the user wants to apply to one or more databases.</summary>
public sealed record BackupPlan
{
    public int PitrDays { get; init; } = 35;
    public int DiffHours { get; init; } = 12;
    public string Weekly { get; init; } = "P12W";
    public string Monthly { get; init; } = "P12M";
    public string Yearly { get; init; } = "P7Y";
    public int WeekOfYear { get; init; } = 1;

    /// <summary>"Geo", "GeoZone", "Zone" or "Local".</summary>
    public string Redundancy { get; init; } = "GeoZone";
    public bool ZoneRedundant { get; init; } = true;
    public bool FailoverGroup { get; init; } = true;

    public bool HasLtr => SqlDatabaseInfo.IsSet(Weekly) || SqlDatabaseInfo.IsSet(Monthly) || SqlDatabaseInfo.IsSet(Yearly);
}

/// <summary>
/// Turns a target backup plan into the concrete changes per database (so the user can see the delta)
/// and into PowerShell (Az.Sql) or Azure CLI scripts. RateMyAzureSQL never runs these itself.
/// </summary>
public static class BackupPlanService
{
    public sealed record Preset(string Key, string Label, string Description, BackupPlan Plan);
    public sealed record PlanOption(string Key, string Label, bool Enabled);
    public sealed record Change(string Setting, string From, string To, string? Note = null);

    public static readonly Preset[] Presets =
    [
        new("baseline", "Baseline",
            "Enough for non-critical workloads: 14 days of point-in-time restore, differential backups every 12 h, weekly backups kept for 4 weeks, geo-redundant backup storage.",
            new BackupPlan { PitrDays = 14, DiffHours = 12, Weekly = "P4W", Monthly = "PT0S", Yearly = "PT0S", Redundancy = "Geo", ZoneRedundant = false, FailoverGroup = false }),
        new("recommended", "Recommended",
            "Production default: 35 days of point-in-time restore, weekly backups for 12 weeks, monthly for 12 months, yearly for 7 years, geo-zone-redundant backup storage, zone redundancy and a failover group.",
            new BackupPlan()),
        new("compliance", "Compliance",
            "Regulated data: everything in Recommended plus weekly backups kept for a year, monthly for 10 years and yearly for 10 years (the maximum).",
            new BackupPlan { Weekly = "P52W", Monthly = "P120M", Yearly = "P10Y" }),
    ];

    public static readonly (string Key, string Label)[] RedundancyChoices =
    [
        ("GeoZone", "Geo-zone-redundant (3 zones + paired region)"),
        ("Geo", "Geo-redundant (paired region)"),
        ("Zone", "Zone-redundant (3 zones, one region)"),
        ("Local", "Locally redundant (one datacenter)"),
    ];

    public static readonly string[] WeeklyChoices = ["PT0S", "P1W", "P4W", "P8W", "P12W", "P26W", "P52W"];
    public static readonly string[] MonthlyChoices = ["PT0S", "P1M", "P3M", "P6M", "P12M", "P24M", "P36M", "P60M", "P84M", "P120M"];
    public static readonly string[] YearlyChoices = ["PT0S", "P1Y", "P2Y", "P3Y", "P5Y", "P7Y", "P10Y"];
    public static readonly int[] PitrChoices = [1, 3, 7, 14, 21, 28, 35];

    /// <summary>Cost notes shown next to the plan; approximate ratios from the Azure SQL backup storage price list.</summary>
    public static readonly string[] CostNotes =
    [
        "Point-in-time backup storage equal to 100% of the database's maximum size is included; storage beyond that is billed per GB-month. Longer retention costs more only when the database changes a lot.",
        "Long-term retention backups are billed per GB-month at the backup storage rate for their redundancy. A yearly full backup of a 50 GB database kept 7 years is roughly 350 GB-months.",
        "Backup storage redundancy pricing is approximately: locally redundant 1×, zone-redundant 1.25×, geo-redundant 2×, geo-zone-redundant 2.5×. Changing it affects new backups only.",
        "A failover group needs a second server with a copy of each database in the paired region, billed at the secondary's compute tier (readable secondaries can serve reporting traffic).",
        "Zone redundancy is free on Business Critical / Premium, and included on General Purpose and Hyperscale in regions that support it; it is not available on Basic or Standard.",
    ];

    public static List<PlanOption> DefaultOptions(SqlFlowKind kind) =>
    [
        new("pitr", "Point-in-time retention", true),
        new("diff", "Differential backup interval", kind == SqlFlowKind.SqlDatabase),
        new("ltr", "Long-term retention policy", true),
        new("redundancy", "Backup storage redundancy", true),
        new("zone", "Zone redundancy", true),
        new("fog", "Failover group", true),
    ];

    /// <summary>What applying the plan would change for one database (empty when it already matches).</summary>
    public static List<Change> Describe(SqlDatabaseInfo db, SqlServerInfo? server, BackupPlan plan, ISet<string> enabled)
    {
        var changes = new List<Change>();
        var isMi = db.Kind == SqlFlowKind.ManagedInstance;

        if (enabled.Contains("pitr"))
        {
            var target = Math.Min(plan.PitrDays, db.MaxPitrDays);
            var current = db.PitrRetentionDays;
            if (current != target)
                changes.Add(new Change("Point-in-time retention", current is null ? "unknown" : $"{current} days", $"{target} days",
                    target < plan.PitrDays ? "capped at 7 days by the Basic tier" : null));
        }

        if (enabled.Contains("diff") && !isMi && !db.IsHyperscale && db.DiffBackupIntervalHours != plan.DiffHours)
            changes.Add(new Change("Differential backups", db.DiffBackupIntervalHours is null ? "unknown" : $"every {db.DiffBackupIntervalHours} h", $"every {plan.DiffHours} h"));

        if (enabled.Contains("ltr"))
        {
            var from = LtrLabel(db.WeeklyRetention, db.MonthlyRetention, db.YearlyRetention);
            var to = LtrLabel(plan.Weekly, plan.Monthly, plan.Yearly);
            if (!db.LtrRead || from != to)
                changes.Add(new Change("Long-term retention", db.LtrRead ? from : "unknown", to));
        }

        if (enabled.Contains("redundancy") && !db.BackupStorageRedundancy.Equals(plan.Redundancy, StringComparison.OrdinalIgnoreCase))
            changes.Add(new Change("Backup storage redundancy", RedundancyLabel(db.BackupStorageRedundancy), RedundancyLabel(plan.Redundancy),
                isMi ? "instance-level setting: applies to every database on the instance" : db.IsHyperscale ? "Hyperscale: needs a database copy" : null));

        if (enabled.Contains("zone") && plan.ZoneRedundant && !db.ZoneRedundant)
            changes.Add(db.SupportsZoneRedundancy
                ? new Change("Zone redundancy", "off", "on", isMi ? "instance-level setting" : db.ElasticPoolId is not null ? $"set on elastic pool '{db.ElasticPoolName}'" : null)
                : new Change("Zone redundancy", "off", "unavailable", $"not supported on the {db.Tier} tier — the script skips it"));

        if (enabled.Contains("fog") && plan.FailoverGroup && !db.HasFailoverGroup)
            changes.Add(new Change("Failover group", db.GeoReplicas.Count > 0 ? "geo-replica without a group" : "none", "new group with a partner in the paired region",
                "the partner server / instance must exist first"));

        return changes;
    }

    public static string LtrLabel(string weekly, string monthly, string yearly)
    {
        var parts = new List<string>();
        if (SqlDatabaseInfo.IsSet(weekly)) parts.Add($"weekly × {SqlDatabaseInfo.DurationLabel(weekly)}");
        if (SqlDatabaseInfo.IsSet(monthly)) parts.Add($"monthly × {SqlDatabaseInfo.DurationLabel(monthly)}");
        if (SqlDatabaseInfo.IsSet(yearly)) parts.Add($"yearly × {SqlDatabaseInfo.DurationLabel(yearly)}");
        return parts.Count == 0 ? "none" : string.Join(", ", parts);
    }

    public static string RedundancyLabel(string redundancy) => redundancy.ToLowerInvariant() switch
    {
        "geozone" => "Geo-zone-redundant",
        "geo" => "Geo-redundant",
        "zone" => "Zone-redundant",
        "local" => "Locally redundant",
        "" => "unknown",
        _ => redundancy
    };

    // ── PowerShell ───────────────────────────────────────────────────────────

    public static string GeneratePowerShell(IReadOnlyList<SqlDatabaseInfo> databases, SqlServerInfo? server, BackupPlan plan, ISet<string> enabled)
    {
        if (databases.Count == 0) return "# No databases selected.";
        var first = databases[0];
        var isMi = first.Kind == SqlFlowKind.ManagedInstance;
        var sb = new StringBuilder();
        sb.AppendLine("# Backup improvement script — generated by RateMyAzureSQL");
        sb.AppendLine($"# {first.Kind.HostLabel()}: {first.ServerName} · databases: {string.Join(", ", databases.Select(d => d.Name))}");
        sb.AppendLine();
        sb.AppendLine("# ─── Prerequisites ───");
        sb.AppendLine("# Requires the Az.Sql PowerShell module. Run Connect-AzAccount first.");
        sb.AppendLine("# Review every line before running: this script CHANGES backup settings (and may add cost).");
        sb.AppendLine();
        sb.AppendLine($"Set-AzContext -Subscription \"{first.SubscriptionId}\" | Out-Null");
        sb.AppendLine($"$resourceGroup = \"{first.ResourceGroup}\"");
        sb.AppendLine($"${(isMi ? "instanceName" : "serverName")} = \"{first.ServerName}\"");
        sb.AppendLine($"$databases = @({string.Join(", ", databases.Select(d => $"\"{d.Name}\""))})");
        var basicNames = databases.Where(d => d.IsBasicTier).Select(d => d.Name).ToList();
        if (basicNames.Count > 0 && plan.PitrDays > 7)
            sb.AppendLine($"$basicTier = @({string.Join(", ", basicNames.Select(n => $"\"{n}\""))})   # Basic tier: point-in-time retention is capped at 7 days");
        sb.AppendLine();

        var target = isMi ? "-ResourceGroupName $resourceGroup -InstanceName $instanceName" : "-ResourceGroupName $resourceGroup -ServerName $serverName";
        var perDb = new StringBuilder();

        if (enabled.Contains("pitr") || (enabled.Contains("diff") && !isMi))
        {
            var basic = databases.Where(d => d.IsBasicTier).Select(d => d.Name).ToList();
            perDb.AppendLine("    # ─── Point-in-time restore retention ───");
            if (basic.Count > 0 && plan.PitrDays > 7)
                perDb.AppendLine($"    # Basic tier allows at most 7 days: {string.Join(", ", basic)} get 7.");
            var days = enabled.Contains("pitr") ? plan.PitrDays.ToString() : "$null";
            if (isMi)
            {
                perDb.AppendLine($"    Set-AzSqlInstanceDatabaseBackupShortTermRetentionPolicy {target} -DatabaseName $db -RetentionDays {RetentionExpr(plan, basic.Count > 0)}");
            }
            else
            {
                var diff = enabled.Contains("diff") ? $" -DiffBackupIntervalInHours {plan.DiffHours}" : "";
                if (enabled.Contains("pitr"))
                    perDb.AppendLine($"    Set-AzSqlDatabaseBackupShortTermRetentionPolicy {target} -DatabaseName $db -RetentionDays {RetentionExpr(plan, basic.Count > 0)}{diff}");
                else
                    perDb.AppendLine($"    Set-AzSqlDatabaseBackupShortTermRetentionPolicy {target} -DatabaseName $db{diff}");
                if (enabled.Contains("diff") && databases.Any(d => d.IsHyperscale))
                    perDb.AppendLine("    # Hyperscale databases ignore the differential backup interval.");
            }
            perDb.AppendLine();
        }

        if (enabled.Contains("ltr"))
        {
            perDb.AppendLine("    # ─── Long-term retention (weekly / monthly / yearly full backups) ───");
            var cmd = isMi ? "Set-AzSqlInstanceDatabaseBackupLongTermRetentionPolicy" : "Set-AzSqlDatabaseBackupLongTermRetentionPolicy";
            if (plan.HasLtr)
                perDb.AppendLine($"    {cmd} {target} -DatabaseName $db -WeeklyRetention {Iso(plan.Weekly)} -MonthlyRetention {Iso(plan.Monthly)} -YearlyRetention {Iso(plan.Yearly)} -WeekOfYear {plan.WeekOfYear}");
            else
                perDb.AppendLine($"    {cmd} {target} -DatabaseName $db -RemovePolicy   # the plan has no long-term retention");
            perDb.AppendLine();
        }

        if (enabled.Contains("redundancy") && !isMi)
        {
            perDb.AppendLine("    # ─── Backup storage redundancy (applies to new backups) ───");
            if (databases.Any(d => d.IsHyperscale))
                perDb.AppendLine("    # Hyperscale: redundancy can only be changed by copying the database (New-AzSqlDatabaseCopy -BackupStorageRedundancy ...).");
            perDb.AppendLine($"    Set-AzSqlDatabase {target} -DatabaseName $db -BackupStorageRedundancy {plan.Redundancy}");
            perDb.AppendLine();
        }

        if (enabled.Contains("zone") && plan.ZoneRedundant && !isMi)
        {
            var eligible = databases.Where(d => d.SupportsZoneRedundancy && !d.ZoneRedundant && d.ElasticPoolId is null).ToList();
            var pools = databases.Where(d => d.SupportsZoneRedundancy && !d.ZoneRedundant && d.ElasticPoolId is not null).Select(d => d.ElasticPoolName).Distinct().ToList();
            var unsupported = databases.Where(d => !d.SupportsZoneRedundancy).Select(d => d.Name).ToList();
            perDb.AppendLine("    # ─── Zone redundancy ───");
            if (unsupported.Count > 0)
                perDb.AppendLine($"    # Not available on the Basic/Standard tier: {string.Join(", ", unsupported)} are skipped.");
            if (eligible.Count > 0)
                perDb.AppendLine($"    if ($db -in @({string.Join(", ", eligible.Select(d => $"\"{d.Name}\""))})) {{ Set-AzSqlDatabase {target} -DatabaseName $db -ZoneRedundant }}");
            foreach (var pool in pools)
                perDb.AppendLine($"    # Pooled database: enable it on the pool instead → Set-AzSqlElasticPool {target} -ElasticPoolName \"{pool}\" -ZoneRedundant");
            perDb.AppendLine();
        }

        if (perDb.Length > 0)
        {
            sb.AppendLine("foreach ($db in $databases) {");
            sb.AppendLine("    Write-Host \"Updating $db…\"");
            sb.Append(perDb);
            sb.AppendLine("}");
            sb.AppendLine();
        }

        if (isMi && enabled.Contains("redundancy"))
        {
            sb.AppendLine("# ─── Backup storage redundancy (instance-level, applies to every database) ───");
            sb.AppendLine($"Set-AzSqlInstance -ResourceGroupName $resourceGroup -Name $instanceName -BackupStorageRedundancy {plan.Redundancy} -Force");
            sb.AppendLine();
        }
        if (isMi && enabled.Contains("zone") && plan.ZoneRedundant && server is { ZoneRedundant: false })
        {
            sb.AppendLine("# ─── Zone redundancy (instance-level) ───");
            sb.AppendLine("Set-AzSqlInstance -ResourceGroupName $resourceGroup -Name $instanceName -ZoneRedundant -Force");
            sb.AppendLine();
        }

        if (enabled.Contains("fog") && plan.FailoverGroup)
        {
            sb.AppendLine("# ─── Failover group (needs a partner in the paired region; create it first) ───");
            if (isMi)
            {
                sb.AppendLine("$partnerResourceGroup = \"<PARTNER-RESOURCE-GROUP>\"   # <- update");
                sb.AppendLine("$partnerInstanceName = \"<PARTNER-INSTANCE>\"          # <- an instance in the paired region, same DNS zone");
                sb.AppendLine("$partnerRegion = \"<PAIRED-REGION>\"                   # <- e.g. northeurope");
                sb.AppendLine($"New-AzSqlDatabaseInstanceFailoverGroup -Name \"fog-$instanceName\" -Location \"{first.Location}\" -ResourceGroupName $resourceGroup -PrimaryManagedInstanceName $instanceName `");
                sb.AppendLine("    -PartnerRegion $partnerRegion -PartnerResourceGroupName $partnerResourceGroup -PartnerManagedInstanceName $partnerInstanceName `");
                sb.AppendLine("    -FailoverPolicy Automatic -GracePeriodWithDataLossHours 1");
                sb.AppendLine("# Every database on the instance is replicated automatically.");
            }
            else
            {
                sb.AppendLine("$partnerResourceGroup = \"<PARTNER-RESOURCE-GROUP>\"   # <- update");
                sb.AppendLine("$partnerServerName = \"<PARTNER-SERVER>\"              # <- a logical server in the paired region");
                sb.AppendLine("$failoverGroupName = \"fog-$serverName\"");
                sb.AppendLine("if (-not (Get-AzSqlDatabaseFailoverGroup -ResourceGroupName $resourceGroup -ServerName $serverName -FailoverGroupName $failoverGroupName -ErrorAction SilentlyContinue)) {");
                sb.AppendLine("    New-AzSqlDatabaseFailoverGroup -ResourceGroupName $resourceGroup -ServerName $serverName -PartnerResourceGroupName $partnerResourceGroup `");
                sb.AppendLine("        -PartnerServerName $partnerServerName -FailoverGroupName $failoverGroupName -FailoverPolicy Automatic -GracePeriodWithDataLossHours 1 | Out-Null");
                sb.AppendLine("}");
                sb.AppendLine("Get-AzSqlDatabase -ResourceGroupName $resourceGroup -ServerName $serverName | Where-Object DatabaseName -in $databases |");
                sb.AppendLine("    Add-AzSqlDatabaseToFailoverGroup -ResourceGroupName $resourceGroup -ServerName $serverName -FailoverGroupName $failoverGroupName | Out-Null");
                sb.AppendLine("# Point clients at \"$failoverGroupName.database.windows.net\" so they follow failovers.");
            }
            sb.AppendLine();
        }

        if (enabled.Count == 0)
            sb.AppendLine("# No options selected — tick the options above to generate a script.");

        sb.AppendLine("Write-Host \"Done — backup settings updated.\" -ForegroundColor Green");
        return sb.ToString();
    }

    // ── Azure CLI ────────────────────────────────────────────────────────────

    public static string GenerateCli(IReadOnlyList<SqlDatabaseInfo> databases, SqlServerInfo? server, BackupPlan plan, ISet<string> enabled)
    {
        if (databases.Count == 0) return "# No databases selected.";
        var first = databases[0];
        var isMi = first.Kind == SqlFlowKind.ManagedInstance;
        var sb = new StringBuilder();
        sb.AppendLine("# Backup improvement script (Azure CLI, bash) — generated by RateMyAzureSQL");
        sb.AppendLine($"# {first.Kind.HostLabel()}: {first.ServerName} · databases: {string.Join(", ", databases.Select(d => d.Name))}");
        sb.AppendLine("# Review every line before running: this script CHANGES backup settings (and may add cost).");
        sb.AppendLine();
        sb.AppendLine($"az account set --subscription \"{first.SubscriptionId}\"");
        sb.AppendLine($"rg=\"{first.ResourceGroup}\"");
        sb.AppendLine($"{(isMi ? "mi" : "server")}=\"{first.ServerName}\"");
        sb.AppendLine();

        var scope = isMi ? "-g \"$rg\" --mi \"$mi\"" : "-g \"$rg\" -s \"$server\"";
        var perDb = new StringBuilder();

        if (enabled.Contains("pitr") || (enabled.Contains("diff") && !isMi))
        {
            var basic = databases.Where(d => d.IsBasicTier).Select(d => d.Name).ToList();
            perDb.AppendLine("  # Point-in-time restore retention" + (basic.Count > 0 && plan.PitrDays > 7 ? $" (Basic tier max 7 days: {string.Join(", ", basic)})" : ""));
            if (isMi)
                perDb.AppendLine($"  az sql midb short-term-retention-policy set {scope} -n \"$db\" --retention-days {plan.PitrDays}");
            else
            {
                var args = new List<string>();
                if (enabled.Contains("pitr")) args.Add($"--retention-days {plan.PitrDays}");
                if (enabled.Contains("diff")) args.Add($"--diffbackup-hours {plan.DiffHours}");
                perDb.AppendLine($"  az sql db str-policy set {scope} -n \"$db\" {string.Join(" ", args)}");
            }
        }

        if (enabled.Contains("ltr"))
        {
            perDb.AppendLine("  # Long-term retention");
            var cmd = isMi ? "az sql midb ltr-policy set" : "az sql db ltr-policy set";
            perDb.AppendLine($"  {cmd} {scope} -n \"$db\" --weekly-retention {Iso(plan.Weekly)} --monthly-retention {Iso(plan.Monthly)} --yearly-retention {Iso(plan.Yearly)} --week-of-year {plan.WeekOfYear}");
        }

        if (enabled.Contains("redundancy") && !isMi)
        {
            perDb.AppendLine("  # Backup storage redundancy (Hyperscale needs a copy instead: az sql db copy --backup-storage-redundancy)");
            perDb.AppendLine($"  az sql db update {scope} -n \"$db\" --backup-storage-redundancy {plan.Redundancy}");
        }

        if (enabled.Contains("zone") && plan.ZoneRedundant && !isMi)
        {
            var eligible = databases.Where(d => d.SupportsZoneRedundancy && !d.ZoneRedundant && d.ElasticPoolId is null).Select(d => d.Name).ToList();
            var pools = databases.Where(d => d.SupportsZoneRedundancy && !d.ZoneRedundant && d.ElasticPoolId is not null).Select(d => d.ElasticPoolName).Distinct().ToList();
            if (eligible.Count > 0)
            {
                perDb.AppendLine("  # Zone redundancy (not available on Basic/Standard)");
                perDb.AppendLine($"  case \"$db\" in {string.Join("|", eligible)}) az sql db update {scope} -n \"$db\" --zone-redundant true ;; esac");
            }
            foreach (var pool in pools)
                perDb.AppendLine($"  # Pooled database: az sql elastic-pool update {scope} -n \"{pool}\" --zone-redundant true");
        }

        if (perDb.Length > 0)
        {
            sb.AppendLine($"for db in {string.Join(" ", databases.Select(d => $"\"{d.Name}\""))}; do");
            sb.AppendLine("  echo \"Updating $db…\"");
            sb.Append(perDb);
            sb.AppendLine("done");
            sb.AppendLine();
        }

        if (isMi && enabled.Contains("redundancy"))
            sb.AppendLine($"az sql mi update -g \"$rg\" -n \"$mi\" --backup-storage-redundancy {plan.Redundancy}");
        if (isMi && enabled.Contains("zone") && plan.ZoneRedundant && server is { ZoneRedundant: false })
            sb.AppendLine("az sql mi update -g \"$rg\" -n \"$mi\" --zone-redundant true");

        if (enabled.Contains("fog") && plan.FailoverGroup)
        {
            sb.AppendLine();
            sb.AppendLine("# Failover group (the partner must exist in the paired region)");
            if (isMi)
            {
                sb.AppendLine("partner_rg=\"<PARTNER-RESOURCE-GROUP>\"; partner_mi=\"<PARTNER-INSTANCE>\"");
                sb.AppendLine("az sql instance-failover-group create -g \"$rg\" --mi \"$mi\" -n \"fog-$mi\" --partner-resource-group \"$partner_rg\" --partner-mi \"$partner_mi\" --failover-policy Automatic --grace-period 1");
            }
            else
            {
                sb.AppendLine("partner_rg=\"<PARTNER-RESOURCE-GROUP>\"; partner_server=\"<PARTNER-SERVER>\"");
                sb.AppendLine($"az sql failover-group create -g \"$rg\" -s \"$server\" -n \"fog-$server\" --partner-resource-group \"$partner_rg\" --partner-server \"$partner_server\" --failover-policy Automatic --grace-period 1 --add-db {string.Join(" ", databases.Select(d => $"\"{d.Name}\""))}");
            }
        }

        if (enabled.Count == 0)
            sb.AppendLine("# No options selected — tick the options above to generate a script.");
        return sb.ToString();
    }

    private static string RetentionExpr(BackupPlan plan, bool anyBasic) =>
        anyBasic && plan.PitrDays > 7 ? $"$(if ($db -in $basicTier) {{ 7 }} else {{ {plan.PitrDays} }})" : plan.PitrDays.ToString();

    private static string Iso(string duration) => SqlDatabaseInfo.IsSet(duration) ? duration : "PT0S";
}
