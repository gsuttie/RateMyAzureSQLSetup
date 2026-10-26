namespace RateMyAzureSql.Models;

/// <summary>One server-level firewall rule (Azure SQL Database logical servers only).</summary>
public sealed class FirewallRuleInfo
{
    public string Name { get; set; } = string.Empty;
    public string StartIp { get; set; } = string.Empty;
    public string EndIp { get; set; } = string.Empty;

    /// <summary>The special 0.0.0.0–0.0.0.0 rule: "Allow Azure services and resources to access this server".</summary>
    public bool IsAllowAzureServices => StartIp == "0.0.0.0" && EndIp == "0.0.0.0";

    /// <summary>A rule spanning the whole IPv4 space.</summary>
    public bool IsOpenToInternet => StartIp == "0.0.0.0" && EndIp == "255.255.255.255";

    /// <summary>Number of addresses the rule admits (1 for a single IP).</summary>
    public long AddressCount
    {
        get
        {
            if (!TryToNumber(StartIp, out var s) || !TryToNumber(EndIp, out var e) || e < s) return 1;
            return e - s + 1;
        }
    }

    /// <summary>More than a /24 (256 addresses) and not the special Azure rule.</summary>
    public bool IsBroad => !IsAllowAzureServices && !IsOpenToInternet && AddressCount > 256;

    public string Display => StartIp == EndIp ? StartIp : $"{StartIp} – {EndIp}";

    private static bool TryToNumber(string ip, out long value)
    {
        value = 0;
        var parts = ip.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
        {
            if (!int.TryParse(p, out var n) || n is < 0 or > 255) return false;
            value = (value << 8) + n;
        }
        return true;
    }
}

/// <summary>A failover group (logical server) or instance failover group (managed instance).</summary>
public sealed class FailoverGroupInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string PartnerServer { get; set; } = string.Empty;
    public string PartnerLocation { get; set; } = string.Empty;

    /// <summary>"Automatic" or "Manual".</summary>
    public string FailoverPolicy { get; set; } = string.Empty;
    public int? GracePeriodMinutes { get; set; }

    /// <summary>"Primary" or "Secondary" from this server's point of view.</summary>
    public string ReplicationRole { get; set; } = string.Empty;

    /// <summary>Database resource IDs in the group (logical servers); empty for instance failover groups, which cover every database.</summary>
    public List<string> DatabaseIds { get; set; } = new();
}

/// <summary>Active geo-replication link of one database.</summary>
public sealed class GeoReplicaInfo
{
    public string PartnerServer { get; set; } = string.Empty;
    public string PartnerLocation { get; set; } = string.Empty;
    public string PartnerDatabase { get; set; } = string.Empty;

    /// <summary>This database's role in the link: "Primary" or "Secondary".</summary>
    public string Role { get; set; } = string.Empty;
    public string ReplicationState { get; set; } = string.Empty;
}

/// <summary>
/// The host of one or more databases: an Azure SQL Database logical server, or a SQL Managed Instance.
/// Security settings live here; they apply to every database on the host.
/// </summary>
public sealed class SqlServerInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Fqdn { get; set; } = string.Empty;
    public SqlFlowKind Kind { get; set; }

    // ── Network ──────────────────────────────────────────────────────────────

    /// <summary>Logical server: publicNetworkAccess. Managed instance: the public data endpoint. Null = unknown.</summary>
    public bool? PublicNetworkAccess { get; set; }

    /// <summary>"1.0", "1.1", "1.2", "1.3", or empty when nothing is enforced.</summary>
    public string MinimalTlsVersion { get; set; } = string.Empty;
    public int PrivateEndpointCount { get; set; }

    /// <summary>Logical servers only. Null when the rules could not be read.</summary>
    public List<FirewallRuleInfo>? FirewallRules { get; set; }

    public bool OpenToInternet => FirewallRules?.Any(r => r.IsOpenToInternet) == true;
    public bool AllowAzureServices => FirewallRules?.Any(r => r.IsAllowAzureServices) == true;
    public IEnumerable<FirewallRuleInfo> BroadRules => FirewallRules?.Where(r => r.IsBroad) ?? [];

    /// <summary>Managed instance: the subnet it is injected into.</summary>
    public string SubnetId { get; set; } = string.Empty;

    // ── Identity ─────────────────────────────────────────────────────────────

    public string SqlAdminLogin { get; set; } = string.Empty;
    public string EntraAdminLogin { get; set; } = string.Empty;
    public string EntraAdminType { get; set; } = string.Empty;
    public bool HasEntraAdmin => !string.IsNullOrEmpty(EntraAdminLogin);

    /// <summary>Microsoft Entra-only authentication (SQL logins disabled). Null = unknown.</summary>
    public bool? EntraOnlyAuthentication { get; set; }

    // ── Threat protection & auditing ─────────────────────────────────────────

    /// <summary>Microsoft Defender for SQL (server-level policy or subscription plan). Null = unknown.</summary>
    public bool? DefenderEnabled { get; set; }
    public bool? VulnerabilityAssessmentEnabled { get; set; }

    /// <summary>Server auditing. Always null for managed instances (configured in T-SQL, not readable via ARM).</summary>
    public bool? AuditingEnabled { get; set; }
    public List<string> AuditDestinations { get; set; } = new();
    public int? AuditRetentionDays { get; set; }

    // ── Encryption ───────────────────────────────────────────────────────────

    /// <summary>"ServiceManaged" or "AzureKeyVault" (customer-managed key).</summary>
    public string EncryptionProtector { get; set; } = string.Empty;
    public bool UsesCustomerManagedKey => EncryptionProtector.Equals("AzureKeyVault", StringComparison.OrdinalIgnoreCase);

    // ── Managed instance only ────────────────────────────────────────────────

    /// <summary>"GeneralPurpose" or "BusinessCritical".</summary>
    public string Tier { get; set; } = string.Empty;
    public int? VCores { get; set; }
    public bool ZoneRedundant { get; set; }

    /// <summary>Instance-level backup storage redundancy: "Geo", "GeoZone", "Zone" or "Local".</summary>
    public string BackupStorageRedundancy { get; set; } = string.Empty;

    // ── Resilience ───────────────────────────────────────────────────────────

    public List<FailoverGroupInfo> FailoverGroups { get; set; } = new();

    public string KindLabel => Kind == SqlFlowKind.SqlDatabase ? "Logical server" : "Managed instance";
}

/// <summary>One user database on a logical server or managed instance: the unit that gets a grade.</summary>
public sealed class SqlDatabaseInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string ServerId { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public string ResourceGroup { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public SqlFlowKind Kind { get; set; }

    /// <summary>"Basic", "Standard", "Premium", "GeneralPurpose", "BusinessCritical", "Hyperscale", "DataWarehouse".</summary>
    public string Tier { get; set; } = string.Empty;
    public string SkuName { get; set; } = string.Empty;
    public int? Capacity { get; set; }
    public string ServiceObjective { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public long? MaxSizeBytes { get; set; }
    public DateTime? CreationDate { get; set; }
    public string? ElasticPoolId { get; set; }
    public string ElasticPoolName => ElasticPoolId is null ? "" : ElasticPoolId[(ElasticPoolId.LastIndexOf('/') + 1)..];

    /// <summary>Serverless compute (from the resource kind).</summary>
    public bool IsServerless { get; set; }
    public bool IsDataWarehouse => Tier.Equals("DataWarehouse", StringComparison.OrdinalIgnoreCase);
    public bool IsBasicTier => Tier.Equals("Basic", StringComparison.OrdinalIgnoreCase);
    public bool IsHyperscale => Tier.Equals("Hyperscale", StringComparison.OrdinalIgnoreCase);

    /// <summary>Zone redundancy is a Premium / Business Critical / General Purpose / Hyperscale feature (and instance-level for managed instances).</summary>
    public bool SupportsZoneRedundancy => Kind == SqlFlowKind.ManagedInstance ||
        Tier.Equals("Premium", StringComparison.OrdinalIgnoreCase) ||
        Tier.Equals("BusinessCritical", StringComparison.OrdinalIgnoreCase) ||
        Tier.Equals("GeneralPurpose", StringComparison.OrdinalIgnoreCase) ||
        IsHyperscale;

    /// <summary>Basic tier databases can keep point-in-time backups for at most 7 days.</summary>
    public int MaxPitrDays => IsBasicTier ? 7 : 35;

    // ── Resilience ───────────────────────────────────────────────────────────

    public bool ZoneRedundant { get; set; }

    /// <summary>True when zone redundancy comes from the elastic pool rather than the database.</summary>
    public bool ZoneRedundancyFromPool { get; set; }

    /// <summary>"Geo", "GeoZone", "Zone" or "Local". Managed instance databases inherit the instance setting.</summary>
    public string BackupStorageRedundancy { get; set; } = string.Empty;

    public List<GeoReplicaInfo> GeoReplicas { get; set; } = new();
    public string? FailoverGroupName { get; set; }
    public bool HasFailoverGroup => !string.IsNullOrEmpty(FailoverGroupName);
    public bool HasGeoReplica => GeoReplicas.Count > 0 || HasFailoverGroup;

    /// <summary>True when this database is a read-only geo-secondary: backups are taken on the primary, so it is not rated.</summary>
    public bool IsGeoSecondary => GeoReplicas.Any(r => r.Role.Equals("Secondary", StringComparison.OrdinalIgnoreCase));

    // ── Backups ──────────────────────────────────────────────────────────────

    /// <summary>Point-in-time restore retention in days (1–35). Null when it could not be read.</summary>
    public int? PitrRetentionDays { get; set; }

    /// <summary>Differential backup interval (12 or 24 hours). Null when unknown / not applicable (Hyperscale, managed instance).</summary>
    public int? DiffBackupIntervalHours { get; set; }

    /// <summary>ISO 8601 durations ("P12W", "P12M", "P5Y"); "PT0S" or empty means not configured.</summary>
    public string WeeklyRetention { get; set; } = string.Empty;
    public string MonthlyRetention { get; set; } = string.Empty;
    public string YearlyRetention { get; set; } = string.Empty;
    public int? WeekOfYear { get; set; }

    /// <summary>False when the long-term retention policy could not be read.</summary>
    public bool LtrRead { get; set; }

    public bool HasWeeklyLtr => IsSet(WeeklyRetention);
    public bool HasMonthlyLtr => IsSet(MonthlyRetention);
    public bool HasYearlyLtr => IsSet(YearlyRetention);
    public bool HasLtr => HasWeeklyLtr || HasMonthlyLtr || HasYearlyLtr;

    public DateTime? EarliestRestoreDate { get; set; }

    // ── Encryption ───────────────────────────────────────────────────────────

    /// <summary>Transparent data encryption. Managed instance databases are always encrypted. Null = unknown.</summary>
    public bool? TdeEnabled { get; set; }
    public bool IsLedgerOn { get; set; }

    public static bool IsSet(string isoDuration) =>
        !string.IsNullOrWhiteSpace(isoDuration) && !isoDuration.Equals("PT0S", StringComparison.OrdinalIgnoreCase) && !isoDuration.Equals("P0D", StringComparison.OrdinalIgnoreCase);

    /// <summary>"P12W" → "12 weeks", "P1Y" → "1 year", "PT0S" → "none".</summary>
    public static string DurationLabel(string isoDuration)
    {
        if (!IsSet(isoDuration)) return "none";
        var s = isoDuration.Trim().ToUpperInvariant();
        if (s.Length < 3 || s[0] != 'P') return isoDuration;
        var unit = s[^1];
        if (!int.TryParse(s[1..^1], out var n)) return isoDuration;
        var word = unit switch { 'W' => "week", 'M' => "month", 'Y' => "year", 'D' => "day", _ => isoDuration };
        return $"{n} {word}{(n == 1 ? "" : "s")}";
    }

    /// <summary>Human-readable size, e.g. "32 GB".</summary>
    public string MaxSizeLabel => MaxSizeBytes switch
    {
        null => "",
        >= 1024L * 1024 * 1024 * 1024 => $"{MaxSizeBytes.Value / (1024.0 * 1024 * 1024 * 1024):0.#} TB",
        >= 1024L * 1024 * 1024 => $"{MaxSizeBytes.Value / (1024.0 * 1024 * 1024):0.#} GB",
        _ => $"{MaxSizeBytes.Value / (1024.0 * 1024):0.#} MB"
    };

    public string TierLabel => string.IsNullOrEmpty(Tier) ? "" : Tier switch
    {
        "GeneralPurpose" => "General Purpose",
        "BusinessCritical" => "Business Critical",
        "DataWarehouse" => "Data Warehouse",
        _ => Tier
    } + (ElasticPoolId is not null ? " (pool)" : IsServerless ? " (serverless)" : "");
}

/// <summary>One long-term retention backup that actually exists (listed on demand in the Backups step).</summary>
public sealed class LtrBackupInfo
{
    public string Name { get; set; } = string.Empty;
    public DateTime BackupTime { get; set; }
    public DateTime? ExpirationTime { get; set; }
    public string StorageRedundancy { get; set; } = string.Empty;
}

public sealed class SqlFinding
{
    /// <summary>"High", "Medium" or "Info".</summary>
    public string Severity { get; set; } = "Info";
    public string Category { get; set; } = string.Empty;

    /// <summary>"Security" or "Backups".</summary>
    public string Area { get; set; } = "Security";
    public string Message { get; set; } = string.Empty;
    public string ResourceName { get; set; } = string.Empty;
    public string ResourceId { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;

    /// <summary>Concrete guidance on how to fix the finding.</summary>
    public string Fix { get; set; } = string.Empty;
}

/// <summary>Complete result of a scan for one flow across one or more subscriptions.</summary>
public sealed class SqlScanResult
{
    public SqlFlowKind Flow { get; set; }
    public List<SqlServerInfo> Servers { get; set; } = new();
    public List<SqlDatabaseInfo> Databases { get; set; } = new();
    public List<SqlFinding> Findings { get; set; } = new();
    public List<SqlRating> Ratings { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> SubscriptionIds { get; set; } = new();
    public DateTime CompletedAt { get; set; } = DateTime.Now;

    public SqlServerInfo? Server(string serverId) =>
        Servers.FirstOrDefault(s => s.Id.Equals(serverId, StringComparison.OrdinalIgnoreCase));

    public SqlDatabaseInfo? Database(string databaseId) =>
        Databases.FirstOrDefault(d => d.Id.Equals(databaseId, StringComparison.OrdinalIgnoreCase));

    public IEnumerable<SqlDatabaseInfo> DatabasesOn(string serverId) =>
        Databases.Where(d => d.ServerId.Equals(serverId, StringComparison.OrdinalIgnoreCase));

    /// <summary>Databases that get a grade (user databases that are not geo-secondaries or data warehouses).</summary>
    public IEnumerable<SqlDatabaseInfo> RatableDatabases => Databases.Where(d => !d.IsGeoSecondary && !d.IsDataWarehouse);

    public void Merge(SqlScanResult other)
    {
        Servers.AddRange(other.Servers);
        Databases.AddRange(other.Databases);
        Findings.AddRange(other.Findings);
        Ratings.AddRange(other.Ratings);
        Warnings.AddRange(other.Warnings);
        SubscriptionIds.AddRange(other.SubscriptionIds);
    }
}
