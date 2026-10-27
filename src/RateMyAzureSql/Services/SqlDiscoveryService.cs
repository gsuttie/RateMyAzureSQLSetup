using System.Collections.Concurrent;
using System.Text.Json;
using RateMyAzureSql.Models;
using RateMyAzureSql.Services.Azure;
using static RateMyAzureSql.Services.Azure.Json;

namespace RateMyAzureSql.Services;

/// <summary>
/// Discovers the SQL estate of one flow (logical servers + databases, or managed instances + databases)
/// via Azure Resource Graph, then reads the per-server and per-database settings that matter for security
/// and backups through ARM GETs, produces findings and rates every database A-F.
/// Strictly read-only: nothing here ever modifies an Azure resource.
/// </summary>
public sealed class SqlDiscoveryService
{
    internal const string TypeServer = "microsoft.sql/servers";
    internal const string TypeDatabase = "microsoft.sql/servers/databases";
    internal const string TypePool = "microsoft.sql/servers/elasticpools";
    internal const string TypeManagedInstance = "microsoft.sql/managedinstances";
    internal const string TypeManagedDatabase = "microsoft.sql/managedinstances/databases";

    internal const string Api = "2021-11-01";
    private const string ExpressVaApi = "2022-02-01-preview";
    /// <summary>
    /// Concurrent ARM reads per scan. ARM allows ~12,000 reads/hour per subscription, but a short burst from a
    /// per-database fan-out can still trip "SubscriptionRequestsThrottled" (HTTP 429); AzureApi retries those
    /// with backoff, so this only needs to be low enough that the retries converge.
    /// </summary>
    private const int Parallelism = 4;

    /// <summary>
    /// Resource groups and resources whose name contains this word are restore targets / scratch copies,
    /// not production estate, and are excluded from discovery and rating entirely.
    /// </summary>
    internal const string ExcludedNameFragment = "restore";

    /// <summary>KQL fragment that drops anything whose resource group or resource id path contains the excluded word.</summary>
    private static readonly string ExclusionFilter =
        $"| where resourceGroup !contains '{ExcludedNameFragment}' and id !contains '{ExcludedNameFragment}' ";

    private static readonly string SummaryQuery =
        $"Resources | where type in~ ('{TypeServer}','{TypeDatabase}','{TypeManagedInstance}','{TypeManagedDatabase}') " +
        $"| where not(type =~ '{TypeDatabase}' and kind contains 'system') " +
        ExclusionFilter +
        "| summarize cnt = count() by subscriptionId, type";

    private const string Projection = "| project id, name, type, location, resourceGroup, subscriptionId, kind, sku, properties";

    private static string HostQuery(SqlFlowKind flow) =>
        $"Resources | where type =~ '{(flow == SqlFlowKind.SqlDatabase ? TypeServer : TypeManagedInstance)}' {ExclusionFilter}{Projection}";

    private static string DatabaseQuery(SqlFlowKind flow) => flow == SqlFlowKind.SqlDatabase
        ? $"Resources | where type =~ '{TypeDatabase}' | where kind !contains 'system' {ExclusionFilter}{Projection}"
        : $"Resources | where type =~ '{TypeManagedDatabase}' {ExclusionFilter}{Projection}";

    private static readonly string PoolQuery =
        $"Resources | where type =~ '{TypePool}' {ExclusionFilter}| project id, name, subscriptionId, sku, properties";

    /// <summary>
    /// Code-side guard matching <see cref="ExclusionFilter"/>: true when the resource group or any segment of the
    /// resource id (server, instance, database name) contains the excluded word, case-insensitively.
    /// </summary>
    internal static bool IsExcluded(string? resourceGroup, string? resourceId) =>
        (resourceGroup?.Contains(ExcludedNameFragment, StringComparison.OrdinalIgnoreCase) ?? false)
        || (resourceId?.Contains(ExcludedNameFragment, StringComparison.OrdinalIgnoreCase) ?? false);

    private readonly IAzureApi _azure;
    private readonly ILogger<SqlDiscoveryService> _logger;

    public SqlDiscoveryService(IAzureApi azure, ILogger<SqlDiscoveryService> logger)
    {
        _azure = azure;
        _logger = logger;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// <summary>Counts of SQL resources per subscription, so the scope step can highlight the relevant ones.</summary>
    public async Task<Dictionary<string, SqlSubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
    {
        var result = subscriptionIds.ToDictionary(
            id => id, id => new SqlSubscriptionSummary { SubscriptionId = id }, StringComparer.OrdinalIgnoreCase);
        if (subscriptionIds.Count == 0) return result;

        var rows = await _azure.QueryResourceGraphAsync(SummaryQuery, subscriptionIds, tenantId, ct);
        foreach (var row in rows)
        {
            if (!result.TryGetValue(Str(row, "subscriptionId"), out var summary)) continue;
            var cnt = row.TryGetProperty("cnt", out var c) && c.TryGetInt32(out var n) ? n : 0;
            switch (Str(row, "type").ToLowerInvariant())
            {
                case TypeServer: summary.ServerCount += cnt; break;
                case TypeDatabase: summary.DatabaseCount += cnt; break;
                case TypeManagedInstance: summary.ManagedInstanceCount += cnt; break;
                case TypeManagedDatabase: summary.ManagedDatabaseCount += cnt; break;
            }
        }
        return result;
    }

    /// <summary>Full read-only scan of one flow across the supplied subscriptions (which must share a tenant).</summary>
    public async Task<SqlScanResult> ScanAsync(
        SqlFlowKind flow, IReadOnlyCollection<string> subscriptionIds, string? tenantId,
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var result = new SqlScanResult { Flow = flow, SubscriptionIds = subscriptionIds.ToList() };
        if (subscriptionIds.Count == 0) return result;

        progress?.Report("Querying Azure Resource Graph…");
        var hostTask = _azure.QueryResourceGraphAsync(HostQuery(flow), subscriptionIds, tenantId, ct);
        var dbTask = _azure.QueryResourceGraphAsync(DatabaseQuery(flow), subscriptionIds, tenantId, ct);
        var poolTask = flow == SqlFlowKind.SqlDatabase
            ? _azure.QueryResourceGraphAsync(PoolQuery, subscriptionIds, tenantId, ct)
            : Task.FromResult(new List<JsonElement>());
        await Task.WhenAll(hostTask, dbTask, poolTask);

        foreach (var row in hostTask.Result)
        {
            var server = flow == SqlFlowKind.SqlDatabase ? ParseServer(row) : ParseManagedInstance(row);
            if (IsExcluded(server.ResourceGroup, server.Id)) continue;
            result.Servers.Add(server);
        }

        var pools = poolTask.Result.Select(ParsePool).ToDictionary(p => p.Id, p => p.ZoneRedundant, StringComparer.OrdinalIgnoreCase);
        foreach (var row in dbTask.Result)
        {
            var db = flow == SqlFlowKind.SqlDatabase ? ParseDatabase(row) : ParseManagedDatabase(row);
            if (IsExcluded(db.ResourceGroup, db.Id)) continue;
            if (db.ElasticPoolId is not null && pools.TryGetValue(db.ElasticPoolId, out var poolZr) && poolZr)
            {
                db.ZoneRedundant = true;
                db.ZoneRedundancyFromPool = true;
            }
            result.Databases.Add(db);
        }

        var failures = new ConcurrentDictionary<string, int>();
        var defenderPlans = await ReadDefenderPlansAsync(subscriptionIds, tenantId, failures, ct);

        progress?.Report($"Reading {flow.HostPluralLabel()} ({result.Servers.Count}): firewall, identity, Defender, auditing…");
        await ForEachAsync(result.Servers, (s, token) => flow == SqlFlowKind.SqlDatabase
            ? EnrichServerAsync(s, tenantId, defenderPlans, failures, token)
            : EnrichManagedInstanceAsync(s, tenantId, defenderPlans, failures, token), ct);

        if (flow == SqlFlowKind.ManagedInstance)
            await ApplyInstanceFailoverGroupsAsync(result, tenantId, failures, ct);

        progress?.Report($"Reading databases ({result.Databases.Count}): retention, long-term backups, encryption, replicas…");
        await ForEachAsync(result.Databases, (db, token) => flow == SqlFlowKind.SqlDatabase
            ? EnrichDatabaseAsync(db, tenantId, failures, token)
            : EnrichManagedDatabaseAsync(db, result.Server(db.ServerId), tenantId, failures, token), ct);

        if (flow == SqlFlowKind.SqlDatabase)
            LinkFailoverGroups(result);

        foreach (var (what, count) in failures.OrderBy(f => f.Key))
            result.Warnings.Add($"{what} could not be read for {count} resource(s) — shown as unknown.");

        progress?.Report("Rating…");
        Finalize(result);
        return result;
    }

    /// <summary>Findings + ratings. Split out so demo data and tests can reuse it on an already-populated result.</summary>
    public static void Finalize(SqlScanResult result)
    {
        result.Findings = SqlFindingsBuilder.Build(result);
        SqlRatingService.RateAll(result);
        result.CompletedAt = DateTime.Now;
    }

    /// <summary>The long-term retention backups that actually exist for a database (listed on demand).</summary>
    public async Task<List<LtrBackupInfo>> GetLtrBackupsAsync(SqlDatabaseInfo db, string? tenantId, CancellationToken ct = default)
    {
        var location = db.Location.Replace(" ", "").ToLowerInvariant();
        var url = db.Kind == SqlFlowKind.SqlDatabase
            ? $"{AzureApi.ArmBase}/subscriptions/{db.SubscriptionId}/resourceGroups/{db.ResourceGroup}/providers/Microsoft.Sql/locations/{location}/longTermRetentionServers/{db.ServerName}/longTermRetentionDatabases/{db.Name}/longTermRetentionBackups?api-version={Api}"
            : $"{AzureApi.ArmBase}/subscriptions/{db.SubscriptionId}/resourceGroups/{db.ResourceGroup}/providers/Microsoft.Sql/locations/{location}/longTermRetentionManagedInstances/{db.ServerName}/longTermRetentionDatabases/{db.Name}/longTermRetentionManagedInstanceBackups?api-version={Api}";
        var items = await _azure.GetArmListAsync(url, tenantId, ct);
        return items.Select(ParseLtrBackup).OrderByDescending(b => b.BackupTime).ToList();
    }

    internal static LtrBackupInfo ParseLtrBackup(JsonElement item)
    {
        var p = Obj(item, "properties");
        return new LtrBackupInfo
        {
            Name = Str(item, "name"),
            BackupTime = Date(p, "backupTime") ?? DateTime.MinValue,
            ExpirationTime = Date(p, "backupExpirationTime"),
            StorageRedundancy = Str(p, "backupStorageRedundancy")
        };
    }

    // ── Parsing (Resource Graph rows) ────────────────────────────────────────

    internal static SqlServerInfo ParseServer(JsonElement row)
    {
        var props = Obj(row, "properties");
        var info = new SqlServerInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Location = Str(row, "location"),
            Kind = SqlFlowKind.SqlDatabase,
            Fqdn = Str(props, "fullyQualifiedDomainName"),
            SqlAdminLogin = Str(props, "administratorLogin"),
            MinimalTlsVersion = Str(props, "minimalTlsVersion"),
            PublicNetworkAccess = ParsePublicAccess(Str(props, "publicNetworkAccess")),
            PrivateEndpointCount = Arr(props, "privateEndpointConnections")
                .Count(pe => !Str(Obj(Obj(pe, "properties"), "privateLinkServiceConnectionState"), "status").Equals("Rejected", StringComparison.OrdinalIgnoreCase))
        };
        ApplyAdministrators(info, Obj(props, "administrators"));
        return info;
    }

    internal static SqlServerInfo ParseManagedInstance(JsonElement row)
    {
        var props = Obj(row, "properties");
        var info = new SqlServerInfo
        {
            Id = Str(row, "id"),
            Name = Str(row, "name"),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Location = Str(row, "location"),
            Kind = SqlFlowKind.ManagedInstance,
            Fqdn = Str(props, "fullyQualifiedDomainName"),
            SqlAdminLogin = Str(props, "administratorLogin"),
            MinimalTlsVersion = Str(props, "minimalTlsVersion"),
            PublicNetworkAccess = Bool(props, "publicDataEndpointEnabled") ?? false,
            SubnetId = Str(props, "subnetId"),
            Tier = FirstNonEmpty(Str(Obj(row, "sku"), "tier"), Str(Obj(props, "sku"), "tier")),
            VCores = Int(props, "vCores"),
            ZoneRedundant = Bool(props, "zoneRedundant") == true,
            BackupStorageRedundancy = NormaliseRedundancy(FirstNonEmpty(
                Str(props, "currentBackupStorageRedundancy"), Str(props, "requestedBackupStorageRedundancy"), Str(props, "storageAccountType")))
        };
        ApplyAdministrators(info, Obj(props, "administrators"));
        return info;
    }

    internal static SqlDatabaseInfo ParseDatabase(JsonElement row)
    {
        var props = Obj(row, "properties");
        var sku = Obj(row, "sku");
        var id = Str(row, "id");
        var kind = Str(row, "kind");
        var db = new SqlDatabaseInfo
        {
            Id = id,
            Name = Str(row, "name"),
            ServerId = ParentId(id),
            ServerName = LastSegment(ParentId(id)),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Location = Str(row, "location"),
            Kind = SqlFlowKind.SqlDatabase,
            Tier = FirstNonEmpty(Str(sku, "tier"), Str(Obj(props, "currentSku"), "tier")),
            SkuName = FirstNonEmpty(Str(sku, "name"), Str(Obj(props, "currentSku"), "name")),
            Capacity = Int(sku, "capacity"),
            ServiceObjective = Str(props, "currentServiceObjectiveName"),
            Status = Str(props, "status"),
            MaxSizeBytes = Long(props, "maxSizeBytes"),
            CreationDate = Date(props, "creationDate"),
            ElasticPoolId = NullIfEmpty(Str(props, "elasticPoolId")),
            IsServerless = kind.Contains("serverless", StringComparison.OrdinalIgnoreCase),
            ZoneRedundant = Bool(props, "zoneRedundant") == true,
            BackupStorageRedundancy = NormaliseRedundancy(FirstNonEmpty(
                Str(props, "currentBackupStorageRedundancy"), Str(props, "requestedBackupStorageRedundancy"))),
            EarliestRestoreDate = Date(props, "earliestRestoreDate"),
            IsLedgerOn = Bool(props, "isLedgerOn") == true
        };
        return db;
    }

    internal static SqlDatabaseInfo ParseManagedDatabase(JsonElement row)
    {
        var props = Obj(row, "properties");
        var id = Str(row, "id");
        return new SqlDatabaseInfo
        {
            Id = id,
            Name = Str(row, "name"),
            ServerId = ParentId(id),
            ServerName = LastSegment(ParentId(id)),
            ResourceGroup = Str(row, "resourceGroup"),
            SubscriptionId = Str(row, "subscriptionId"),
            Location = Str(row, "location"),
            Kind = SqlFlowKind.ManagedInstance,
            Status = Str(props, "status"),
            CreationDate = Date(props, "creationDate"),
            EarliestRestoreDate = Date(props, "earliestRestorePoint"),
            TdeEnabled = true
        };
    }

    internal static (string Id, bool ZoneRedundant) ParsePool(JsonElement row) =>
        (Str(row, "id"), Bool(Obj(row, "properties"), "zoneRedundant") == true);

    internal static void ApplyAdministrators(SqlServerInfo info, JsonElement admins)
    {
        if (admins.ValueKind != JsonValueKind.Object) return;
        info.EntraAdminLogin = Str(admins, "login");
        info.EntraAdminType = Str(admins, "principalType");
        var only = Bool(admins, "azureADOnlyAuthentication");
        if (only is not null) info.EntraOnlyAuthentication = only;
    }

    internal static bool? ParsePublicAccess(string value) => value.ToLowerInvariant() switch
    {
        "disabled" => false,
        "enabled" => true,
        "" => true, // the default when the property is absent
        _ => null
    };

    internal static string NormaliseRedundancy(string value) => value.ToLowerInvariant() switch
    {
        "grs" or "geo" => "Geo",
        "gzrs" or "geozone" => "GeoZone",
        "zrs" or "zone" => "Zone",
        "lrs" or "local" => "Local",
        _ => value
    };

    private static string ParentId(string id)
    {
        var idx = id.LastIndexOf('/');
        if (idx <= 0) return id;
        var withoutName = id[..idx];
        idx = withoutName.LastIndexOf('/');
        return idx <= 0 ? withoutName : withoutName[..idx];
    }

    // ── Enrichment: logical servers ──────────────────────────────────────────

    private async Task EnrichServerAsync(SqlServerInfo s, string? tenantId, IReadOnlyDictionary<string, bool> defenderPlans,
        ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        var b = $"{AzureApi.ArmBase}{s.Id}";

        var rules = await TryAsync("Firewall rules", s.Id, failures,
            () => _azure.GetArmListAsync($"{b}/firewallRules?api-version={Api}", tenantId, ct));
        if (rules is not null) s.FirewallRules = rules.Select(ParseFirewallRule).ToList();

        var alert = await TryAsync("Defender for SQL", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/securityAlertPolicies/Default?api-version={Api}", tenantId, ct));
        s.DefenderEnabled = ParseDefender(alert, defenderPlans.TryGetValue(s.SubscriptionId, out var plan) ? plan : null);

        s.VulnerabilityAssessmentEnabled = await ReadVulnerabilityAssessmentAsync(b, s.Id, tenantId, failures, ct);

        var audit = await TryAsync("Auditing", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/auditingSettings/default?api-version={Api}", tenantId, ct));
        if (audit is { } a)
        {
            var p = Obj(a, "properties");
            s.AuditingEnabled = Str(p, "state").Equals("Enabled", StringComparison.OrdinalIgnoreCase);
            s.AuditRetentionDays = Int(p, "retentionDays");
            if (s.AuditingEnabled == true)
            {
                var storage = Str(p, "storageEndpoint");
                if (!string.IsNullOrEmpty(storage))
                    s.AuditDestinations.Add($"Storage: {(Uri.TryCreate(storage, UriKind.Absolute, out var u) ? u.Host.Split('.')[0] : storage)}");
                if (Bool(p, "isAzureMonitorTargetEnabled") == true)
                {
                    var diag = await TryAsync("Audit destinations", s.Id, failures,
                        () => _azure.GetArmListAsync($"{b}/databases/master/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", tenantId, ct));
                    var monitorDests = diag is null ? [] : ParseAuditDiagnostics(diag);
                    s.AuditDestinations.AddRange(monitorDests.Count > 0 ? monitorDests : ["Azure Monitor (no destination found on master)"]);
                }
            }
        }

        if (!s.HasEntraAdmin)
        {
            var admin = await TryAsync("Microsoft Entra admin", s.Id, failures,
                () => _azure.GetArmAsync($"{b}/administrators/ActiveDirectory?api-version={Api}", tenantId, ct));
            if (admin is { } ad)
            {
                var p = Obj(ad, "properties");
                s.EntraAdminLogin = Str(p, "login");
                s.EntraAdminType = Str(p, "administratorType") == "ActiveDirectory" ? Str(p, "principalType") : Str(p, "administratorType");
                if (Bool(p, "azureADOnlyAuthentication") is { } only) s.EntraOnlyAuthentication = only;
            }
        }
        if (s.HasEntraAdmin && s.EntraOnlyAuthentication is null)
        {
            var only = await TryAsync("Entra-only authentication", s.Id, failures,
                () => _azure.GetArmAsync($"{b}/azureADOnlyAuthentications/Default?api-version={Api}", tenantId, ct));
            s.EntraOnlyAuthentication = only is { } o ? Bool(Obj(o, "properties"), "azureADOnlyAuthentication") ?? false : false;
        }

        var protector = await TryAsync("Encryption protector", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/encryptionProtector/current?api-version={Api}", tenantId, ct));
        if (protector is { } ep) s.EncryptionProtector = Str(Obj(ep, "properties"), "serverKeyType");

        var groups = await TryAsync("Failover groups", s.Id, failures,
            () => _azure.GetArmListAsync($"{b}/failoverGroups?api-version={Api}", tenantId, ct));
        if (groups is not null) s.FailoverGroups = groups.Select(ParseFailoverGroup).ToList();
    }

    private async Task EnrichDatabaseAsync(SqlDatabaseInfo db, string? tenantId, ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        if (db.IsDataWarehouse) return;
        var b = $"{AzureApi.ArmBase}{db.Id}";

        var str = await TryAsync("Point-in-time retention", db.Id, failures,
            () => _azure.GetArmAsync($"{b}/backupShortTermRetentionPolicies/default?api-version={Api}", tenantId, ct));
        if (str is { } s)
        {
            var p = Obj(s, "properties");
            db.PitrRetentionDays = Int(p, "retentionDays");
            db.DiffBackupIntervalHours = db.IsHyperscale ? null : Int(p, "diffBackupIntervalInHours");
        }

        var ltr = await TryAsync("Long-term retention", db.Id, failures,
            () => _azure.GetArmAsync($"{b}/backupLongTermRetentionPolicies/default?api-version={Api}", tenantId, ct));
        if (ltr is { } l) ApplyLtr(db, Obj(l, "properties"));

        var tde = await TryAsync("Transparent data encryption", db.Id, failures,
            () => _azure.GetArmAsync($"{b}/transparentDataEncryption/current?api-version={Api}", tenantId, ct));
        if (tde is { } t) db.TdeEnabled = Str(Obj(t, "properties"), "state").Equals("Enabled", StringComparison.OrdinalIgnoreCase);

        var links = await TryAsync("Geo-replication links", db.Id, failures,
            () => _azure.GetArmListAsync($"{b}/replicationLinks?api-version={Api}", tenantId, ct));
        if (links is not null) db.GeoReplicas = links.Select(ParseReplicationLink).ToList();
    }

    // ── Enrichment: managed instances ────────────────────────────────────────

    private async Task EnrichManagedInstanceAsync(SqlServerInfo s, string? tenantId, IReadOnlyDictionary<string, bool> defenderPlans,
        ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        var b = $"{AzureApi.ArmBase}{s.Id}";

        var alert = await TryAsync("Defender for SQL", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/securityAlertPolicies/Default?api-version={Api}", tenantId, ct));
        s.DefenderEnabled = ParseDefender(alert, defenderPlans.TryGetValue(s.SubscriptionId, out var plan) ? plan : null);

        var va = await TryAsync("Vulnerability assessment", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/vulnerabilityAssessments/Default?api-version={Api}", tenantId, ct));
        s.VulnerabilityAssessmentEnabled = va is { } v ? Bool(Obj(Obj(v, "properties"), "recurringScans"), "isEnabled") ?? false : false;

        if (!s.HasEntraAdmin)
        {
            var admin = await TryAsync("Microsoft Entra admin", s.Id, failures,
                () => _azure.GetArmAsync($"{b}/administrators/ActiveDirectory?api-version={Api}", tenantId, ct));
            if (admin is { } ad)
            {
                var p = Obj(ad, "properties");
                s.EntraAdminLogin = Str(p, "login");
                s.EntraAdminType = Str(p, "administratorType") == "ActiveDirectory" ? Str(p, "principalType") : Str(p, "administratorType");
            }
        }
        if (s.HasEntraAdmin && s.EntraOnlyAuthentication is null)
        {
            var only = await TryAsync("Entra-only authentication", s.Id, failures,
                () => _azure.GetArmAsync($"{b}/azureADOnlyAuthentications/Default?api-version={Api}", tenantId, ct));
            s.EntraOnlyAuthentication = only is { } o ? Bool(Obj(o, "properties"), "azureADOnlyAuthentication") ?? false : false;
        }

        var protector = await TryAsync("Encryption protector", s.Id, failures,
            () => _azure.GetArmAsync($"{b}/encryptionProtector/current?api-version={Api}", tenantId, ct));
        if (protector is { } ep) s.EncryptionProtector = Str(Obj(ep, "properties"), "serverKeyType");
    }

    private async Task EnrichManagedDatabaseAsync(SqlDatabaseInfo db, SqlServerInfo? mi, string? tenantId,
        ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        if (mi is not null)
        {
            db.Tier = mi.Tier;
            db.ZoneRedundant = mi.ZoneRedundant;
            db.BackupStorageRedundancy = mi.BackupStorageRedundancy;
            if (mi.FailoverGroups.Count > 0)
            {
                var fog = mi.FailoverGroups[0];
                db.FailoverGroupName = fog.Name;
                if (fog.ReplicationRole.Equals("Secondary", StringComparison.OrdinalIgnoreCase))
                    db.GeoReplicas.Add(new GeoReplicaInfo { PartnerServer = fog.PartnerServer, PartnerLocation = fog.PartnerLocation, Role = "Secondary", ReplicationState = "CATCH_UP" });
            }
        }
        var b = $"{AzureApi.ArmBase}{db.Id}";

        var str = await TryAsync("Point-in-time retention", db.Id, failures,
            () => _azure.GetArmAsync($"{b}/backupShortTermRetentionPolicies/default?api-version={Api}", tenantId, ct));
        if (str is { } s) db.PitrRetentionDays = Int(Obj(s, "properties"), "retentionDays");

        var ltr = await TryAsync("Long-term retention", db.Id, failures,
            () => _azure.GetArmAsync($"{b}/backupLongTermRetentionPolicies/default?api-version={Api}", tenantId, ct));
        if (ltr is { } l) ApplyLtr(db, Obj(l, "properties"));
    }

    private async Task ApplyInstanceFailoverGroupsAsync(SqlScanResult result, string? tenantId, ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        var scopes = result.Servers
            .Select(s => (s.SubscriptionId, s.ResourceGroup, Location: s.Location.Replace(" ", "").ToLowerInvariant()))
            .Distinct()
            .ToList();
        var groups = new List<JsonElement>();
        await ForEachAsync(scopes, async (scope, token) =>
        {
            var url = $"{AzureApi.ArmBase}/subscriptions/{scope.SubscriptionId}/resourceGroups/{scope.ResourceGroup}/providers/Microsoft.Sql/locations/{scope.Location}/instanceFailoverGroups?api-version={Api}";
            var items = await TryAsync("Instance failover groups", $"{scope.SubscriptionId}/{scope.ResourceGroup}/{scope.Location}", failures,
                () => _azure.GetArmListAsync(url, tenantId, token));
            if (items is not null) lock (groups) groups.AddRange(items);
        }, ct);

        foreach (var g in groups)
        {
            var p = Obj(g, "properties");
            var policy = Str(Obj(p, "readWriteEndpoint"), "failoverPolicy");
            var grace = Int(Obj(p, "readWriteEndpoint"), "failoverWithDataLossGracePeriodMinutes");
            foreach (var pair in Arr(p, "managedInstancePairs"))
            {
                var primary = Str(pair, "primaryManagedInstanceId");
                var partner = Str(pair, "partnerManagedInstanceId");
                foreach (var mi in result.Servers)
                {
                    var isPrimary = mi.Id.Equals(primary, StringComparison.OrdinalIgnoreCase);
                    var isPartner = mi.Id.Equals(partner, StringComparison.OrdinalIgnoreCase);
                    if (!isPrimary && !isPartner) continue;
                    var other = isPrimary ? partner : primary;
                    mi.FailoverGroups.Add(new FailoverGroupInfo
                    {
                        Id = Str(g, "id"),
                        Name = Str(g, "name"),
                        PartnerServer = LastSegment(other),
                        PartnerLocation = Arr(p, "partnerRegions").Select(r => Str(r, "location")).FirstOrDefault(l => !l.Equals(mi.Location, StringComparison.OrdinalIgnoreCase)) ?? "",
                        FailoverPolicy = policy,
                        GracePeriodMinutes = grace,
                        ReplicationRole = isPrimary ? "Primary" : "Secondary"
                    });
                }
            }
        }
    }

    // ── Shared enrichment helpers ────────────────────────────────────────────

    private async Task<bool?> ReadVulnerabilityAssessmentAsync(string b, string id, string? tenantId, ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        try
        {
            var express = await _azure.GetArmAsync($"{b}/sqlVulnerabilityAssessments/Default?api-version={ExpressVaApi}", tenantId, ct);
            if (express is { } e && Str(Obj(e, "properties"), "state").Equals("Enabled", StringComparison.OrdinalIgnoreCase)) return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Express vulnerability assessment not readable for {Id}.", id);
        }
        var classic = await TryAsync("Vulnerability assessment", id, failures,
            () => _azure.GetArmAsync($"{b}/vulnerabilityAssessments/Default?api-version={Api}", tenantId, ct));
        if (classic is null) return failures.ContainsKey("Vulnerability assessment") ? null : false;
        return Bool(Obj(Obj(classic.Value, "properties"), "recurringScans"), "isEnabled") ?? false;
    }

    private async Task<Dictionary<string, bool>> ReadDefenderPlansAsync(IReadOnlyCollection<string> subscriptionIds, string? tenantId,
        ConcurrentDictionary<string, int> failures, CancellationToken ct)
    {
        var plans = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        await ForEachAsync(subscriptionIds.ToList(), async (sub, token) =>
        {
            var pricing = await TryAsync("Defender for SQL plan", sub, failures,
                () => _azure.GetArmAsync($"{AzureApi.ArmBase}/subscriptions/{sub}/providers/Microsoft.Security/pricings/SqlServers?api-version=2023-01-01", tenantId, token));
            if (pricing is { } p)
                plans[sub] = Str(Obj(p, "properties"), "pricingTier").Equals("Standard", StringComparison.OrdinalIgnoreCase);
        }, ct);
        return new Dictionary<string, bool>(plans, StringComparer.OrdinalIgnoreCase);
    }

    internal static bool? ParseDefender(JsonElement? serverPolicy, bool? subscriptionPlan)
    {
        if (serverPolicy is { } sp)
        {
            var enabled = Str(Obj(sp, "properties"), "state").Equals("Enabled", StringComparison.OrdinalIgnoreCase);
            return enabled || subscriptionPlan == true;
        }
        return subscriptionPlan;
    }

    internal static FirewallRuleInfo ParseFirewallRule(JsonElement rule)
    {
        var p = Obj(rule, "properties");
        return new FirewallRuleInfo { Name = Str(rule, "name"), StartIp = Str(p, "startIpAddress"), EndIp = Str(p, "endIpAddress") };
    }

    internal static FailoverGroupInfo ParseFailoverGroup(JsonElement g)
    {
        var p = Obj(g, "properties");
        var partner = Arr(p, "partnerServers").FirstOrDefault();
        return new FailoverGroupInfo
        {
            Id = Str(g, "id"),
            Name = Str(g, "name"),
            PartnerServer = LastSegment(Str(partner, "id")),
            PartnerLocation = Str(partner, "location"),
            FailoverPolicy = Str(Obj(p, "readWriteEndpoint"), "failoverPolicy"),
            GracePeriodMinutes = Int(Obj(p, "readWriteEndpoint"), "failoverWithDataLossGracePeriodMinutes"),
            ReplicationRole = Str(p, "replicationRole"),
            DatabaseIds = Arr(p, "databases").Select(d => d.ValueKind == JsonValueKind.String ? d.GetString() ?? "" : "").Where(d => d.Length > 0).ToList()
        };
    }

    internal static GeoReplicaInfo ParseReplicationLink(JsonElement link)
    {
        var p = Obj(link, "properties");
        return new GeoReplicaInfo
        {
            PartnerServer = Str(p, "partnerServer"),
            PartnerLocation = Str(p, "partnerLocation"),
            PartnerDatabase = Str(p, "partnerDatabase"),
            Role = Str(p, "role"),
            ReplicationState = Str(p, "replicationState")
        };
    }

    internal static void ApplyLtr(SqlDatabaseInfo db, JsonElement p)
    {
        if (p.ValueKind != JsonValueKind.Object) return;
        db.LtrRead = true;
        db.WeeklyRetention = Str(p, "weeklyRetention");
        db.MonthlyRetention = Str(p, "monthlyRetention");
        db.YearlyRetention = Str(p, "yearlyRetention");
        db.WeekOfYear = Int(p, "weekOfYear");
    }

    /// <summary>Destinations of the SQLSecurityAuditEvents category from the master database's diagnostic settings.</summary>
    internal static List<string> ParseAuditDiagnostics(IEnumerable<JsonElement> settings)
    {
        var dests = new List<string>();
        foreach (var setting in settings)
        {
            var props = Obj(setting, "properties");
            if (props.ValueKind != JsonValueKind.Object) continue;
            var auditOn = Arr(props, "logs").Any(l => Bool(l, "enabled") == true &&
                (Str(l, "category").Equals("SQLSecurityAuditEvents", StringComparison.OrdinalIgnoreCase) ||
                 Str(l, "categoryGroup").Equals("audit", StringComparison.OrdinalIgnoreCase) ||
                 Str(l, "categoryGroup").Equals("allLogs", StringComparison.OrdinalIgnoreCase)));
            if (!auditOn) continue;
            var ws = Str(props, "workspaceId");
            if (!string.IsNullOrEmpty(ws)) dests.Add($"Log Analytics: {LastSegment(ws)}");
            var eh = Str(props, "eventHubAuthorizationRuleId");
            if (!string.IsNullOrEmpty(eh)) dests.Add($"Event Hub: {FirstNonEmpty(Str(props, "eventHubName"), "default")}");
            var sa = Str(props, "storageAccountId");
            if (!string.IsNullOrEmpty(sa)) dests.Add($"Storage: {LastSegment(sa)}");
        }
        return dests.Distinct().ToList();
    }

    /// <summary>Attach each database to the failover group that lists it.</summary>
    internal static void LinkFailoverGroups(SqlScanResult result)
    {
        foreach (var server in result.Servers)
            foreach (var fog in server.FailoverGroups)
                foreach (var dbId in fog.DatabaseIds)
                {
                    var db = result.Database(dbId);
                    if (db is not null) db.FailoverGroupName = fog.Name;
                }
    }

    private async Task<T?> TryAsync<T>(string what, string id, ConcurrentDictionary<string, int> failures, Func<Task<T>> read)
    {
        try
        {
            return await read();
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "{What} could not be read for {Id}.", what, id);
            failures.AddOrUpdate(what, 1, (_, n) => n + 1);
            return default;
        }
    }

    private static async Task ForEachAsync<T>(IReadOnlyList<T> items, Func<T, CancellationToken, Task> body, CancellationToken ct)
    {
        if (items.Count == 0) return;
        using var gate = new SemaphoreSlim(Parallelism, Parallelism);
        var tasks = items.Select(async item =>
        {
            await gate.WaitAsync(ct);
            try { await body(item, ct); }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks);
    }
}
