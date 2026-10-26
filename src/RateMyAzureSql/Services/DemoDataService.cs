using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>
/// A realistic sample estate for each flow so the app can be explored (and tested end to end)
/// without Azure credentials. Every grade band from A to F appears somewhere.
/// </summary>
public static class DemoDataService
{
    public const string TenantId = "00000000-0000-0000-0000-00000000demo";
    public const string SubProd = "11111111-1111-1111-1111-111111111111";
    public const string SubShared = "22222222-2222-2222-2222-222222222222";

    public static List<SubscriptionInfo> Subscriptions() =>
    [
        new() { SubscriptionId = SubProd, DisplayName = "Contoso Production", State = "Enabled", TenantId = TenantId },
        new() { SubscriptionId = SubShared, DisplayName = "Contoso Shared Services", State = "Enabled", TenantId = TenantId },
    ];

    public static Dictionary<string, TenantInfo> Tenants() => new(StringComparer.OrdinalIgnoreCase)
    {
        [TenantId] = new TenantInfo { TenantId = TenantId, DisplayName = "Contoso Ltd (demo)", DefaultDomain = "contoso.onmicrosoft.com" }
    };

    public static Dictionary<string, SqlSubscriptionSummary> Summaries() => new(StringComparer.OrdinalIgnoreCase)
    {
        [SubProd] = new() { SubscriptionId = SubProd, ServerCount = 2, DatabaseCount = 4, ManagedInstanceCount = 1, ManagedDatabaseCount = 2 },
        [SubShared] = new() { SubscriptionId = SubShared, ServerCount = 1, DatabaseCount = 3, ManagedInstanceCount = 1, ManagedDatabaseCount = 1 },
    };

    private static string Rg(string sub, string rg) => $"/subscriptions/{sub}/resourceGroups/{rg}/providers";

    public static SqlScanResult Scan(SqlFlowKind flow, IReadOnlyCollection<string> subscriptionIds)
    {
        var result = flow == SqlFlowKind.SqlDatabase ? SqlDatabaseEstate() : ManagedInstanceEstate();
        result.SubscriptionIds = subscriptionIds.ToList();
        var subs = new HashSet<string>(subscriptionIds, StringComparer.OrdinalIgnoreCase);
        result.Servers = result.Servers.Where(s => subs.Contains(s.SubscriptionId)).ToList();
        result.Databases = result.Databases.Where(d => subs.Contains(d.SubscriptionId)).ToList();
        SqlDiscoveryService.Finalize(result);
        return result;
    }

    /// <summary>Sample long-term retention backups for a database (consistent with its policy).</summary>
    public static List<LtrBackupInfo> LtrBackups(SqlDatabaseInfo db)
    {
        var list = new List<LtrBackupInfo>();
        if (!db.HasLtr) return list;
        var now = DateTime.UtcNow.Date;
        if (db.HasWeeklyLtr)
            for (var i = 0; i < 4; i++)
                list.Add(new LtrBackupInfo { Name = $"{db.Name}-weekly-{i}", BackupTime = now.AddDays(-7 * i - 2), ExpirationTime = now.AddDays(-7 * i - 2 + 84), StorageRedundancy = db.BackupStorageRedundancy });
        if (db.HasMonthlyLtr)
            for (var i = 1; i <= 3; i++)
                list.Add(new LtrBackupInfo { Name = $"{db.Name}-monthly-{i}", BackupTime = now.AddMonths(-i).AddDays(-1), ExpirationTime = now.AddMonths(-i + 12), StorageRedundancy = db.BackupStorageRedundancy });
        if (db.HasYearlyLtr)
            list.Add(new LtrBackupInfo { Name = $"{db.Name}-yearly-1", BackupTime = new DateTime(now.Year, 1, 3), ExpirationTime = new DateTime(now.Year + 7, 1, 3), StorageRedundancy = db.BackupStorageRedundancy });
        return list.OrderByDescending(b => b.BackupTime).ToList();
    }

    // ── SQL Databases ────────────────────────────────────────────────────────

    public static SqlScanResult SqlDatabaseEstate()
    {
        var result = new SqlScanResult { Flow = SqlFlowKind.SqlDatabase };

        // 1. Production server: locked down, Entra-only, Defender, auditing → its databases grade A / B
        var prodId = $"{Rg(SubProd, "rg-data-prod")}/Microsoft.Sql/servers/sql-contoso-prod";
        var prod = new SqlServerInfo
        {
            Id = prodId, Name = "sql-contoso-prod", ResourceGroup = "rg-data-prod", SubscriptionId = SubProd, Location = "westeurope",
            Fqdn = "sql-contoso-prod.database.windows.net", Kind = SqlFlowKind.SqlDatabase,
            PublicNetworkAccess = false, PrivateEndpointCount = 2, MinimalTlsVersion = "1.2",
            FirewallRules = [],
            SqlAdminLogin = "sqladmin", EntraAdminLogin = "sg-sql-admins@contoso.com", EntraAdminType = "Group", EntraOnlyAuthentication = true,
            DefenderEnabled = true, VulnerabilityAssessmentEnabled = true,
            AuditingEnabled = true, AuditDestinations = ["Log Analytics: law-contoso-prod"], AuditRetentionDays = 0,
            EncryptionProtector = "AzureKeyVault",
            FailoverGroups =
            [
                new() { Id = prodId + "/failoverGroups/fog-contoso-prod", Name = "fog-contoso-prod", PartnerServer = "sql-contoso-prod-dr", PartnerLocation = "northeurope",
                        FailoverPolicy = "Automatic", GracePeriodMinutes = 60, ReplicationRole = "Primary", DatabaseIds = [prodId + "/databases/contoso-orders"] }
            ]
        };
        result.Servers.Add(prod);
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = prodId + "/databases/contoso-orders", Name = "contoso-orders", ServerId = prodId, ServerName = "sql-contoso-prod",
            ResourceGroup = "rg-data-prod", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "BusinessCritical", SkuName = "BC_Gen5", Capacity = 8, ServiceObjective = "BC_Gen5_8", Status = "Online", MaxSizeBytes = 512L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddYears(-3), ZoneRedundant = true, BackupStorageRedundancy = "GeoZone",
            PitrRetentionDays = 35, DiffBackupIntervalHours = 12, LtrRead = true, WeeklyRetention = "P12W", MonthlyRetention = "P12M", YearlyRetention = "P7Y", WeekOfYear = 1,
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-35), TdeEnabled = true, FailoverGroupName = "fog-contoso-prod",
            GeoReplicas = [new() { PartnerServer = "sql-contoso-prod-dr", PartnerLocation = "northeurope", PartnerDatabase = "contoso-orders", Role = "Primary", ReplicationState = "CATCH_UP" }]
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = prodId + "/databases/contoso-crm", Name = "contoso-crm", ServerId = prodId, ServerName = "sql-contoso-prod",
            ResourceGroup = "rg-data-prod", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "GeneralPurpose", SkuName = "GP_Gen5", Capacity = 4, ServiceObjective = "GP_Gen5_4", Status = "Online", MaxSizeBytes = 250L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddYears(-2), ZoneRedundant = false, BackupStorageRedundancy = "Geo",
            PitrRetentionDays = 14, DiffBackupIntervalHours = 24, LtrRead = true, WeeklyRetention = "P4W", MonthlyRetention = "PT0S", YearlyRetention = "PT0S", WeekOfYear = 0,
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-14), TdeEnabled = true
        });

        // 2. Legacy server: open to the internet, SQL auth only, no Defender, no auditing, TLS 1.0 → F / E
        var legacyId = $"{Rg(SubProd, "rg-legacy")}/Microsoft.Sql/servers/sql-contoso-legacy";
        result.Servers.Add(new SqlServerInfo
        {
            Id = legacyId, Name = "sql-contoso-legacy", ResourceGroup = "rg-legacy", SubscriptionId = SubProd, Location = "westeurope",
            Fqdn = "sql-contoso-legacy.database.windows.net", Kind = SqlFlowKind.SqlDatabase,
            PublicNetworkAccess = true, PrivateEndpointCount = 0, MinimalTlsVersion = "1.0",
            FirewallRules =
            [
                new() { Name = "AllowAllWindowsAzureIps", StartIp = "0.0.0.0", EndIp = "0.0.0.0" },
                new() { Name = "AllowAll", StartIp = "0.0.0.0", EndIp = "255.255.255.255" },
                new() { Name = "Office", StartIp = "81.145.0.0", EndIp = "81.145.255.255" },
            ],
            SqlAdminLogin = "sa-legacy", EntraOnlyAuthentication = false,
            DefenderEnabled = false, VulnerabilityAssessmentEnabled = false,
            AuditingEnabled = false, EncryptionProtector = "ServiceManaged"
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = legacyId + "/databases/legacyapp", Name = "legacyapp", ServerId = legacyId, ServerName = "sql-contoso-legacy",
            ResourceGroup = "rg-legacy", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "Standard", SkuName = "Standard", Capacity = 20, ServiceObjective = "S1", Status = "Online", MaxSizeBytes = 250L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddYears(-6), ZoneRedundant = false, BackupStorageRedundancy = "Local",
            PitrRetentionDays = 7, DiffBackupIntervalHours = 24, LtrRead = true, WeeklyRetention = "PT0S", MonthlyRetention = "PT0S", YearlyRetention = "PT0S",
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-7), TdeEnabled = false
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = legacyId + "/databases/reporting", Name = "reporting", ServerId = legacyId, ServerName = "sql-contoso-legacy",
            ResourceGroup = "rg-legacy", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "Standard", SkuName = "Standard", Capacity = 100, ServiceObjective = "S3", Status = "Online", MaxSizeBytes = 250L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddYears(-4), ZoneRedundant = false, BackupStorageRedundancy = "Zone",
            PitrRetentionDays = 14, DiffBackupIntervalHours = 12, LtrRead = true, WeeklyRetention = "P4W", MonthlyRetention = "P12M", YearlyRetention = "PT0S", WeekOfYear = 0,
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-14), TdeEnabled = true
        });

        // 3. Shared-services server: private, Entra admin but SQL auth still on, no VA, audit to storage → C-ish, with a Basic sandbox (E) and a DW
        var sharedId = $"{Rg(SubShared, "rg-shared-data")}/Microsoft.Sql/servers/sql-contoso-shared";
        result.Servers.Add(new SqlServerInfo
        {
            Id = sharedId, Name = "sql-contoso-shared", ResourceGroup = "rg-shared-data", SubscriptionId = SubShared, Location = "northeurope",
            Fqdn = "sql-contoso-shared.database.windows.net", Kind = SqlFlowKind.SqlDatabase,
            PublicNetworkAccess = true, PrivateEndpointCount = 1, MinimalTlsVersion = "1.2",
            FirewallRules =
            [
                new() { Name = "AllowAllWindowsAzureIps", StartIp = "0.0.0.0", EndIp = "0.0.0.0" },
                new() { Name = "vpn-gateway", StartIp = "20.50.10.4", EndIp = "20.50.10.4" },
            ],
            SqlAdminLogin = "sqladmin", EntraAdminLogin = "sg-platform-admins@contoso.com", EntraAdminType = "Group", EntraOnlyAuthentication = false,
            DefenderEnabled = true, VulnerabilityAssessmentEnabled = false,
            AuditingEnabled = true, AuditDestinations = ["Storage: stcontosoaudit"], AuditRetentionDays = 90,
            EncryptionProtector = "ServiceManaged"
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = sharedId + "/databases/hr-portal", Name = "hr-portal", ServerId = sharedId, ServerName = "sql-contoso-shared",
            ResourceGroup = "rg-shared-data", SubscriptionId = SubShared, Location = "northeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "GeneralPurpose", SkuName = "GP_S_Gen5", Capacity = 2, ServiceObjective = "GP_S_Gen5_2", IsServerless = true, Status = "Online", MaxSizeBytes = 32L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddMonths(-10), ZoneRedundant = false, BackupStorageRedundancy = "Geo",
            PitrRetentionDays = 7, DiffBackupIntervalHours = 12, LtrRead = true, WeeklyRetention = "PT0S", MonthlyRetention = "PT0S", YearlyRetention = "PT0S",
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-7), TdeEnabled = true
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = sharedId + "/databases/intranet", Name = "intranet", ServerId = sharedId, ServerName = "sql-contoso-shared",
            ResourceGroup = "rg-shared-data", SubscriptionId = SubShared, Location = "northeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "GeneralPurpose", SkuName = "ElasticPool", Capacity = 0, ServiceObjective = "ElasticPool", Status = "Online", MaxSizeBytes = 32L * 1024 * 1024 * 1024,
            ElasticPoolId = sharedId + "/elasticPools/sqlpool-shared", ZoneRedundant = true, ZoneRedundancyFromPool = true,
            CreationDate = DateTime.UtcNow.AddMonths(-20), BackupStorageRedundancy = "Geo",
            PitrRetentionDays = 35, DiffBackupIntervalHours = 12, LtrRead = true, WeeklyRetention = "P12W", MonthlyRetention = "P12M", YearlyRetention = "PT0S", WeekOfYear = 0,
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-35), TdeEnabled = true
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = sharedId + "/databases/basic-sandbox", Name = "basic-sandbox", ServerId = sharedId, ServerName = "sql-contoso-shared",
            ResourceGroup = "rg-shared-data", SubscriptionId = SubShared, Location = "northeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "Basic", SkuName = "Basic", Capacity = 5, ServiceObjective = "Basic", Status = "Online", MaxSizeBytes = 2L * 1024 * 1024 * 1024,
            CreationDate = DateTime.UtcNow.AddMonths(-3), ZoneRedundant = false, BackupStorageRedundancy = "Local",
            PitrRetentionDays = 7, DiffBackupIntervalHours = 24, LtrRead = true, WeeklyRetention = "PT0S", MonthlyRetention = "PT0S", YearlyRetention = "PT0S",
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-7), TdeEnabled = true
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = sharedId + "/databases/analytics-dw", Name = "analytics-dw", ServerId = sharedId, ServerName = "sql-contoso-shared",
            ResourceGroup = "rg-shared-data", SubscriptionId = SubShared, Location = "northeurope", Kind = SqlFlowKind.SqlDatabase,
            Tier = "DataWarehouse", SkuName = "DataWarehouse", ServiceObjective = "DW100c", Status = "Paused",
            CreationDate = DateTime.UtcNow.AddYears(-1), BackupStorageRedundancy = "Geo", TdeEnabled = true
        });

        return result;
    }

    // ── Managed Instances ────────────────────────────────────────────────────

    public static SqlScanResult ManagedInstanceEstate()
    {
        var result = new SqlScanResult { Flow = SqlFlowKind.ManagedInstance };

        // 1. Production instance: private, Entra-only, Defender, BC, zone redundant, instance failover group → A / B
        var prodId = $"{Rg(SubProd, "rg-mi-prod")}/Microsoft.Sql/managedInstances/mi-contoso-prod";
        result.Servers.Add(new SqlServerInfo
        {
            Id = prodId, Name = "mi-contoso-prod", ResourceGroup = "rg-mi-prod", SubscriptionId = SubProd, Location = "westeurope",
            Fqdn = "mi-contoso-prod.abc123.database.windows.net", Kind = SqlFlowKind.ManagedInstance,
            PublicNetworkAccess = false, MinimalTlsVersion = "1.2", SubnetId = $"{Rg(SubProd, "rg-mi-prod")}/Microsoft.Network/virtualNetworks/vnet-prod/subnets/snet-mi",
            Tier = "BusinessCritical", VCores = 8, ZoneRedundant = true, BackupStorageRedundancy = "GeoZone",
            SqlAdminLogin = "miadmin", EntraAdminLogin = "sg-sql-admins@contoso.com", EntraAdminType = "Group", EntraOnlyAuthentication = true,
            DefenderEnabled = true, VulnerabilityAssessmentEnabled = true, EncryptionProtector = "ServiceManaged",
            FailoverGroups =
            [
                new() { Id = $"{Rg(SubProd, "rg-mi-prod")}/Microsoft.Sql/locations/westeurope/instanceFailoverGroups/fog-mi-contoso", Name = "fog-mi-contoso",
                        PartnerServer = "mi-contoso-dr", PartnerLocation = "northeurope", FailoverPolicy = "Automatic", GracePeriodMinutes = 60, ReplicationRole = "Primary" }
            ]
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = prodId + "/databases/erp", Name = "erp", ServerId = prodId, ServerName = "mi-contoso-prod",
            ResourceGroup = "rg-mi-prod", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.ManagedInstance,
            Tier = "BusinessCritical", Status = "Online", CreationDate = DateTime.UtcNow.AddYears(-2), ZoneRedundant = true, BackupStorageRedundancy = "GeoZone",
            PitrRetentionDays = 35, LtrRead = true, WeeklyRetention = "P12W", MonthlyRetention = "P12M", YearlyRetention = "P7Y", WeekOfYear = 1,
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-35), TdeEnabled = true, FailoverGroupName = "fog-mi-contoso"
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = prodId + "/databases/erp-staging", Name = "erp-staging", ServerId = prodId, ServerName = "mi-contoso-prod",
            ResourceGroup = "rg-mi-prod", SubscriptionId = SubProd, Location = "westeurope", Kind = SqlFlowKind.ManagedInstance,
            Tier = "BusinessCritical", Status = "Online", CreationDate = DateTime.UtcNow.AddMonths(-8), ZoneRedundant = true, BackupStorageRedundancy = "GeoZone",
            PitrRetentionDays = 7, LtrRead = true, WeeklyRetention = "PT0S", MonthlyRetention = "PT0S", YearlyRetention = "PT0S",
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-7), TdeEnabled = true, FailoverGroupName = "fog-mi-contoso"
        });

        // 2. Dev instance: public endpoint, SQL auth only, no Defender, TLS 1.1, GP, local backups → F
        var devId = $"{Rg(SubShared, "rg-mi-dev")}/Microsoft.Sql/managedInstances/mi-contoso-dev";
        result.Servers.Add(new SqlServerInfo
        {
            Id = devId, Name = "mi-contoso-dev", ResourceGroup = "rg-mi-dev", SubscriptionId = SubShared, Location = "northeurope",
            Fqdn = "mi-contoso-dev.def456.database.windows.net", Kind = SqlFlowKind.ManagedInstance,
            PublicNetworkAccess = true, MinimalTlsVersion = "1.1", SubnetId = $"{Rg(SubShared, "rg-mi-dev")}/Microsoft.Network/virtualNetworks/vnet-dev/subnets/snet-mi",
            Tier = "GeneralPurpose", VCores = 4, ZoneRedundant = false, BackupStorageRedundancy = "Local",
            SqlAdminLogin = "miadmin", EntraOnlyAuthentication = false,
            DefenderEnabled = false, VulnerabilityAssessmentEnabled = false, EncryptionProtector = "ServiceManaged"
        });
        result.Databases.Add(new SqlDatabaseInfo
        {
            Id = devId + "/databases/devdb", Name = "devdb", ServerId = devId, ServerName = "mi-contoso-dev",
            ResourceGroup = "rg-mi-dev", SubscriptionId = SubShared, Location = "northeurope", Kind = SqlFlowKind.ManagedInstance,
            Tier = "GeneralPurpose", Status = "Online", CreationDate = DateTime.UtcNow.AddMonths(-5), ZoneRedundant = false, BackupStorageRedundancy = "Local",
            PitrRetentionDays = 7, LtrRead = true, WeeklyRetention = "PT0S", MonthlyRetention = "PT0S", YearlyRetention = "PT0S",
            EarliestRestoreDate = DateTime.UtcNow.AddDays(-7), TdeEnabled = true
        });

        return result;
    }
}
