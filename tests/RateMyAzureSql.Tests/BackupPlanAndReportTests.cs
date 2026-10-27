using RateMyAzureSql.Models;
using RateMyAzureSql.Services;
using RateMyAzureSql.Services.Reports;
using Xunit;

namespace RateMyAzureSql.Tests;

/// <summary>Backup plan deltas, generated scripts, and the Word / HTML reports.</summary>
public class BackupPlanAndReportTests
{
    private static SqlScanResult Demo() => DemoDataService.Scan(SqlFlowKind.SqlDatabase, [DemoDataService.SubProd, DemoDataService.SubShared]);
    private static SqlScanResult MiDemo() => DemoDataService.Scan(SqlFlowKind.ManagedInstance, [DemoDataService.SubProd, DemoDataService.SubShared]);
    private static HashSet<string> All(SqlFlowKind kind) => BackupPlanService.DefaultOptions(kind).Select(o => o.Key).ToHashSet();
    private static SqlDatabaseInfo Db(SqlScanResult scan, string name) => scan.Databases.First(d => d.Name == name);

    [Fact]
    public void Describe_PerfectDatabase_HasNoChanges()
    {
        var scan = Demo();
        var db = Db(scan, "contoso-orders");
        Assert.Empty(BackupPlanService.Describe(db, scan.Server(db.ServerId), new BackupPlan(), All(SqlFlowKind.SqlDatabase)));
    }

    [Fact]
    public void Describe_LegacyDatabase_ListsEveryDelta_WithTierNotes()
    {
        var scan = Demo();
        var db = Db(scan, "legacyapp");
        var changes = BackupPlanService.Describe(db, scan.Server(db.ServerId), new BackupPlan(), All(SqlFlowKind.SqlDatabase));
        var settings = changes.Select(c => c.Setting).ToList();

        Assert.Contains("Point-in-time retention", settings);
        Assert.Contains("Differential backups", settings);
        Assert.Contains("Long-term retention", settings);
        Assert.Contains("Backup storage redundancy", settings);
        Assert.Contains("Zone redundancy", settings);
        Assert.Contains("Failover group", settings);
        Assert.Equal("7 days", changes.Single(c => c.Setting == "Point-in-time retention").From);
        Assert.Equal("35 days", changes.Single(c => c.Setting == "Point-in-time retention").To);
        Assert.Contains("not supported on the Standard tier", changes.Single(c => c.Setting == "Zone redundancy").Note);
        Assert.Equal("Locally redundant", changes.Single(c => c.Setting == "Backup storage redundancy").From);
        Assert.Equal("Geo-zone-redundant", changes.Single(c => c.Setting == "Backup storage redundancy").To);
    }

    [Fact]
    public void Describe_BasicTier_CapsPitrAtSeven_AndDisabledOptionsAreIgnored()
    {
        var scan = Demo();
        var db = Db(scan, "basic-sandbox");
        var changes = BackupPlanService.Describe(db, scan.Server(db.ServerId), new BackupPlan(), new HashSet<string> { "pitr", "ltr" });
        Assert.DoesNotContain(changes, c => c.Setting == "Point-in-time retention"); // already 7, the Basic maximum
        Assert.Single(changes, c => c.Setting == "Long-term retention");
        Assert.DoesNotContain(changes, c => c.Setting == "Failover group");

        var plan14 = new BackupPlan { PitrDays = 14 };
        var withPlan = BackupPlanService.Describe(db, scan.Server(db.ServerId), plan14, new HashSet<string> { "pitr" });
        Assert.Empty(withPlan); // 14 clamps to 7 → no change
    }

    [Fact]
    public void Presets_AreDistinctAndValid()
    {
        Assert.Equal(3, BackupPlanService.Presets.Length);
        Assert.Equal(["baseline", "recommended", "compliance"], BackupPlanService.Presets.Select(p => p.Key).ToArray());
        Assert.False(BackupPlanService.Presets[0].Plan.FailoverGroup);
        Assert.True(BackupPlanService.Presets[1].Plan.HasLtr);
        Assert.Equal("P10Y", BackupPlanService.Presets[2].Plan.Yearly);
        Assert.NotEmpty(BackupPlanService.CostNotes);
    }

    [Fact]
    public void LtrEstimate_UsesBackupCompressionAndRetentionOverlapRange()
    {
        var estimate = BackupOptionsResearchService.EstimateLtrCost(
            100L * 1024 * 1024 * 1024, "P4W", "P3M", "P2Y", 0.03m);

        Assert.NotNull(estimate);
        Assert.Equal(3m, estimate.MinMonthlyUsd);
        Assert.Equal(9m, estimate.MaxMonthlyUsd);
        Assert.Equal((4, 9), BackupOptionsResearchService.LtrBackupCountRange("P4W", "P3M", "P2Y"));
    }

    [Fact]
    public void LtrEstimate_NoRetentionIsZero_AndUnknownCapacityIsNotEstimated()
    {
        Assert.Equal(new BackupCostRange(0, 0), BackupOptionsResearchService.EstimateLtrCost(null, "PT0S", "PT0S", "PT0S", null));
        Assert.Null(BackupOptionsResearchService.EstimateLtrCost(null, "P4W", "PT0S", "PT0S", 0.03m));
    }

    [Fact]
    public void BlobEstimate_UsesConfiguredCapacityAndRetainedCopyCount()
    {
        var estimate = BackupOptionsResearchService.EstimateBlobCost(10L * 1024 * 1024 * 1024, 4, 0.02m);

        Assert.Equal(new BackupCostRange(0.8m, 0.8m), estimate);
    }

    [Fact]
    public void BlobArchiveTier_RejectsZoneRedundancyButOnlineTiersSupportIt()
    {
        Assert.False(BackupOptionsResearchService.IsBlobTierSupported("Archive", "ZRS"));
        Assert.False(BackupOptionsResearchService.IsBlobTierSupported("Archive", "GZRS"));
        Assert.True(BackupOptionsResearchService.IsBlobTierSupported("Archive", "RA-GRS"));
        Assert.True(BackupOptionsResearchService.IsBlobTierSupported("Cold", "GZRS"));
    }

    [Fact]
    public void EnvironmentClassification_PrefersTagsThenDelimitedResourceNames()
    {
        var database = new SqlDatabaseInfo { Tags = new Dictionary<string, string> { ["Environment"] = "production" }, ResourceGroup = "rg-app-dev" };
        Assert.Equal("Prod", BackupOptionsResearchService.ClassifyEnvironment(database, null));

        database.Tags.Clear();
        Assert.Equal("Dev", BackupOptionsResearchService.ClassifyEnvironment(database, null));
        database.ResourceGroup = "rg-app-testing";
        Assert.Equal("Tst", BackupOptionsResearchService.ClassifyEnvironment(database, null));
        database.ResourceGroup = "rg-shared";
        Assert.Equal("Unclassified", BackupOptionsResearchService.ClassifyEnvironment(database, null));
        Assert.Equal("Tst", BackupOptionsResearchService.ClassifyEnvironment(database, null, "Contoso Testing"));
        database.Tags["Environment"] = "sandbox";
        database.ResourceGroup = "rg-app-prod";
        Assert.Equal("Unclassified", BackupOptionsResearchService.ClassifyEnvironment(database, null));
    }

    [Fact]
    public void EnvironmentAggregation_SumsOptionsAndKeepsUnknownTotalsUnavailable()
    {
        static List<BlobTierEstimate> Tiers(decimal hot, decimal cool) =>
        [
            new("Hot", 0.02m, new BackupCostRange(hot, hot)),
            new("Cool", 0.01m, new BackupCostRange(cool, cool)),
            new("Cold", 0.005m, new BackupCostRange(cool / 2m, cool / 2m)),
            new("Archive", 0.002m, new BackupCostRange(cool / 5m, cool / 5m))
        ];

        var estimates = new[]
        {
            new DatabaseBackupEstimate("Dev", "db1", "eastus", "10 GB", "weekly", "weekly", new(1, 2), new(3, 4), Tiers(5, 2), null),
            new DatabaseBackupEstimate("Dev", "db2", "eastus", "20 GB", "unknown", "weekly", null, new(1, 1), Tiers(4, 1), null),
            new DatabaseBackupEstimate("Prod", "db3", "westeurope", "30 GB", "weekly", "weekly", new(2, 2), new(2, 2), Tiers(3, 2), null)
        };

        var totals = BackupOptionsResearchService.AggregateByEnvironment(estimates);
        var dev = totals[0];

        Assert.Equal(["Dev", "Prod"], totals.Select(total => total.Environment).ToArray());
        Assert.Equal(2, dev.DatabaseCount);
        Assert.Null(dev.CurrentLtrMonthlyUsd);
        Assert.Equal(new BackupCostRange(4, 5), dev.PlannedLtrMonthlyUsd);
        Assert.Equal(new BackupCostRange(9, 9), dev.BlobExportOptions.Single(option => option.Tier == "Hot").MonthlyUsd);
        Assert.Equal("Archive", dev.CheapestBlobTier?.Tier);
    }

    [Fact]
    public async Task Research_RateLimitsConcurrentRetailPriceRequests()
    {
        using var limiter = new System.Threading.RateLimiting.TokenBucketRateLimiter(new()
        {
            TokenLimit = 1,
            TokensPerPeriod = 1,
            ReplenishmentPeriod = TimeSpan.FromHours(1),
            AutoReplenishment = false,
            QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
        var handler = new CountingRetailPriceHandler();
        using var http = new HttpClient(handler);
        var service = new BackupOptionsResearchService(http, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), limiter);
        var scan = new SqlScanResult
        {
            Flow = SqlFlowKind.SqlDatabase,
            Databases = [new SqlDatabaseInfo { Name = "test", Location = "eastus", Kind = SqlFlowKind.SqlDatabase, MaxSizeBytes = 10L * 1024 * 1024 * 1024 }]
        };

        var result = await service.ResearchAsync(scan, new BackupPlan(), 1, "LRS");

        Assert.Equal(1, handler.RequestCount);
        Assert.Contains(result.PricingWarnings, warning => warning.Contains("request queue is full", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Research_UsesEnvironmentSizeAssumptionOnlyForUnknownDatabases()
    {
        using var limiter = new System.Threading.RateLimiting.TokenBucketRateLimiter(new()
        {
            TokenLimit = 2,
            TokensPerPeriod = 1,
            ReplenishmentPeriod = TimeSpan.FromSeconds(1),
            AutoReplenishment = true,
            QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
            QueueLimit = 2
        });
        using var http = new HttpClient(new CountingRetailPriceHandler());
        var service = new BackupOptionsResearchService(http, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), limiter);
        var scan = new SqlScanResult
        {
            Flow = SqlFlowKind.ManagedInstance,
            Databases =
            [
                new SqlDatabaseInfo { Name = "devdb", ResourceGroup = "rg-mi-dev", ServerName = "mi-dev", SubscriptionId = "sub", Location = "eastus", Kind = SqlFlowKind.ManagedInstance },
                new SqlDatabaseInfo { Name = "small", ResourceGroup = "rg-mi-dev", ServerName = "mi-dev", SubscriptionId = "sub", Location = "eastus", Kind = SqlFlowKind.ManagedInstance, MaxSizeBytes = 20L * 1024 * 1024 * 1024 }
            ]
        };

        var result = await service.ResearchAsync(
            scan,
            new BackupPlan(),
            1,
            "LRS",
            environmentSizeEstimatesGb: new Dictionary<string, decimal> { ["Dev"] = 50m });

        var assumed = result.Databases.Single(database => database.DatabaseName == "devdb");
        var known = result.Databases.Single(database => database.DatabaseName == "small");
        var dev = Assert.Single(result.EnvironmentTotals);
        Assert.Equal("50 GB assumed", assumed.Capacity);
        Assert.Equal(50m, assumed.AssumedSizeGb);
        Assert.Equal("20 GB", known.Capacity);
        Assert.Null(known.AssumedSizeGb);
        Assert.Equal(1, dev.AssumedCapacityDatabaseCount);
        Assert.Equal(50m, dev.AssumedDatabaseSizeGb);
    }

    private sealed class CountingRetailPriceHandler : HttpMessageHandler
    {
        private int _requestCount;
        public int RequestCount => Volatile.Read(ref _requestCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("{\"Items\":[],\"NextPageLink\":null}")
            });
        }
    }

    [Fact]
    public void PowerShell_SqlDatabase_ContainsEveryCmdlet_AndBasicTierClamp()
    {
        var scan = Demo();
        var server = scan.Server(Db(scan, "hr-portal").ServerId);
        var dbs = scan.DatabasesOn(server!.Id).Where(d => !d.IsDataWarehouse).OrderBy(d => d.Name).ToList();

        var ps = BackupPlanService.GeneratePowerShell(dbs, server, new BackupPlan(), All(SqlFlowKind.SqlDatabase));

        Assert.Contains("generated by RateMyAzureSQL", ps);
        Assert.Contains("$serverName = \"sql-contoso-shared\"", ps);
        Assert.Contains("$databases = @(\"basic-sandbox\", \"hr-portal\", \"intranet\")", ps);
        Assert.Contains("$basicTier = @(\"basic-sandbox\")", ps);
        Assert.Contains("Set-AzSqlDatabaseBackupShortTermRetentionPolicy", ps);
        Assert.Contains("-RetentionDays $(if ($db -in $basicTier) { 7 } else { 35 }) -DiffBackupIntervalInHours 12", ps);
        Assert.Contains("Set-AzSqlDatabaseBackupLongTermRetentionPolicy", ps);
        Assert.Contains("-WeeklyRetention P12W -MonthlyRetention P12M -YearlyRetention P7Y -WeekOfYear 1", ps);
        Assert.Contains("-BackupStorageRedundancy GeoZone", ps);
        Assert.Contains("if ($db -in @(\"hr-portal\")) { Set-AzSqlDatabase", ps); // only the eligible, non-pooled, non-ZR db
        Assert.DoesNotContain("Set-AzSqlElasticPool", ps); // intranet is pooled but already zone redundant via the pool
        Assert.Contains("New-AzSqlDatabaseFailoverGroup", ps);
        Assert.Contains("Add-AzSqlDatabaseToFailoverGroup", ps);
        Assert.Contains("Basic/Standard tier: basic-sandbox are skipped", ps);
    }

    [Fact]
    public void PowerShell_PooledDatabase_PointsAtThePool()
    {
        var scan = Demo();
        var db = Db(scan, "intranet");
        db.ZoneRedundant = false; db.ZoneRedundancyFromPool = false;
        var ps = BackupPlanService.GeneratePowerShell([db], scan.Server(db.ServerId), new BackupPlan(), new HashSet<string> { "zone" });
        Assert.Contains("Set-AzSqlElasticPool -ResourceGroupName $resourceGroup -ServerName $serverName -ElasticPoolName \"sqlpool-shared\" -ZoneRedundant", ps);
        Assert.DoesNotContain("Set-AzSqlDatabase -ResourceGroupName $resourceGroup -ServerName $serverName -DatabaseName $db -ZoneRedundant", ps);
    }

    [Fact]
    public void PowerShell_OptionsCanBeSwitchedOff()
    {
        var scan = Demo();
        var db = Db(scan, "legacyapp");
        var ps = BackupPlanService.GeneratePowerShell([db], scan.Server(db.ServerId), new BackupPlan(), new HashSet<string> { "ltr" });
        Assert.Contains("Set-AzSqlDatabaseBackupLongTermRetentionPolicy", ps);
        Assert.DoesNotContain("ShortTermRetentionPolicy", ps);
        Assert.DoesNotContain("FailoverGroup", ps);
        Assert.DoesNotContain("BackupStorageRedundancy", ps);

        var none = BackupPlanService.GeneratePowerShell([db], scan.Server(db.ServerId), new BackupPlan(), new HashSet<string>());
        Assert.Contains("No options selected", none);
    }

    [Fact]
    public void PowerShell_PlanWithoutLtr_RemovesPolicy()
    {
        var scan = Demo();
        var db = Db(scan, "contoso-crm");
        var plan = new BackupPlan { Weekly = "PT0S", Monthly = "PT0S", Yearly = "PT0S" };
        var ps = BackupPlanService.GeneratePowerShell([db], scan.Server(db.ServerId), plan, new HashSet<string> { "ltr" });
        Assert.Contains("-RemovePolicy", ps);
    }

    [Fact]
    public void PowerShell_ManagedInstance_UsesInstanceCmdlets()
    {
        var scan = MiDemo();
        var db = Db(scan, "devdb");
        var mi = scan.Server(db.ServerId);
        var ps = BackupPlanService.GeneratePowerShell([db], mi, new BackupPlan(), All(SqlFlowKind.ManagedInstance));
        Assert.Contains("$instanceName = \"mi-contoso-dev\"", ps);
        Assert.Contains("Set-AzSqlInstanceDatabaseBackupShortTermRetentionPolicy -ResourceGroupName $resourceGroup -InstanceName $instanceName -DatabaseName $db -RetentionDays 35", ps);
        Assert.Contains("Set-AzSqlInstanceDatabaseBackupLongTermRetentionPolicy", ps);
        Assert.Contains("Set-AzSqlInstance -ResourceGroupName $resourceGroup -Name $instanceName -BackupStorageRedundancy GeoZone", ps);
        Assert.Contains("Set-AzSqlInstance -ResourceGroupName $resourceGroup -Name $instanceName -ZoneRedundant", ps);
        Assert.Contains("New-AzSqlDatabaseInstanceFailoverGroup", ps);
        Assert.DoesNotContain("DiffBackupIntervalInHours", ps);
    }

    [Fact]
    public void Cli_SqlDatabaseAndManagedInstance()
    {
        var scan = Demo();
        var db = Db(scan, "legacyapp");
        var sh = BackupPlanService.GenerateCli([db], scan.Server(db.ServerId), new BackupPlan(), All(SqlFlowKind.SqlDatabase));
        Assert.Contains("az sql db str-policy set -g \"$rg\" -s \"$server\" -n \"$db\" --retention-days 35 --diffbackup-hours 12", sh);
        Assert.Contains("az sql db ltr-policy set", sh);
        Assert.Contains("--backup-storage-redundancy GeoZone", sh);
        Assert.Contains("az sql failover-group create", sh);
        Assert.DoesNotContain("--zone-redundant true", sh); // Standard tier can't

        var mi = MiDemo();
        var midb = Db(mi, "devdb");
        var mish = BackupPlanService.GenerateCli([midb], mi.Server(midb.ServerId), new BackupPlan(), All(SqlFlowKind.ManagedInstance));
        Assert.Contains("az sql midb short-term-retention-policy set", mish);
        Assert.Contains("az sql mi update -g \"$rg\" -n \"$mi\" --backup-storage-redundancy GeoZone", mish);
        Assert.Contains("az sql instance-failover-group create", mish);
    }

    // ── Reports ──────────────────────────────────────────────────────────────

    private static SqlReportContext Ctx(SqlScanResult? scan, SqlFlowKind flow = SqlFlowKind.SqlDatabase) => new()
    {
        Flow = flow, CustomerName = "Contoso Ltd (demo)", TenantName = "Contoso Ltd (demo)", ReportAuthor = "tester",
        ScanDate = new DateTime(2026, 10, 26, 10, 0, 0), SubscriptionLines = ["Contoso Production (111)", "Contoso Shared Services (222)"], Scan = scan
    };

    [Fact]
    public void SummaryReport_HasAllSectionsAndKeyNumbers()
    {
        var doc = SqlReportService.BuildSummary(Ctx(Demo()));
        var headings = doc.Blocks.OfType<HeadingBlock>().Where(h => h.Level == 1).Select(h => h.Text).ToList();
        Assert.Equal(8, headings.Count);
        Assert.Contains("2. Executive summary", headings);
        Assert.Contains("6. Backup posture per database", headings);
        Assert.Contains("7. Network & identity per logical server", headings);

        var grade = Assert.Single(doc.Blocks.OfType<GradeBlock>());
        Assert.Equal("F", grade.Grade);
        Assert.Contains("legacyapp", grade.Summary);

        var html = SqlReportService.SummaryHtml(Ctx(Demo()));
        Assert.Contains("Security &amp; Backup Summary", html);
        Assert.Contains("sql-contoso-legacy", html);
        Assert.Contains("open to the whole internet", html);
    }

    [Fact]
    public void FindingsReport_IncludesFixesInventoryAndBackupPlan()
    {
        var doc = SqlReportService.BuildFindings(Ctx(Demo()));
        var headings = doc.Blocks.OfType<HeadingBlock>().Where(h => h.Level == 1).Select(h => h.Text).ToList();
        Assert.Equal(6, headings.Count);
        Assert.Contains("6. Backup improvement plan", headings);
        var bullets = doc.Blocks.OfType<BulletBlock>().SelectMany(b => b.Items).ToList();
        Assert.Contains(bullets, b => b.Contains("Fix: "));
        Assert.Contains(bullets, b => b.Contains("Firewall rules (3)"));
        Assert.Contains(bullets, b => b.StartsWith("+15 pts") && b.Contains("long-term retention"));
    }

    [Fact]
    public void Reports_RenderToDocxAndHtml_EvenWithoutAScan()
    {
        foreach (var scan in new SqlScanResult?[] { Demo(), MiDemo(), null })
        {
            var flow = scan?.Flow ?? SqlFlowKind.SqlDatabase;
            var summary = SqlReportService.SummaryDocx(Ctx(scan, flow));
            var findings = SqlReportService.FindingsDocx(Ctx(scan, flow));
            Assert.True(summary.Length > 2000);
            Assert.True(findings.Length > 2000);
            Assert.Equal(0x50, summary[0]); // 'P' of the zip header
            Assert.NotEmpty(SqlReportService.SummaryHtml(Ctx(scan, flow)));
            Assert.NotEmpty(SqlReportService.FindingsHtml(Ctx(scan, flow)));
        }
        Assert.Contains("No scan data", SqlReportService.SummaryHtml(Ctx(null)));
    }

    [Fact]
    public void FileName_IsSafeAndDescriptive()
    {
        Assert.Equal("ContosoLtddemo-SqlDatabase-Summary-20261026.docx", SqlReportService.FileName(Ctx(null), false));
        Assert.Equal("ContosoLtddemo-ManagedInstance-Findings-20261026.docx", SqlReportService.FileName(Ctx(null, SqlFlowKind.ManagedInstance), true));
    }
}
