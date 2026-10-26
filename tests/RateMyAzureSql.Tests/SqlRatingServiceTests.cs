using RateMyAzureSql.Models;
using RateMyAzureSql.Services;
using Xunit;

namespace RateMyAzureSql.Tests;

/// <summary>
/// Scoring reference cases: each category's points, the caps, and the improvement arithmetic.
/// These numbers are the contract of the scoring model described in the README.
/// </summary>
public class SqlRatingServiceTests
{
    private const string ServerId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1";
    private const string DbId = ServerId + "/databases/db1";
    private const string MiId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/mi1";
    private const string MiDbId = MiId + "/databases/db1";

    // ── Builders ─────────────────────────────────────────────────────────────

    /// <summary>A server that earns full marks in every security category.</summary>
    private static SqlServerInfo PerfectServer() => new()
    {
        Id = ServerId, Name = "srv1", SubscriptionId = "s1", Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
        PublicNetworkAccess = false, PrivateEndpointCount = 1, MinimalTlsVersion = "1.2", FirewallRules = [],
        SqlAdminLogin = "sqladmin", EntraAdminLogin = "admins@contoso.com", EntraAdminType = "Group", EntraOnlyAuthentication = true,
        DefenderEnabled = true, VulnerabilityAssessmentEnabled = true, AuditingEnabled = true, AuditDestinations = ["Log Analytics: law"],
        EncryptionProtector = "ServiceManaged",
        FailoverGroups = [new() { Name = "fog1", PartnerServer = "srv1-dr", PartnerLocation = "northeurope", FailoverPolicy = "Automatic", ReplicationRole = "Primary", DatabaseIds = [DbId] }]
    };

    /// <summary>A database that earns full marks in every backup category.</summary>
    private static SqlDatabaseInfo PerfectDatabase() => new()
    {
        Id = DbId, Name = "db1", ServerId = ServerId, ServerName = "srv1", SubscriptionId = "s1", Location = "westeurope", Kind = SqlFlowKind.SqlDatabase,
        Tier = "GeneralPurpose", SkuName = "GP_Gen5", ZoneRedundant = true, BackupStorageRedundancy = "GeoZone",
        PitrRetentionDays = 35, DiffBackupIntervalHours = 12, LtrRead = true, WeeklyRetention = "P12W", MonthlyRetention = "P12M", YearlyRetention = "P7Y", WeekOfYear = 1,
        TdeEnabled = true, FailoverGroupName = "fog1"
    };

    private static SqlRatingCategory Cat(SqlRating r, string name) => r.Categories.Single(c => c.Name == name);

    // ── Reference cases ──────────────────────────────────────────────────────

    [Fact]
    public void FullyConfigured_ScoresHundred_GradeA()
    {
        var r = SqlRatingService.Rate(PerfectDatabase(), PerfectServer());

        Assert.Equal(100, r.Score);
        Assert.Equal(50, r.SecurityScore);
        Assert.Equal(50, r.BackupScore);
        Assert.Equal("A", r.Grade);
        Assert.Null(r.CapReason);
        Assert.Empty(r.Improvements);
        Assert.Equal(8, r.Categories.Count);
        Assert.All(r.Categories, c => Assert.Equal(c.Possible, c.Earned));
    }

    [Fact]
    public void OpenToInternet_ZeroNetworkPoints_CappedAtD()
    {
        var server = PerfectServer();
        server.PublicNetworkAccess = true;
        server.FirewallRules = [new() { Name = "AllowAll", StartIp = "0.0.0.0", EndIp = "255.255.255.255" }];

        var r = SqlRatingService.Rate(PerfectDatabase(), server);

        Assert.Equal(0, Cat(r, SqlRatingService.NetworkCategory).Earned);
        Assert.Equal(85, r.Score);
        Assert.Equal("D", r.Grade);
        Assert.Contains("every IPv4 address", r.CapReason);

        // Deleting the open rule lifts the cap: 85 + 10 (public endpoint with a private endpoint) = 95 → A.
        var delete = r.Improvements.Single(i => i.Action.StartsWith("Delete the firewall rule"));
        Assert.Equal(10, delete.PointsGained);
        Assert.Equal("A", delete.ResultingGrade);

        // Disabling public access altogether gains the full 15 and also lifts the cap.
        var disable = r.Improvements.Single(i => i.Action.StartsWith("Disable public network access"));
        Assert.Equal(15, disable.PointsGained);
        Assert.Equal("A", disable.ResultingGrade);
    }

    [Fact]
    public void PublicEndpoint_AllowAzureServicesAndBroadRule_Deducted()
    {
        var server = PerfectServer();
        server.PublicNetworkAccess = true;
        server.PrivateEndpointCount = 0;
        server.FirewallRules =
        [
            new() { Name = "AllowAllWindowsAzureIps", StartIp = "0.0.0.0", EndIp = "0.0.0.0" },
            new() { Name = "Office", StartIp = "10.0.0.0", EndIp = "10.0.255.255" },
            new() { Name = "Home", StartIp = "1.2.3.4", EndIp = "1.2.3.4" },
        ];

        var r = SqlRatingService.Rate(PerfectDatabase(), server);

        // 8 base − 3 (Azure services) − 2 (broad rule) = 3
        Assert.Equal(3, Cat(r, SqlRatingService.NetworkCategory).Earned);
        Assert.Null(r.CapReason);
        Assert.Equal("B", r.Grade);
        Assert.Contains(r.Improvements, i => i.Action.Contains("Allow Azure services") && i.PointsGained == 3);
        Assert.Contains(r.Improvements, i => i.Action.Contains("Narrow the broad firewall rule") && i.PointsGained == 2);
        Assert.Contains(r.Improvements, i => i.Action.StartsWith("Disable public network access") && i.PointsGained == 12);
    }

    [Fact]
    public void NoEntraAdmin_CappedAtB_AndEntraOnlyImpossible()
    {
        var server = PerfectServer();
        server.EntraAdminLogin = "";
        server.EntraOnlyAuthentication = null;

        var r = SqlRatingService.Rate(PerfectDatabase(), server);

        Assert.Equal(0, Cat(r, SqlRatingService.IdentityCategory).Earned);
        Assert.Equal(90, r.Score);
        Assert.Equal("B", r.Grade);
        Assert.Contains("No Microsoft Entra admin", r.CapReason);
        var setAdmin = r.Improvements.Single(i => i.Action.StartsWith("Set a Microsoft Entra admin"));
        Assert.Equal(5, setAdmin.PointsGained);
        Assert.Equal("A", setAdmin.ResultingGrade);
    }

    [Fact]
    public void DefenderOff_LosesDefenderAndVaPoints_CappedAtB()
    {
        var server = PerfectServer();
        server.DefenderEnabled = false;
        server.VulnerabilityAssessmentEnabled = false;

        var r = SqlRatingService.Rate(PerfectDatabase(), server);

        Assert.Equal(6, Cat(r, SqlRatingService.ThreatCategory).Earned); // auditing only
        Assert.Equal("B", r.Grade);
        Assert.Contains("Defender for SQL is off", r.CapReason);
        var enable = r.Improvements.Single(i => i.Action.StartsWith("Enable Microsoft Defender"));
        Assert.Equal(9, enable.PointsGained); // 6 Defender + 3 VA
        Assert.Equal("A", enable.ResultingGrade);
        Assert.DoesNotContain(r.Improvements, i => i.Action.Contains("vulnerability assessment (express"));
    }

    [Fact]
    public void TdeDisabled_CappedAtD()
    {
        var db = PerfectDatabase();
        db.TdeEnabled = false;

        var r = SqlRatingService.Rate(db, PerfectServer());

        Assert.Equal(3, Cat(r, SqlRatingService.EncryptionCategory).Earned);
        Assert.Equal(93, r.Score);
        Assert.Equal("D", r.Grade);
        Assert.Contains("Transparent data encryption is disabled", r.CapReason);
        Assert.Equal("A", r.Improvements.Single(i => i.Action.StartsWith("Enable transparent data encryption")).ResultingGrade);
    }

    [Fact]
    public void WeakOrMissingTls_LosesThreePoints()
    {
        var server = PerfectServer();
        server.MinimalTlsVersion = "";
        var r = SqlRatingService.Rate(PerfectDatabase(), server);
        Assert.Equal(7, Cat(r, SqlRatingService.EncryptionCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("minimum TLS version") && i.PointsGained == 3);

        server.MinimalTlsVersion = "1.1";
        Assert.Equal(7, Cat(SqlRatingService.Rate(PerfectDatabase(), server), SqlRatingService.EncryptionCategory).Earned);

        server.MinimalTlsVersion = "1.3";
        Assert.Equal(10, Cat(SqlRatingService.Rate(PerfectDatabase(), server), SqlRatingService.EncryptionCategory).Earned);
    }

    [Theory]
    [InlineData(35, 15)]
    [InlineData(30, 13)]
    [InlineData(28, 13)]
    [InlineData(14, 11)]
    [InlineData(7, 8)]
    [InlineData(3, 3)]
    [InlineData(1, 1)]
    public void PitrRetention_TieredPoints(int days, int expected)
    {
        var db = PerfectDatabase();
        db.PitrRetentionDays = days;
        var r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Equal(expected, Cat(r, SqlRatingService.PitrCategory).Earned);
        if (days < 35)
            Assert.Contains(r.Improvements, i => i.Action.Contains("Raise point-in-time retention") && i.PointsGained == 15 - expected);
    }

    [Fact]
    public void BasicTier_SevenDaysIsFullMarks_AndZoneRedundancyUnavailable()
    {
        var db = PerfectDatabase();
        db.Tier = "Basic";
        db.PitrRetentionDays = 7;
        db.ZoneRedundant = false;

        var r = SqlRatingService.Rate(db, PerfectServer());

        Assert.Equal(15, Cat(r, SqlRatingService.PitrCategory).Earned);
        Assert.DoesNotContain(r.Improvements, i => i.Action.Contains("Raise point-in-time retention"));
        Assert.Equal(6, Cat(r, SqlRatingService.ResilienceCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("from Basic to General Purpose") && i.PointsGained == 4);
    }

    [Fact]
    public void NoLongTermRetention_CappedAtB()
    {
        var db = PerfectDatabase();
        db.WeeklyRetention = "PT0S"; db.MonthlyRetention = "PT0S"; db.YearlyRetention = "PT0S";

        var r = SqlRatingService.Rate(db, PerfectServer());

        Assert.Equal(0, Cat(r, SqlRatingService.LtrCategory).Earned);
        Assert.Equal(85, r.Score);
        Assert.Equal("B", r.Grade);
        // Losing all 15 LTR points already lands on B, so the cap never has to override the score.
        Assert.Null(r.CapReason);
        var ltr = r.Improvements.Single(i => i.Action.StartsWith("Configure long-term retention"));
        Assert.Equal(15, ltr.PointsGained);
        Assert.Equal("A", ltr.ResultingGrade);
        Assert.Equal(RatingArea.Backups, ltr.Area);
    }

    [Fact]
    public void PartialLongTermRetention_FivePointsEach()
    {
        var db = PerfectDatabase();
        db.MonthlyRetention = "PT0S";
        db.YearlyRetention = "";

        var r = SqlRatingService.Rate(db, PerfectServer());

        Assert.Equal(5, Cat(r, SqlRatingService.LtrCategory).Earned);
        Assert.Null(r.CapReason);
        Assert.Contains(r.Improvements, i => i.Action.Contains("Add monthly backups") && i.PointsGained == 5);
        Assert.Contains(r.Improvements, i => i.Action.Contains("Add yearly backups") && i.PointsGained == 5);
    }

    [Fact]
    public void LtrNotReadable_PartialPointsNoCap()
    {
        var db = PerfectDatabase();
        db.LtrRead = false;
        var r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Equal(8, Cat(r, SqlRatingService.LtrCategory).Earned);
        Assert.Null(r.CapReason);
    }

    [Theory]
    [InlineData("GeoZone", 10, null)]
    [InlineData("Geo", 10, null)]
    [InlineData("Zone", 5, null)]
    [InlineData("Local", 0, "C")]
    [InlineData("", 5, null)]
    public void BackupStorageRedundancy_Points(string redundancy, int expected, string? capGrade)
    {
        var db = PerfectDatabase();
        db.BackupStorageRedundancy = redundancy;
        var r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Equal(expected, Cat(r, SqlRatingService.RedundancyCategory).Earned);
        if (capGrade is null) Assert.True(string.CompareOrdinal(r.Grade, "C") < 0, $"grade {r.Grade} should be better than C");
        else
        {
            Assert.Equal(capGrade, r.Grade);
            Assert.Contains("locally redundant", r.CapReason);
            Assert.Equal("A", r.Improvements.Single(i => i.Action.Contains("Change backup storage redundancy")).ResultingGrade);
        }
    }

    [Fact]
    public void GeoReplicaWithoutGroup_FourPoints_FailoverGroupSix()
    {
        var db = PerfectDatabase();
        db.FailoverGroupName = null;
        db.GeoReplicas = [new() { PartnerServer = "srv1-dr", PartnerLocation = "northeurope", Role = "Primary" }];
        var r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Equal(8, Cat(r, SqlRatingService.ResilienceCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("into a failover group") && i.PointsGained == 2);

        db.GeoReplicas = [];
        r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Equal(4, Cat(r, SqlRatingService.ResilienceCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("failover group") && i.PointsGained == 6);
    }

    [Fact]
    public void PooledDatabase_ZoneRedundancyImprovementNamesThePool()
    {
        var db = PerfectDatabase();
        db.ZoneRedundant = false;
        db.ElasticPoolId = ServerId + "/elasticPools/pool1";
        var r = SqlRatingService.Rate(db, PerfectServer());
        Assert.Contains(r.Improvements, i => i.Action.Contains("elastic pool 'pool1'") && i.PointsGained == 4);
    }

    [Fact]
    public void UnknownServer_PartialPointsEverywhere_NoCaps()
    {
        var r = SqlRatingService.Rate(PerfectDatabase(), null);
        Assert.Null(r.CapReason);
        Assert.Equal(8, Cat(r, SqlRatingService.NetworkCategory).Earned);
        Assert.Equal(5, Cat(r, SqlRatingService.IdentityCategory).Earned);
        Assert.Equal(7, Cat(r, SqlRatingService.ThreatCategory).Earned);
        Assert.Equal(8, Cat(r, SqlRatingService.EncryptionCategory).Earned); // TDE 7 + TLS unknown 1
    }

    [Fact]
    public void ManagedInstance_WeightsShiftToDefenderAndVa_TdeAlwaysOn()
    {
        var mi = new SqlServerInfo
        {
            Id = MiId, Name = "mi1", SubscriptionId = "s1", Kind = SqlFlowKind.ManagedInstance, Location = "westeurope",
            PublicNetworkAccess = true, MinimalTlsVersion = "1.2", EntraAdminLogin = "admins@contoso.com", EntraOnlyAuthentication = true,
            DefenderEnabled = true, VulnerabilityAssessmentEnabled = false, Tier = "GeneralPurpose", ZoneRedundant = false, BackupStorageRedundancy = "Geo"
        };
        var db = new SqlDatabaseInfo
        {
            Id = MiDbId, Name = "db1", ServerId = MiId, ServerName = "mi1", SubscriptionId = "s1", Kind = SqlFlowKind.ManagedInstance,
            Tier = "GeneralPurpose", BackupStorageRedundancy = "Geo", PitrRetentionDays = 35, LtrRead = true,
            WeeklyRetention = "P12W", MonthlyRetention = "P12M", YearlyRetention = "P7Y", TdeEnabled = true
        };

        var r = SqlRatingService.Rate(db, mi);

        Assert.Equal(6, Cat(r, SqlRatingService.NetworkCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("public data endpoint") && i.PointsGained == 9);
        Assert.Equal(9, Cat(r, SqlRatingService.ThreatCategory).Earned); // Defender 9, VA 0, no auditing item
        Assert.Contains(r.Improvements, i => i.Action.Contains("vulnerability assessment") && i.PointsGained == 6);
        Assert.Equal(10, Cat(r, SqlRatingService.EncryptionCategory).Earned);
        Assert.Equal(0, Cat(r, SqlRatingService.ResilienceCategory).Earned);
        Assert.Contains(r.Improvements, i => i.Action.Contains("instance failover group") && i.PointsGained == 6);
        Assert.Contains(r.Improvements, i => i.Action.Contains("zone redundancy on 'mi1'") && i.PointsGained == 4);
    }

    [Fact]
    public void Improvements_SortedByPoints_AndEveryActionHasAResultingGrade()
    {
        var db = PerfectDatabase();
        db.PitrRetentionDays = 7; db.WeeklyRetention = "PT0S"; db.MonthlyRetention = "PT0S"; db.YearlyRetention = "PT0S"; db.BackupStorageRedundancy = "Local";
        var r = SqlRatingService.Rate(db, PerfectServer());
        var points = r.Improvements.Select(i => i.PointsGained).ToList();
        Assert.Equal(points.OrderByDescending(p => p), points);
        Assert.All(r.Improvements, i => Assert.Matches("^[A-F]$", i.ResultingGrade));
        Assert.All(r.Improvements, i => Assert.True(i.Area is RatingArea.Security or RatingArea.Backups));
    }

    [Fact]
    public void RateAll_SkipsGeoSecondariesAndDataWarehouses()
    {
        var scan = new SqlScanResult { Flow = SqlFlowKind.SqlDatabase, Servers = [PerfectServer()] };
        var primary = PerfectDatabase();
        var secondary = PerfectDatabase();
        secondary.Id = ServerId + "/databases/db1-dr"; secondary.Name = "db1-dr";
        secondary.GeoReplicas = [new() { Role = "Secondary", PartnerServer = "srv0" }];
        var dw = PerfectDatabase();
        dw.Id = ServerId + "/databases/dw"; dw.Name = "dw"; dw.Tier = "DataWarehouse";
        scan.Databases = [primary, secondary, dw];

        SqlRatingService.RateAll(scan);

        Assert.Single(scan.Ratings);
        Assert.Equal("db1", scan.Ratings[0].TargetName);
    }

    [Theory]
    [InlineData(100, "A")] [InlineData(90, "A")] [InlineData(89, "B")] [InlineData(75, "B")] [InlineData(74, "C")]
    [InlineData(60, "C")] [InlineData(59, "D")] [InlineData(45, "D")] [InlineData(44, "E")] [InlineData(30, "E")] [InlineData(29, "F")] [InlineData(0, "F")]
    public void GradeBands(int score, string grade) => Assert.Equal(grade, SqlRatingService.GradeForScore(score));

    [Fact]
    public void WorstGrade_AndWorst_PickTheWeakest()
    {
        Assert.Equal("D", SqlRatingService.WorstGrade("B", "D"));
        Assert.Equal("D", SqlRatingService.WorstGrade("D", "B"));
        var worst = SqlRatingService.Worst([new SqlRating { Grade = "B", Score = 80 }, new SqlRating { Grade = "C", Score = 70, TargetName = "weak" }, new SqlRating { Grade = "C", Score = 65, TargetName = "weakest" }]);
        Assert.Equal("weakest", worst!.TargetName);
    }
}
