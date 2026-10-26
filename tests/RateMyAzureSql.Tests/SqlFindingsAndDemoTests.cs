using RateMyAzureSql.Models;
using RateMyAzureSql.Services;
using Xunit;

namespace RateMyAzureSql.Tests;

/// <summary>Findings, and the sample estate as an end-to-end reference (every grade band, expected findings).</summary>
public class SqlFindingsAndDemoTests
{
    private static SqlScanResult SqlDbDemo() => DemoDataService.Scan(SqlFlowKind.SqlDatabase, [DemoDataService.SubProd, DemoDataService.SubShared]);
    private static SqlScanResult MiDemo() => DemoDataService.Scan(SqlFlowKind.ManagedInstance, [DemoDataService.SubProd, DemoDataService.SubShared]);

    [Fact]
    public void SqlDatabaseDemo_CoversEveryGradeBand()
    {
        var scan = SqlDbDemo();
        var grades = scan.Ratings.ToDictionary(r => r.TargetName, r => (r.Grade, r.Score));

        Assert.Equal(3, scan.Servers.Count);
        Assert.Equal(8, scan.Databases.Count);
        Assert.Equal(7, scan.Ratings.Count); // the data warehouse is not rated
        Assert.Equal(("A", 100), grades["contoso-orders"]);
        Assert.Equal(("B", 76), grades["contoso-crm"]);
        Assert.Equal(("C", 73), grades["intranet"]);
        Assert.Equal(("D", 52), grades["hr-portal"]);
        Assert.Equal(("D", 49), grades["basic-sandbox"]);
        Assert.Equal(("E", 33), grades["reporting"]);
        Assert.Equal(("F", 8), grades["legacyapp"]);
        Assert.Equal("legacyapp", SqlRatingService.Worst(scan.Ratings)!.TargetName);
        Assert.Equal(["A", "B", "C", "D", "E", "F"], scan.Ratings.Select(r => r.Grade).Distinct().OrderBy(g => g).ToList());
    }

    [Fact]
    public void SqlDatabaseDemo_ProducesTheExpectedFindings()
    {
        var f = SqlDbDemo().Findings;

        Assert.Contains(f, x => x.Severity == "High" && x.Category == "Open to the internet" && x.ResourceName == "sql-contoso-legacy");
        Assert.Contains(f, x => x.Severity == "High" && x.Category == "Defender disabled");
        Assert.Contains(f, x => x.Severity == "High" && x.Category == "TDE disabled" && x.ResourceName == "sql-contoso-legacy/legacyapp");
        Assert.Equal(2, f.Count(x => x.Category == "Local backup storage"));
        Assert.Contains(f, x => x.Severity == "Medium" && x.Category == "Allow Azure services" && x.ResourceName == "sql-contoso-shared");
        Assert.Contains(f, x => x.Severity == "Medium" && x.Category == "No Entra admin");
        Assert.Contains(f, x => x.Severity == "Medium" && x.Category == "Weak TLS");
        Assert.Contains(f, x => x.Severity == "Medium" && x.Category == "Vulnerability assessment off");
        Assert.Contains(f, x => x.Category == "Data warehouse not rated" && x.ResourceName == "sql-contoso-shared/analytics-dw");
        Assert.Contains(f, x => x.Category == "Basic tier limits");
        Assert.Contains(f, x => x.Category == "Broad firewall rule" && x.Message.Contains("65,536"));
        Assert.All(f, x => Assert.False(string.IsNullOrWhiteSpace(x.Fix)));
        Assert.All(f, x => Assert.True(x.Area is RatingArea.Security or RatingArea.Backups));

        // Ordered High → Medium → Info.
        var order = f.Select(x => SqlFindingsBuilder.SeverityOrder(x.Severity)).ToList();
        Assert.Equal(order.OrderBy(o => o), order);
    }

    [Fact]
    public void ManagedInstanceDemo_GradesAndFindings()
    {
        var scan = MiDemo();
        var grades = scan.Ratings.ToDictionary(r => r.TargetName, r => (r.Grade, r.Score));

        Assert.Equal(2, scan.Servers.Count);
        Assert.Equal(3, scan.Ratings.Count);
        Assert.Equal(("A", 100), grades["erp"]);
        Assert.Equal(("B", 78), grades["erp-staging"]);
        Assert.Equal(("F", 21), grades["devdb"]);

        var f = scan.Findings;
        Assert.Contains(f, x => x.Category == "Public data endpoint" && x.ResourceName == "mi-contoso-dev");
        Assert.Contains(f, x => x.Category == "Defender disabled" && x.ResourceName == "mi-contoso-dev");
        Assert.Contains(f, x => x.Category == "Local backup storage" && x.ResourceName == "mi-contoso-dev/devdb");
        Assert.DoesNotContain(f, x => x.Category == "Auditing disabled"); // not assessed for managed instances
        Assert.DoesNotContain(f, x => x.Category == "Open to the internet");
    }

    [Fact]
    public void Demo_FiltersBySubscription()
    {
        var prodOnly = DemoDataService.Scan(SqlFlowKind.SqlDatabase, [DemoDataService.SubProd]);
        Assert.Equal(2, prodOnly.Servers.Count);
        Assert.All(prodOnly.Databases, d => Assert.Equal(DemoDataService.SubProd, d.SubscriptionId));
        Assert.All(prodOnly.Findings, f => Assert.Equal(DemoDataService.SubProd, f.SubscriptionId));
    }

    [Fact]
    public void GeoSecondary_IsReportedNotRated()
    {
        var scan = SqlDbDemo();
        var secondary = scan.Databases.First(d => d.Name == "contoso-crm");
        secondary.GeoReplicas = [new() { Role = "Secondary", PartnerServer = "sql-contoso-prod-dr" }];
        SqlDiscoveryService.Finalize(scan);
        Assert.DoesNotContain(scan.Ratings, r => r.TargetName == "contoso-crm");
        Assert.Contains(scan.Findings, f => f.Category == "Geo-secondary not rated" && f.ResourceName.EndsWith("contoso-crm"));
    }

    [Fact]
    public void Summaries_MatchTheEstate()
    {
        var s = DemoDataService.Summaries();
        Assert.True(s[DemoDataService.SubProd].IsRelevant(SqlFlowKind.SqlDatabase));
        Assert.True(s[DemoDataService.SubShared].IsRelevant(SqlFlowKind.ManagedInstance));
        Assert.Equal(2, s[DemoDataService.SubProd].HostCount(SqlFlowKind.SqlDatabase));
    }

    [Fact]
    public void LtrBackups_FollowThePolicy()
    {
        var scan = SqlDbDemo();
        Assert.NotEmpty(DemoDataService.LtrBackups(scan.Database(scan.Ratings.First(r => r.TargetName == "contoso-orders").TargetId)!));
        Assert.Empty(DemoDataService.LtrBackups(scan.Database(scan.Ratings.First(r => r.TargetName == "legacyapp").TargetId)!));
    }

    [Fact]
    public void FixFor_UnknownCategory_HasGenericGuidance()
    {
        Assert.Contains("Azure Portal", SqlFindingsBuilder.FixFor("Something new"));
        Assert.All(SqlFindingsBuilder.FixByCategory.Values, v => Assert.True(v.Length > 40));
    }
}
