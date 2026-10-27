using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using RateMyAzureSql.Models;
using RateMyAzureSql.Services;
using RateMyAzureSql.Services.Azure;
using Xunit;

namespace RateMyAzureSql.Tests;

/// <summary>Parsing of the Azure JSON shapes (as returned by Resource Graph and ARM) into the estate model.</summary>
public class SqlDiscoveryParsingTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void ParseServer_ReadsNetworkIdentityAndPrivateEndpoints()
    {
        var row = J("""
        {
          "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1",
          "name": "srv1", "location": "westeurope", "resourceGroup": "rg", "subscriptionId": "s1", "kind": "v12.0",
          "properties": {
            "administratorLogin": "sqladmin", "fullyQualifiedDomainName": "srv1.database.windows.net", "minimalTlsVersion": "1.2",
            "publicNetworkAccess": "Enabled",
            "privateEndpointConnections": [
              { "properties": { "privateLinkServiceConnectionState": { "status": "Approved" } } },
              { "properties": { "privateLinkServiceConnectionState": { "status": "Rejected" } } }
            ],
            "administrators": { "administratorType": "ActiveDirectory", "principalType": "Group", "login": "sql-admins", "azureADOnlyAuthentication": true }
          }
        }
        """);

        var s = SqlDiscoveryService.ParseServer(row);

        Assert.Equal("srv1", s.Name);
        Assert.Equal(SqlFlowKind.SqlDatabase, s.Kind);
        Assert.Equal("srv1.database.windows.net", s.Fqdn);
        Assert.True(s.PublicNetworkAccess);
        Assert.Equal(1, s.PrivateEndpointCount);
        Assert.Equal("1.2", s.MinimalTlsVersion);
        Assert.Equal("sqladmin", s.SqlAdminLogin);
        Assert.Equal("sql-admins", s.EntraAdminLogin);
        Assert.Equal("Group", s.EntraAdminType);
        Assert.True(s.EntraOnlyAuthentication);
    }

    [Fact]
    public void ParseServer_MissingPublicAccessMeansEnabled_DisabledParses()
    {
        var s = SqlDiscoveryService.ParseServer(J("""{ "id": "/x/servers/a", "name": "a", "properties": { } }"""));
        Assert.True(s.PublicNetworkAccess);
        Assert.False(s.HasEntraAdmin);
        Assert.Null(s.EntraOnlyAuthentication);

        s = SqlDiscoveryService.ParseServer(J("""{ "id": "/x/servers/a", "name": "a", "properties": { "publicNetworkAccess": "Disabled" } }"""));
        Assert.False(s.PublicNetworkAccess);
    }

    [Fact]
    public void ParseDatabase_ReadsSkuBackupRedundancyPoolAndDates()
    {
        var row = J("""
        {
          "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1/databases/orders",
          "name": "orders", "location": "westeurope", "resourceGroup": "rg", "subscriptionId": "s1", "kind": "v12.0,user,vcore,pool",
          "sku": { "name": "ElasticPool", "tier": "GeneralPurpose", "capacity": 0 },
          "properties": {
            "status": "Online", "currentServiceObjectiveName": "ElasticPool", "zoneRedundant": false, "maxSizeBytes": 34359738368,
            "currentBackupStorageRedundancy": "Geo", "requestedBackupStorageRedundancy": "Zone",
            "earliestRestoreDate": "2026-10-19T09:35:58.7595591Z", "creationDate": "2026-08-24T10:38:02.35Z",
            "elasticPoolId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1/elasticPools/pool1",
            "isLedgerOn": false
          }
        }
        """);

        var d = SqlDiscoveryService.ParseDatabase(row);

        Assert.Equal("orders", d.Name);
        Assert.Equal("/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1", d.ServerId);
        Assert.Equal("srv1", d.ServerName);
        Assert.Equal("GeneralPurpose", d.Tier);
        Assert.Equal("ElasticPool", d.SkuName);
        Assert.Equal("pool1", d.ElasticPoolName);
        Assert.Equal("Geo", d.BackupStorageRedundancy); // current wins over requested
        Assert.Equal(new DateTime(2026, 10, 19, 9, 35, 58, DateTimeKind.Utc).Date, d.EarliestRestoreDate!.Value.Date);
        Assert.Equal(32L * 1024 * 1024 * 1024, d.MaxSizeBytes);
        Assert.Equal("32 GB", d.MaxSizeLabel);
        Assert.False(d.IsServerless);
        Assert.Equal("General Purpose (pool)", d.TierLabel);
    }

    [Fact]
    public void ParseDatabase_ServerlessKindAndBasicTier()
    {
        var d = SqlDiscoveryService.ParseDatabase(J("""{ "id": "/s/servers/a/databases/b", "name": "b", "kind": "v12.0,user,vcore,serverless", "sku": { "name": "GP_S_Gen5", "tier": "GeneralPurpose" }, "properties": {} }"""));
        Assert.True(d.IsServerless);
        Assert.Equal("General Purpose (serverless)", d.TierLabel);
        Assert.Equal(35, d.MaxPitrDays);

        var basic = SqlDiscoveryService.ParseDatabase(J("""{ "id": "/s/servers/a/databases/c", "name": "c", "kind": "v12.0,user", "sku": { "name": "Basic", "tier": "Basic" }, "properties": {} }"""));
        Assert.True(basic.IsBasicTier);
        Assert.Equal(7, basic.MaxPitrDays);
        Assert.False(basic.SupportsZoneRedundancy);
    }

    [Fact]
    public void ParseManagedInstance_ReadsEndpointTierRedundancyAndStorageAccountTypeAlias()
    {
        var row = J("""
        {
          "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/mi1",
          "name": "mi1", "location": "westeurope", "resourceGroup": "rg", "subscriptionId": "s1",
          "sku": { "name": "GP_Gen5", "tier": "GeneralPurpose" },
          "properties": {
            "fullyQualifiedDomainName": "mi1.abc.database.windows.net", "administratorLogin": "miadmin",
            "publicDataEndpointEnabled": true, "minimalTlsVersion": "1.2", "subnetId": "/vnet/subnets/snet", "vCores": 8,
            "zoneRedundant": true, "storageAccountType": "GZRS",
            "administrators": { "administratorType": "ActiveDirectory", "principalType": "User", "login": "admin@contoso.com", "azureADOnlyAuthentication": false }
          }
        }
        """);

        var mi = SqlDiscoveryService.ParseManagedInstance(row);

        Assert.Equal(SqlFlowKind.ManagedInstance, mi.Kind);
        Assert.True(mi.PublicNetworkAccess);
        Assert.Equal("GeneralPurpose", mi.Tier);
        Assert.Equal(8, mi.VCores);
        Assert.True(mi.ZoneRedundant);
        Assert.Equal("GeoZone", mi.BackupStorageRedundancy);
        Assert.Equal("admin@contoso.com", mi.EntraAdminLogin);
        Assert.False(mi.EntraOnlyAuthentication);
    }

    [Theory]
    [InlineData("GRS", "Geo")] [InlineData("LRS", "Local")] [InlineData("ZRS", "Zone")] [InlineData("GZRS", "GeoZone")]
    [InlineData("Geo", "Geo")] [InlineData("local", "Local")] [InlineData("", "")]
    public void NormaliseRedundancy(string input, string expected) => Assert.Equal(expected, SqlDiscoveryService.NormaliseRedundancy(input));

    [Fact]
    public void ParseFirewallRule_ClassifiesSpecialRules()
    {
        var open = SqlDiscoveryService.ParseFirewallRule(J("""{ "name": "AllowAll", "properties": { "startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255" } }"""));
        Assert.True(open.IsOpenToInternet);
        Assert.False(open.IsAllowAzureServices);
        Assert.False(open.IsBroad);

        var azure = SqlDiscoveryService.ParseFirewallRule(J("""{ "name": "AllowAllWindowsAzureIps", "properties": { "startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0" } }"""));
        Assert.True(azure.IsAllowAzureServices);
        Assert.Equal(1, azure.AddressCount);

        var broad = SqlDiscoveryService.ParseFirewallRule(J("""{ "name": "Office", "properties": { "startIpAddress": "81.145.0.0", "endIpAddress": "81.145.255.255" } }"""));
        Assert.True(broad.IsBroad);
        Assert.Equal(65536, broad.AddressCount);

        var single = SqlDiscoveryService.ParseFirewallRule(J("""{ "name": "Home", "properties": { "startIpAddress": "85.246.209.201", "endIpAddress": "85.246.209.201" } }"""));
        Assert.False(single.IsBroad);
        Assert.Equal("85.246.209.201", single.Display);

        var slash24 = SqlDiscoveryService.ParseFirewallRule(J("""{ "name": "Branch", "properties": { "startIpAddress": "10.1.2.0", "endIpAddress": "10.1.2.255" } }"""));
        Assert.False(slash24.IsBroad); // exactly 256 is not "broad"
    }

    [Fact]
    public void ParseFailoverGroup_ReadsPartnerPolicyAndDatabases()
    {
        var g = SqlDiscoveryService.ParseFailoverGroup(J("""
        {
          "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1/failoverGroups/fog1", "name": "fog1",
          "properties": {
            "readWriteEndpoint": { "failoverPolicy": "Automatic", "failoverWithDataLossGracePeriodMinutes": 60 },
            "replicationRole": "Primary",
            "partnerServers": [ { "id": "/subscriptions/s1/resourceGroups/rg-dr/providers/Microsoft.Sql/servers/srv1-dr", "location": "North Europe", "replicationRole": "Secondary" } ],
            "databases": [ "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1/databases/orders" ]
          }
        }
        """));
        Assert.Equal("fog1", g.Name);
        Assert.Equal("srv1-dr", g.PartnerServer);
        Assert.Equal("North Europe", g.PartnerLocation);
        Assert.Equal("Automatic", g.FailoverPolicy);
        Assert.Equal(60, g.GracePeriodMinutes);
        Assert.Equal("Primary", g.ReplicationRole);
        Assert.Single(g.DatabaseIds);
    }

    [Fact]
    public void LinkFailoverGroups_AttachesDatabasesCaseInsensitively()
    {
        var serverId = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/servers/srv1";
        var scan = new SqlScanResult
        {
            Servers = [new() { Id = serverId, Name = "srv1", FailoverGroups = [new() { Name = "fog1", DatabaseIds = [serverId.ToUpperInvariant() + "/DATABASES/ORDERS"] }] }],
            Databases = [new() { Id = serverId + "/databases/orders", Name = "orders", ServerId = serverId }, new() { Id = serverId + "/databases/other", Name = "other", ServerId = serverId }]
        };
        SqlDiscoveryService.LinkFailoverGroups(scan);
        Assert.Equal("fog1", scan.Databases[0].FailoverGroupName);
        Assert.Null(scan.Databases[1].FailoverGroupName);
    }

    [Fact]
    public void ParseReplicationLink_AndGeoSecondaryDetection()
    {
        var link = SqlDiscoveryService.ParseReplicationLink(J("""{ "properties": { "partnerServer": "srv0", "partnerLocation": "West Europe", "partnerDatabase": "orders", "role": "Secondary", "replicationState": "CATCH_UP" } }"""));
        Assert.Equal("Secondary", link.Role);
        var db = new SqlDatabaseInfo { GeoReplicas = [link] };
        Assert.True(db.IsGeoSecondary);
        Assert.True(db.HasGeoReplica);
    }

    [Fact]
    public void ApplyLtr_ParsesDurationsAndLabels()
    {
        var db = new SqlDatabaseInfo();
        SqlDiscoveryService.ApplyLtr(db, J("""{ "weeklyRetention": "P12W", "monthlyRetention": "PT0S", "yearlyRetention": "P5Y", "weekOfYear": 1 }"""));
        Assert.True(db.LtrRead);
        Assert.True(db.HasWeeklyLtr);
        Assert.False(db.HasMonthlyLtr);
        Assert.True(db.HasYearlyLtr);
        Assert.Equal("12 weeks", SqlDatabaseInfo.DurationLabel("P12W"));
        Assert.Equal("1 year", SqlDatabaseInfo.DurationLabel("P1Y"));
        Assert.Equal("none", SqlDatabaseInfo.DurationLabel("PT0S"));
        Assert.Equal("weekly × 12 weeks, yearly × 5 years", BackupPlanService.LtrLabel("P12W", "PT0S", "P5Y"));

        var none = new SqlDatabaseInfo();
        SqlDiscoveryService.ApplyLtr(none, default);
        Assert.False(none.LtrRead);
    }

    [Fact]
    public void ParseDefender_ServerPolicyOrSubscriptionPlan()
    {
        var enabled = J("""{ "properties": { "state": "Enabled" } }""");
        var disabled = J("""{ "properties": { "state": "Disabled" } }""");
        Assert.True(SqlDiscoveryService.ParseDefender(enabled, null));
        Assert.False(SqlDiscoveryService.ParseDefender(disabled, false));
        Assert.True(SqlDiscoveryService.ParseDefender(disabled, true));
        Assert.Null(SqlDiscoveryService.ParseDefender(null, null));
        Assert.True(SqlDiscoveryService.ParseDefender(null, true));
    }

    [Fact]
    public void ParseAuditDiagnostics_FindsAuditCategoryDestinations()
    {
        var settings = new List<JsonElement>
        {
            J("""{ "properties": { "workspaceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law1", "logs": [ { "category": "SQLSecurityAuditEvents", "enabled": true } ] } }"""),
            J("""{ "properties": { "storageAccountId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stlogs", "logs": [ { "category": "SQLSecurityAuditEvents", "enabled": false } ] } }"""),
            J("""{ "properties": { "eventHubAuthorizationRuleId": "/x/authorizationRules/RootManageSharedAccessKey", "eventHubName": "audit", "logs": [ { "categoryGroup": "audit", "enabled": true } ] } }"""),
        };
        var dests = SqlDiscoveryService.ParseAuditDiagnostics(settings);
        Assert.Equal(["Log Analytics: law1", "Event Hub: audit"], dests);
    }

    [Fact]
    public void ParseLtrBackup_ReadsTimes()
    {
        var b = SqlDiscoveryService.ParseLtrBackup(J("""{ "name": "orders,132...", "properties": { "backupTime": "2026-10-05T03:12:00Z", "backupExpirationTime": "2027-01-05T03:12:00Z", "backupStorageRedundancy": "Geo" } }"""));
        Assert.Equal(new DateTime(2026, 10, 5, 3, 12, 0), b.BackupTime);
        Assert.Equal(new DateTime(2027, 1, 5, 3, 12, 0), b.ExpirationTime);
        Assert.Equal("Geo", b.StorageRedundancy);
    }

    [Theory]
    [InlineData("rg-restore-tests", "/subscriptions/s1/resourceGroups/rg-restore-tests/providers/Microsoft.Sql/servers/srv1", true)]
    [InlineData("rg-prod", "/subscriptions/s1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/srv-RESTORE-01", true)]
    [InlineData("rg-prod", "/subscriptions/s1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/srv1/databases/orders_restored", true)]
    [InlineData("rg-prod", "/subscriptions/s1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/srv1/databases/orders", false)]
    [InlineData(null, null, false)]
    public void IsExcluded_SkipsResourceGroupsAndResourcesNamedRestore(string? resourceGroup, string? id, bool expected)
    {
        Assert.Equal(expected, SqlDiscoveryService.IsExcluded(resourceGroup, id));
    }

    [Fact]
    public void RetryDelay_HonoursRetryAfterHeaderAndCapsBackoff()
    {
        using var throttled = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        throttled.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(10));
        Assert.Equal(TimeSpan.FromSeconds(10), AzureApi.RetryDelay(0, throttled));

        var noHeader = AzureApi.RetryDelay(2, null);
        Assert.InRange(noHeader.TotalSeconds, 4, 5);

        Assert.Equal(TimeSpan.FromSeconds(60), AzureApi.RetryDelay(20, null));

        Assert.True(AzureApi.IsRetryable(HttpStatusCode.TooManyRequests));
        Assert.True(AzureApi.IsRetryable(HttpStatusCode.ServiceUnavailable));
        Assert.False(AzureApi.IsRetryable(HttpStatusCode.Forbidden));
        Assert.False(AzureApi.IsRetryable(HttpStatusCode.NotFound));
    }
}
