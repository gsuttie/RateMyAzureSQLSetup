namespace RateMyAzureSql.Models;

public sealed class SubscriptionInfo
{
    public string SubscriptionId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
}

public sealed class TenantInfo
{
    public string TenantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DefaultDomain { get; set; } = string.Empty;

    public string BestName => string.IsNullOrWhiteSpace(DisplayName) ? TenantId : DisplayName;
}

/// <summary>Which of the two product flows the user is in.</summary>
public enum SqlFlowKind { SqlDatabase, ManagedInstance }

public static class SqlFlowKindExtensions
{
    /// <summary>The product: "SQL Database" or "Managed Instance".</summary>
    public static string Label(this SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? "SQL Database" : "Managed Instance";
    public static string PluralLabel(this SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? "SQL Databases" : "Managed Instances";
    public static string Route(this SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? "sql-database" : "managed-instance";

    /// <summary>The thing that hosts databases: "logical server" or "managed instance".</summary>
    public static string HostLabel(this SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? "logical server" : "managed instance";
    public static string HostPluralLabel(this SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? "logical servers" : "managed instances";
}

/// <summary>Counts of flow-relevant resources in one subscription (from Azure Resource Graph).</summary>
public sealed class SqlSubscriptionSummary
{
    public string SubscriptionId { get; set; } = string.Empty;
    public int ServerCount { get; set; }
    public int DatabaseCount { get; set; }
    public int ManagedInstanceCount { get; set; }
    public int ManagedDatabaseCount { get; set; }

    public int HostCount(SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? ServerCount : ManagedInstanceCount;
    public int DbCount(SqlFlowKind kind) => kind == SqlFlowKind.SqlDatabase ? DatabaseCount : ManagedDatabaseCount;
    public bool IsRelevant(SqlFlowKind kind) => HostCount(kind) + DbCount(kind) > 0;
}
