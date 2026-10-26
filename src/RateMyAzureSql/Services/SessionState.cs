using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>Everything one flow (SQL Database or Managed Instance) remembers while the user moves between steps.</summary>
public sealed class FlowState
{
    public SqlFlowKind Flow { get; }
    public FlowState(SqlFlowKind flow) => Flow = flow;

    public HashSet<string> SelectedSubscriptionIds { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? SelectedTenantId { get; set; }

    public SqlScanResult? Scan { get; set; }
    public string? ScanError { get; set; }

    /// <summary>Long-term retention backups listed on demand in the Backups step, keyed by database ID.</summary>
    public Dictionary<string, List<LtrBackupInfo>> LtrBackups { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool HasScan => Scan is not null;
}

/// <summary>
/// Per-circuit (scoped) state: subscriptions loaded once, plus independent state for each flow so a
/// user can rate their SQL Databases and Managed Instances side by side without one flow resetting the other.
/// </summary>
public sealed class SessionState
{
    private readonly AzureSubscriptionService _subscriptions;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private bool _loaded;

    public SessionState(AzureSubscriptionService subscriptions)
    {
        _subscriptions = subscriptions;
        Flows = new Dictionary<SqlFlowKind, FlowState>
        {
            [SqlFlowKind.SqlDatabase] = new(SqlFlowKind.SqlDatabase),
            [SqlFlowKind.ManagedInstance] = new(SqlFlowKind.ManagedInstance),
        };
    }

    public IReadOnlyDictionary<SqlFlowKind, FlowState> Flows { get; }
    public FlowState For(SqlFlowKind flow) => Flows[flow];

    public List<SubscriptionInfo> Subscriptions { get; private set; } = new();
    public Dictionary<string, TenantInfo> Tenants { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? LoadError { get; private set; }
    public bool IsLoaded => _loaded;

    private bool _demoMode;

    /// <summary>True when the app runs on built-in sample data instead of Azure.</summary>
    public bool DemoMode
    {
        get => _demoMode;
        set
        {
            if (_demoMode == value) return;
            _demoMode = value;
            Changed?.Invoke();
        }
    }

    /// <summary>Raised when session-wide state (sample-data mode) changes, so the layout can re-render.</summary>
    public event Action? Changed;

    public async Task EnsureLoadedAsync(bool force = false, CancellationToken ct = default)
    {
        if (_loaded && !force) return;
        await _loadLock.WaitAsync(ct);
        try
        {
            if (_loaded && !force) return;
            LoadError = null;
            if (force) _subscriptions.Reset();
            try
            {
                Subscriptions = await _subscriptions.GetSubscriptionsAsync(ct);
                Tenants = await _subscriptions.GetTenantsAsync(ct);
                if (Subscriptions.Count == 0)
                    LoadError = "No subscriptions are visible to the current credential. Run 'az login' and make sure the account has Reader access.";
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Subscriptions = new();
                LoadError = "Could not list subscriptions. Run 'az login' (optionally with --tenant <id>) in a terminal, then retry. Details: " + ex.Message;
            }
            _loaded = true;
        }
        finally
        {
            _loadLock.Release();
        }
    }

    public string TenantName(string tenantId) =>
        Tenants.TryGetValue(tenantId, out var t) ? t.BestName : tenantId;

    public string SubscriptionName(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.DisplayName
        ?? subscriptionId;

    public IEnumerable<string> DistinctTenantIds() =>
        Subscriptions.Select(s => s.TenantId).Where(t => !string.IsNullOrEmpty(t)).Distinct(StringComparer.OrdinalIgnoreCase);
}
