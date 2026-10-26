using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>
/// Orchestrates one flow's steps against either Azure or the built-in demo estate, so the UI never
/// has to know which one it is talking to.
/// </summary>
public sealed class SqlFlowService
{
    private readonly SessionState _state;
    private readonly SqlDiscoveryService _discovery;

    public SqlFlowService(SessionState state, SqlDiscoveryService discovery)
    {
        _state = state;
        _discovery = discovery;
    }

    public SessionState State => _state;

    public IReadOnlyList<SubscriptionInfo> Subscriptions =>
        _state.DemoMode ? DemoDataService.Subscriptions() : _state.Subscriptions;

    public string TenantName(string tenantId) =>
        _state.DemoMode ? DemoDataService.Tenants()[DemoDataService.TenantId].BestName : _state.TenantName(tenantId);

    public string SubscriptionName(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.DisplayName ?? subscriptionId;

    public Task LoadSubscriptionsAsync(bool force = false, CancellationToken ct = default) =>
        _state.DemoMode ? Task.CompletedTask : _state.EnsureLoadedAsync(force, ct);

    public void EnterDemoMode()
    {
        _state.DemoMode = true;
        foreach (var flow in _state.Flows.Values)
        {
            flow.Scan = null;
            flow.ScanError = null;
            flow.LtrBackups.Clear();
            flow.SelectedSubscriptionIds.Clear();
            flow.SelectedTenantId = DemoDataService.TenantId;
        }
    }

    public void ExitDemoMode()
    {
        _state.DemoMode = false;
        foreach (var flow in _state.Flows.Values)
        {
            flow.Scan = null;
            flow.ScanError = null;
            flow.LtrBackups.Clear();
            flow.SelectedSubscriptionIds.Clear();
            flow.SelectedTenantId = null;
        }
    }

    public Task<Dictionary<string, SqlSubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) =>
        _state.DemoMode
            ? Task.FromResult(DemoDataService.Summaries())
            : _discovery.GetSummariesAsync(subscriptionIds, tenantId, ct);

    public async Task<SqlScanResult> ScanAsync(SqlFlowKind flow, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var fs = _state.For(flow);
        var ids = fs.SelectedSubscriptionIds.ToList();
        SqlScanResult result;

        if (_state.DemoMode)
        {
            progress?.Report("Loading sample estate…");
            await Task.Delay(600, ct);
            result = DemoDataService.Scan(flow, ids);
        }
        else
        {
            // Selections normally live in one tenant, but group defensively.
            var groups = Subscriptions
                .Where(s => fs.SelectedSubscriptionIds.Contains(s.SubscriptionId))
                .GroupBy(s => s.TenantId, StringComparer.OrdinalIgnoreCase)
                .ToList();
            result = new SqlScanResult { Flow = flow };
            foreach (var g in groups)
                result.Merge(await _discovery.ScanAsync(flow, g.Select(s => s.SubscriptionId).ToList(), g.Key, progress, ct));
            result.CompletedAt = DateTime.Now;
        }

        fs.Scan = result;
        fs.ScanError = null;
        fs.LtrBackups.Clear();
        return result;
    }

    public string? TenantOf(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.TenantId;

    /// <summary>Lists the long-term retention backups that exist for a database and caches them on the flow state.</summary>
    public async Task<List<LtrBackupInfo>> GetLtrBackupsAsync(SqlFlowKind flow, SqlDatabaseInfo db, CancellationToken ct = default)
    {
        var fs = _state.For(flow);
        if (fs.LtrBackups.TryGetValue(db.Id, out var cached)) return cached;

        List<LtrBackupInfo> backups;
        if (_state.DemoMode)
        {
            await Task.Delay(400, ct);
            backups = DemoDataService.LtrBackups(db);
        }
        else
        {
            backups = await _discovery.GetLtrBackupsAsync(db, TenantOf(db.SubscriptionId) ?? fs.SelectedTenantId, ct);
        }
        fs.LtrBackups[db.Id] = backups;
        return backups;
    }

    public SqlReportContext ReportContext(SqlFlowKind flow)
    {
        var fs = _state.For(flow);
        var subs = Subscriptions.Where(s => fs.SelectedSubscriptionIds.Contains(s.SubscriptionId))
            .OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        var tenantId = subs.Select(s => s.TenantId).FirstOrDefault(t => !string.IsNullOrEmpty(t)) ?? fs.SelectedTenantId ?? "";
        var tenantName = string.IsNullOrEmpty(tenantId) ? "" : TenantName(tenantId);
        return new SqlReportContext
        {
            Flow = flow,
            CustomerName = tenantName,
            TenantName = tenantName,
            ReportAuthor = Environment.UserName,
            ScanDate = fs.Scan?.CompletedAt ?? DateTime.Now,
            SubscriptionLines = subs.Select(s => $"{s.DisplayName} ({s.SubscriptionId})").ToList(),
            Scan = fs.Scan
        };
    }
}
