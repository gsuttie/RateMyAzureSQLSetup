using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyAzureSql.Components.Shared;
using RateMyAzureSql.Models;
using RateMyAzureSql.Services;
using RateMyAzureSql.Services.Azure;
using System.Text.Json;
using Xunit;

namespace RateMyAzureSql.Tests;

/// <summary>Rendering tests for the UI components, driven by the sample estate (no Azure).</summary>
public class ComponentTests : BunitContext
{
    /// <summary>An IAzureApi that must never be called: the demo mode keeps everything local.</summary>
    private sealed class ThrowingAzureApi : IAzureApi
    {
        public Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
        public Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
        public Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default) => throw new InvalidOperationException("Azure must not be called in demo mode");
    }

    private SqlFlowService Flows { get; }

    public ComponentTests()
    {
        var credential = new global::Azure.Identity.AzureCliCredential();
        Services.AddSingleton<global::Azure.Core.TokenCredential>(credential);
        Services.AddSingleton<IAzureApi, ThrowingAzureApi>();
        Services.AddSingleton(new SqlDiscoveryService(new ThrowingAzureApi(), NullLogger<SqlDiscoveryService>.Instance));
        Services.AddScoped(_ => new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance));
        Services.AddScoped<SessionState>();
        Services.AddScoped<SqlFlowService>();
        JSInterop.Mode = JSRuntimeMode.Loose;

        Flows = Services.GetRequiredService<SqlFlowService>();
        Flows.EnterDemoMode();
    }

    private async Task ScanAsync(SqlFlowKind flow)
    {
        var fs = Flows.State.For(flow);
        fs.SelectedSubscriptionIds.Add(DemoDataService.SubProd);
        fs.SelectedSubscriptionIds.Add(DemoDataService.SubShared);
        await Flows.ScanAsync(flow);
    }

    [Fact]
    public void GradeBadge_RendersLetterAndColour()
    {
        var cut = Render<GradeBadge>(p => p.Add(x => x.Grade, "B").Add(x => x.Large, true));
        var span = cut.Find("span.grade-badge");
        Assert.Equal("B", span.TextContent);
        Assert.Contains("lg", span.ClassName);
        Assert.Contains("#7CB342", span.GetAttribute("style"));
        Assert.Contains("Good", span.GetAttribute("title"));
    }

    [Fact]
    public void StepBar_LocksLaterStepsUntilThereIsAScan()
    {
        var locked = Render<StepBar>(p => p.Add(x => x.Route, "sql-database").Add(x => x.Current, "scope").Add(x => x.HasScan, false));
        Assert.Equal(2, locked.FindAll("li.step.locked").Count);
        Assert.Empty(locked.FindAll("li.step a"));

        var open = Render<StepBar>(p => p.Add(x => x.Route, "sql-database").Add(x => x.Current, "grades").Add(x => x.HasScan, true).Add(x => x.HasBackupTargets, true));
        Assert.Empty(open.FindAll("li.step.locked"));
        Assert.Contains(open.FindAll("li.step a"), a => a.GetAttribute("href") == "/sql-database/backups");
        Assert.Single(open.FindAll("li.step.active"));
    }

    [Fact]
    public async Task GradesStep_ShowsOverallGradeRatingsFindingsAndServers()
    {
        await ScanAsync(SqlFlowKind.SqlDatabase);
        var cut = Render<GradesStep>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase));

        // The weakest database sets the overall grade.
        Assert.Equal("F", cut.Find(".overall .grade-badge.lg").TextContent);
        Assert.Equal(7, cut.FindAll("article.rating").Count);
        Assert.Contains("contoso-orders", cut.Markup);
        Assert.Contains("legacyapp", cut.Markup);

        // The weakest database is expanded by default with both breakdown tables and improvements.
        var open = cut.Find("article.rating.open");
        Assert.Contains("Score breakdown", open.TextContent);
        Assert.Contains("How to improve", open.TextContent);
        Assert.Equal(8, open.QuerySelectorAll("table.cats tr").Length);
        Assert.Contains("Backups at a glance", open.TextContent);
        Assert.Contains("logical server settings", open.TextContent);

        // Findings with fixes, and the server table.
        Assert.Contains("Findings", cut.Markup);
        Assert.NotEmpty(cut.FindAll("ul.findings li"));
        Assert.Equal(3, cut.FindAll("tr.server-row").Count);
        Assert.Contains("Open to internet", cut.Markup);
    }

    [Fact]
    public async Task GradesStep_ExpandingFindingShowsFix_AndServerRowShowsDetail()
    {
        await ScanAsync(SqlFlowKind.SqlDatabase);
        var cut = Render<GradesStep>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase));

        Assert.Empty(cut.FindAll(".fix"));
        cut.FindAll("ul.findings li button.link")[0].Click();
        Assert.Single(cut.FindAll(".fix"));

        Assert.Empty(cut.FindAll(".policy-detail"));
        cut.FindAll("tr.server-row")[0].Click();
        var detail = cut.Find(".policy-detail");
        Assert.Contains("Settings", detail.TextContent);
        Assert.Contains("Failover groups", detail.TextContent);
        Assert.Contains("Databases", detail.TextContent);
    }

    [Fact]
    public async Task GradesStep_ManagedInstance_NoAuditingColumn()
    {
        await ScanAsync(SqlFlowKind.ManagedInstance);
        var cut = Render<GradesStep>(p => p.Add(x => x.Flow, SqlFlowKind.ManagedInstance));
        Assert.Equal("F", cut.Find(".overall .grade-badge.lg").TextContent);
        Assert.Equal(3, cut.FindAll("article.rating").Count);
        Assert.DoesNotContain("<th>Auditing</th>", cut.Markup);
        Assert.Contains("mi-contoso-dev", cut.Markup);
    }

    [Fact]
    public async Task BackupsStep_PreselectsDatabasesNeedingChanges_AndOpensScriptModal()
    {
        await ScanAsync(SqlFlowKind.SqlDatabase);
        var cut = Render<BackupsStep>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase));

        Assert.Contains("Improve the backups", cut.Markup);
        Assert.Equal(4, cut.FindAll("button.preset").Count);
        Assert.Contains("active", cut.FindAll("button.preset")[1].ClassName); // Recommended
        Assert.Equal(7, cut.FindAll("table.db-table tbody tr:not(.group-row):not(.detail-row)").Count);
        // Every database except the perfect one needs changes under the recommended plan and is pre-selected.
        Assert.Equal(6, cut.FindAll("table.db-table tbody tr.selected").Count);
        Assert.Contains("6 selected", cut.Find(".sticky-actions .muted").TextContent);

        // The weakest database is expanded with its deltas.
        Assert.Contains("Changes with this plan", cut.Markup);
        Assert.Contains("Locally redundant", cut.Markup);

        // Switching to the Baseline preset changes the deltas (fewer changes) and summary chips.
        cut.FindAll("button.preset")[0].Click();
        Assert.Contains("PITR 14 d", cut.Markup);
        Assert.Contains("weekly × 4 weeks", cut.Markup);

        // Generating the script opens the modal with PowerShell, switchable to CLI.
        Assert.Empty(cut.FindAll(".modal"));
        cut.Find(".sticky-actions button.btn-primary").Click();
        Assert.Contains("Backup script", cut.Find(".modal").TextContent);
        Assert.Contains("Set-AzSqlDatabaseBackupShortTermRetentionPolicy", cut.Find("pre.script").TextContent);
        cut.FindAll(".script-tabs .tab")[1].Click();
        Assert.Contains("az sql db str-policy set", cut.Find("pre.script").TextContent);
        Assert.Contains("What changes", cut.Find(".modal").TextContent);
    }

    [Fact]
    public async Task BackupsStep_ListsLongTermBackupsOnDemand()
    {
        await ScanAsync(SqlFlowKind.SqlDatabase);
        var cut = Render<BackupsStep>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase));

        // Expand contoso-orders (it has an LTR policy) and list its backups.
        var row = cut.FindAll("table.db-table tbody tr").First(r => r.TextContent.Contains("contoso-orders"));
        row.QuerySelectorAll("button.link").Last().Click();
        var listBtn = cut.FindAll("button").First(b => b.TextContent.Contains("List the backups that exist"));
        await listBtn.ClickAsync(new());
        cut.WaitForState(() => cut.FindAll("ul.ltr-list li").Count > 0, TimeSpan.FromSeconds(5));
        Assert.NotEmpty(Flows.State.For(SqlFlowKind.SqlDatabase).LtrBackups);
    }

    [Fact]
    public async Task SqlFlow_FallsBackToScopeWhenThereIsNoScan()
    {
        var cut = Render<SqlFlow>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase).Add(x => x.Step, "backups"));
        Assert.Contains("Choose what to scan", cut.Markup);

        await ScanAsync(SqlFlowKind.SqlDatabase);
        var grades = Render<SqlFlow>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase).Add(x => x.Step, "grades"));
        Assert.Contains("Findings", grades.Markup);
        Assert.DoesNotContain("Choose what to scan", grades.Markup);

        var backups = Render<SqlFlow>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase).Add(x => x.Step, "backups"));
        Assert.Contains("Improve the backups", backups.Markup);
    }

    [Fact]
    public void ScopeStep_DemoMode_ListsSampleSubscriptionsAndCounts()
    {
        var cut = Render<ScopeStep>(p => p.Add(x => x.Flow, SqlFlowKind.ManagedInstance));
        cut.WaitForState(() => cut.FindAll("li.sub-row").Count == 2, TimeSpan.FromSeconds(5));
        cut.WaitForAssertion(() => Assert.Contains("managed instance", cut.Find(".sub-count").TextContent), TimeSpan.FromSeconds(5));

        Assert.True(cut.Find("button.btn-primary").HasAttribute("disabled"));
        cut.FindAll("li.sub-row input")[0].Change(true);
        Assert.False(cut.Find("button.btn-primary").HasAttribute("disabled"));
        Assert.Contains("Scan 1 subscription", cut.Find("button.btn-primary").TextContent);
    }

    [Fact]
    public async Task ReportModal_RendersPreview()
    {
        await ScanAsync(SqlFlowKind.SqlDatabase);
        var cut = Render<ReportModal>(p => p.Add(x => x.Flow, SqlFlowKind.SqlDatabase));
        Assert.Empty(cut.FindAll(".modal"));
        await cut.InvokeAsync(() => cut.Instance.Open(false));
        Assert.Contains("Security &amp; Backup Summary", cut.Find(".report-preview").InnerHtml);
        cut.FindAll(".report-tabs .tab")[1].Click();
        Assert.Contains("Detailed Findings", cut.Find(".report-preview").InnerHtml);
    }
}
