using System.Globalization;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Caching.Memory;
using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

public sealed record BackupCostRange(decimal MinMonthlyUsd, decimal MaxMonthlyUsd);
public sealed record BlobTierEstimate(string Tier, decimal? PricePerGbMonth, BackupCostRange? MonthlyUsd);

public sealed record DatabaseBackupEstimate(
    string Environment,
    string DatabaseName,
    string Region,
    string Capacity,
    string CurrentLtr,
    string PlannedLtr,
    BackupCostRange? CurrentLtrMonthlyUsd,
    BackupCostRange? PlannedLtrMonthlyUsd,
    List<BlobTierEstimate> BlobExportOptions,
    decimal? AssumedSizeGb)
{
    public BlobTierEstimate? CheapestBlobTier => BlobExportOptions
        .Where(option => option.MonthlyUsd is not null)
        .MinBy(option => option.MonthlyUsd!.MinMonthlyUsd);

    public decimal? BlobSavingsVsHot => BlobExportOptions.FirstOrDefault(option => option.Tier == "Hot")?.MonthlyUsd is { } hot
        && CheapestBlobTier is { MonthlyUsd: { } cheapest }
            ? hot.MinMonthlyUsd - cheapest.MinMonthlyUsd
            : null;
}

public sealed record EnvironmentBackupEstimate(
    string Environment,
    int DatabaseCount,
    int MissingCapacityDatabaseCount,
    int AssumedCapacityDatabaseCount,
    decimal? AssumedDatabaseSizeGb,
    BackupCostRange? CurrentLtrMonthlyUsd,
    BackupCostRange? PlannedLtrMonthlyUsd,
    List<BlobTierEstimate> BlobExportOptions)
{
    public BlobTierEstimate? CheapestBlobTier => BlobExportOptions
        .Where(option => option.MonthlyUsd is not null)
        .MinBy(option => option.MonthlyUsd!.MinMonthlyUsd);

    public decimal? BlobSavingsVsHot => BlobExportOptions.FirstOrDefault(option => option.Tier == "Hot")?.MonthlyUsd is { } hot
        && CheapestBlobTier is { MonthlyUsd: { } cheapest }
            ? hot.MinMonthlyUsd - cheapest.MinMonthlyUsd
            : null;
}

public sealed record BackupOptionsResearchResult(
    DateTimeOffset PricesRetrievedAt,
    int ArchiveCopies,
    string BlobRedundancy,
    bool IsManagedInstance,
    List<EnvironmentBackupEstimate> EnvironmentTotals,
    List<DatabaseBackupEstimate> Databases,
    List<string> Suggestions,
    List<string> PricingWarnings);

public sealed class BackupOptionsResearchService(HttpClient http, IMemoryCache cache, TokenBucketRateLimiter priceLimiter)
{
    private const string RetailPricesEndpoint = "https://prices.azure.com/api/retail/prices?api-version=2023-01-01-preview";
    private const long BytesPerGb = 1024L * 1024 * 1024;
    private readonly TokenBucketRateLimiter _priceLimiter = priceLimiter;

    public static readonly string[] BlobAccessTiers = ["Hot", "Cool", "Cold", "Archive"];

    public static readonly (string Key, string Label)[] BlobRedundancyChoices =
    [
        ("LRS", "Locally redundant (LRS)"),
        ("ZRS", "Zone redundant (ZRS)"),
        ("GRS", "Geo redundant (GRS)"),
        ("RA-GRS", "Geo redundant, read access (RA-GRS)"),
        ("GZRS", "Geo-zone redundant (GZRS)"),
        ("RA-GZRS", "Geo-zone redundant, read access (RA-GZRS)"),
    ];

    public async Task<BackupOptionsResearchResult> ResearchAsync(
        SqlScanResult scan, BackupPlan plan, int archiveCopies, string blobRedundancy,
        IReadOnlyDictionary<string, string>? subscriptionNames = null,
        IReadOnlyDictionary<string, decimal>? environmentSizeEstimatesGb = null, CancellationToken ct = default)
    {
        var databases = scan.RatableDatabases.ToList();
        archiveCopies = Math.Clamp(archiveCopies, 1, 12);
        blobRedundancy = BlobRedundancyChoices.Any(choice => choice.Key.Equals(blobRedundancy, StringComparison.OrdinalIgnoreCase))
            ? BlobRedundancyChoices.First(choice => choice.Key.Equals(blobRedundancy, StringComparison.OrdinalIgnoreCase)).Key
            : "LRS";
        var regions = databases.Select(d => NormalizeRegion(d.Location)).Where(r => r.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var pricesByRegion = new Dictionary<string, RegionalPrices>(StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();

        foreach (var region in regions)
        {
            try
            {
                pricesByRegion[region] = await GetRegionalPricesAsync(region, scan.Flow, ct);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
            {
                warnings.Add($"Retail prices for {region} could not be loaded: {ex.Message}");
            }
        }

        var estimates = databases.Select(db =>
        {
            pricesByRegion.TryGetValue(NormalizeRegion(db.Location), out var prices);
            var ltrRate = prices is null ? null : FindSqlLtrRate(prices.Sql, scan.Flow, db, plan.Redundancy);
            var currentRate = prices is null ? null : FindSqlLtrRate(prices.Sql, scan.Flow, db, db.BackupStorageRedundancy);
            var subscriptionName = subscriptionNames is not null && subscriptionNames.TryGetValue(db.SubscriptionId, out var displayName)
                ? displayName
                : null;
            var server = scan.Server(db.ServerId);
            var environment = ClassifyEnvironment(db, server, subscriptionName);
            decimal? assumedSizeGb = db.MaxSizeBytes is > 0 || environmentSizeEstimatesGb is null
                || !environmentSizeEstimatesGb.TryGetValue(environment, out var configuredSizeGb)
                || configuredSizeGb is <= 0 or > 1_000_000
                    ? null
                    : configuredSizeGb;
            var capacityBytes = db.MaxSizeBytes is > 0
                ? db.MaxSizeBytes
                : assumedSizeGb is { } sizeGb
                    ? decimal.ToInt64(decimal.Round(sizeGb * BytesPerGb, 0, MidpointRounding.AwayFromZero))
                    : null;
            var capacityLabel = db.MaxSizeBytes is > 0
                ? db.MaxSizeLabel
                : assumedSizeGb is { } assumed ? $"{assumed:0.#} GB assumed" : "unknown";
            var currentLtr = db.LtrRead
                ? EstimateLtrCost(capacityBytes, db.WeeklyRetention, db.MonthlyRetention, db.YearlyRetention, currentRate)
                : null;
            var plannedLtr = EstimateLtrCost(capacityBytes, plan.Weekly, plan.Monthly, plan.Yearly, ltrRate);
            var blobOptions = BlobAccessTiers.Select(tier =>
            {
                var rate = prices is null || !IsBlobTierSupported(tier, blobRedundancy)
                    ? null
                    : FindBlobRate(prices.Storage, tier, blobRedundancy);
                return new BlobTierEstimate(tier, rate, EstimateBlobCost(capacityBytes, archiveCopies, rate));
            }).ToList();

            return new DatabaseBackupEstimate(
                environment,
                db.Name,
                db.Location,
                capacityLabel,
                !db.LtrRead ? "unknown" : BackupPlanService.LtrLabel(db.WeeklyRetention, db.MonthlyRetention, db.YearlyRetention),
                BackupPlanService.LtrLabel(plan.Weekly, plan.Monthly, plan.Yearly),
                currentLtr,
                plannedLtr,
                blobOptions,
                assumedSizeGb);
        }).ToList();

        return new BackupOptionsResearchResult(
            DateTimeOffset.UtcNow,
            archiveCopies,
            blobRedundancy,
            scan.Flow == SqlFlowKind.ManagedInstance,
            AggregateByEnvironment(estimates),
            estimates,
            BuildSuggestions(databases, blobRedundancy),
            warnings);
    }

    public static BackupCostRange? EstimateLtrCost(
        long? maxSizeBytes, string weekly, string monthly, string yearly, decimal? pricePerGbMonth)
    {
        var (minCopies, maxCopies) = LtrBackupCountRange(weekly, monthly, yearly);
        if (maxCopies == 0) return new BackupCostRange(0, 0);
        if (maxSizeBytes is null or <= 0 || pricePerGbMonth is null) return null;

        var capacityGb = maxSizeBytes.Value / (decimal)BytesPerGb;
        var lowStorageGb = capacityGb / 4m * minCopies;
        var highStorageGb = capacityGb / 3m * maxCopies;
        return new BackupCostRange(
            decimal.Round(lowStorageGb * pricePerGbMonth.Value, 2),
            decimal.Round(highStorageGb * pricePerGbMonth.Value, 2));
    }

    public static BackupCostRange? EstimateBlobCost(long? maxSizeBytes, int copies, decimal? pricePerGbMonth)
    {
        if (maxSizeBytes is null or <= 0 || pricePerGbMonth is null) return null;
        var storageGb = maxSizeBytes.Value / (decimal)BytesPerGb * Math.Clamp(copies, 1, 12);
        var monthly = decimal.Round(storageGb * pricePerGbMonth.Value, 2);
        return new BackupCostRange(monthly, monthly);
    }

    public static bool IsBlobTierSupported(string tier, string redundancy) =>
        !tier.Equals("Archive", StringComparison.OrdinalIgnoreCase)
        || redundancy.Equals("LRS", StringComparison.OrdinalIgnoreCase)
        || redundancy.Equals("GRS", StringComparison.OrdinalIgnoreCase)
        || redundancy.Equals("RA-GRS", StringComparison.OrdinalIgnoreCase);

    public static string ClassifyEnvironment(SqlDatabaseInfo database, SqlServerInfo? server, string? subscriptionName = null)
    {
        var tagged = TryClassifyEnvironmentTag(database.Tags) ?? (server is null ? null : TryClassifyEnvironmentTag(server.Tags));
        if (tagged is not null) return tagged;

        foreach (var name in new[] { database.ResourceGroup, server?.ResourceGroup, server?.Name, subscriptionName, database.Name })
        {
            var classified = TryClassifyEnvironmentToken(name);
            if (classified is not null) return classified;
        }

        return "Unclassified";
    }

    public static List<EnvironmentBackupEstimate> AggregateByEnvironment(IEnumerable<DatabaseBackupEstimate> estimates) =>
        estimates.GroupBy(estimate => estimate.Environment, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var databases = group.ToList();
                var blobOptions = BlobAccessTiers.Select(tier => new BlobTierEstimate(
                    tier,
                    null,
                    SumRanges(databases.Select(database => database.BlobExportOptions
                        .First(option => option.Tier.Equals(tier, StringComparison.OrdinalIgnoreCase)).MonthlyUsd))))
                    .ToList();
                return new EnvironmentBackupEstimate(
                    group.Key,
                    databases.Count,
                    databases.Count(database => database.Capacity == "unknown"),
                    databases.Count(database => database.AssumedSizeGb is not null),
                    databases.Select(database => database.AssumedSizeGb).FirstOrDefault(size => size is not null),
                    SumRanges(databases.Select(database => database.CurrentLtrMonthlyUsd)),
                    SumRanges(databases.Select(database => database.PlannedLtrMonthlyUsd)),
                    blobOptions);
            })
            .OrderBy(summary => EnvironmentOrder(summary.Environment))
            .ThenBy(summary => summary.Environment, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static BackupCostRange? SumRanges(IEnumerable<BackupCostRange?> values)
    {
        var ranges = values.ToList();
        if (ranges.Count == 0 || ranges.Any(range => range is null)) return null;
        return new BackupCostRange(
            decimal.Round(ranges.Sum(range => range!.MinMonthlyUsd), 2),
            decimal.Round(ranges.Sum(range => range!.MaxMonthlyUsd), 2));
    }

    private static string? TryClassifyEnvironmentTag(Dictionary<string, string> tags)
    {
        foreach (var (key, value) in tags)
        {
            if (key.Equals("env", StringComparison.OrdinalIgnoreCase)
                || key.Contains("environment", StringComparison.OrdinalIgnoreCase))
                return TryClassifyEnvironmentToken(value) ?? "Unclassified";
        }
        return null;
    }

    private static string? TryClassifyEnvironmentToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var match = Regex.Match(value,
            @"(?<![A-Za-z0-9])(dev|development|tst|test|testing|qa|uat|stage|staging|stg|prod|production|prd)(?![A-Za-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return null;

        return match.Value.ToLowerInvariant() switch
        {
            "dev" or "development" => "Dev",
            "tst" or "test" or "testing" or "qa" or "uat" or "stage" or "staging" or "stg" => "Tst",
            "prod" or "production" or "prd" => "Prod",
            _ => null
        };
    }

    private static int EnvironmentOrder(string environment) => environment switch
    {
        "Dev" => 0,
        "Tst" => 1,
        "Prod" => 2,
        "Unclassified" => 3,
        _ => 4
    };

    public static (int Min, int Max) LtrBackupCountRange(string weekly, string monthly, string yearly)
    {
        var counts = new[] { DurationCount(weekly, 'W'), DurationCount(monthly, 'M'), DurationCount(yearly, 'Y') };
        var max = counts.Sum();
        return max == 0 ? (0, 0) : (counts.Max(), max);
    }

    private async Task<RegionalPrices> GetRegionalPricesAsync(string region, SqlFlowKind flow, CancellationToken ct)
    {
        var sqlService = flow == SqlFlowKind.SqlDatabase ? "SQL Database" : "SQL Managed Instance";
        var sqlTask = GetPricesAsync(sqlService, region, ct);
        var storageTask = GetPricesAsync("Storage", region, ct);
        await Task.WhenAll(sqlTask, storageTask);
        return new RegionalPrices(await sqlTask, await storageTask);
    }

    private async Task<IReadOnlyList<RetailPrice>> GetPricesAsync(string service, string region, CancellationToken ct)
    {
        var key = $"retail-prices:{service}:{region}";
        if (cache.TryGetValue(key, out IReadOnlyList<RetailPrice>? cached) && cached is not null)
            return cached;

        var filter = $"serviceName eq '{service}' and armRegionName eq '{region}' and priceType eq 'Consumption'";
        var next = $"{RetailPricesEndpoint}&$filter={Uri.EscapeDataString(filter)}";
        var prices = new List<RetailPrice>();
        while (!string.IsNullOrEmpty(next))
        {
            using var lease = await _priceLimiter.AcquireAsync(1, ct);
            if (!lease.IsAcquired)
                throw new InvalidOperationException("The local Retail Prices request queue is full. Retry the estimate shortly.");

            var page = await http.GetFromJsonAsync<RetailPricePage>(next, ct)
                ?? throw new InvalidOperationException("The Retail Prices API returned an empty response.");
            prices.AddRange(page.Items ?? []);
            next = page.NextPageLink;
        }

        cache.Set(key, prices, TimeSpan.FromHours(6));
        return prices;
    }

    private static decimal? FindSqlLtrRate(IReadOnlyList<RetailPrice> prices, SqlFlowKind flow, SqlDatabaseInfo db, string redundancy)
    {
        var redundancyMeter = RedundancyMeter(redundancy);
        if (redundancyMeter is null) return null;

        var product = flow == SqlFlowKind.ManagedInstance
            ? "SQL Managed Instance - LTR Backup Storage"
            : db.IsHyperscale ? "SQL Database SingleDB Hyperscale - LTR Backup Storage" : "SQL Database - LTR Backup Storage";

        return FindLatestRate(prices.Where(p => p.ProductName.Equals(product, StringComparison.OrdinalIgnoreCase)
            && p.MeterName.Contains(redundancyMeter, StringComparison.OrdinalIgnoreCase)));
    }

    private static decimal? FindBlobRate(IReadOnlyList<RetailPrice> prices, string tier, string redundancy)
    {
        var meter = $"{tier} {redundancy} Data Stored";
        return FindLatestRate(prices.Where(p =>
            (p.ProductName.Equals("Blob Storage", StringComparison.OrdinalIgnoreCase)
                || p.ProductName.Equals("General Block Blob v2", StringComparison.OrdinalIgnoreCase))
            && p.MeterName.Equals(meter, StringComparison.OrdinalIgnoreCase)));
    }

    private static decimal? FindLatestRate(IEnumerable<RetailPrice> candidates)
    {
        var matching = candidates.Where(p => p.UnitOfMeasure.Equals("1 GB/Month", StringComparison.OrdinalIgnoreCase)
            && p.TierMinimumUnits == 0).ToList();
        if (matching.Count == 0) return null;
        var latest = matching.Max(p => p.EffectiveStartDate);
        return matching.Where(p => p.EffectiveStartDate == latest).Min(p => p.Amount);
    }

    private static string? RedundancyMeter(string redundancy) => redundancy.ToLowerInvariant() switch
    {
        "local" => "LRS Data Stored",
        "zone" => "ZRS Data Stored",
        "geo" => "RA-GRS Data Stored",
        "geozone" => "RA-GZRS Data Stored",
        _ => null
    };

    private static int DurationCount(string value, char unit)
    {
        if (!SqlDatabaseInfo.IsSet(value)) return 0;
        var normalized = value.Trim().ToUpperInvariant();
        return normalized.Length > 2 && normalized[^1] == unit
            && int.TryParse(normalized.AsSpan(1, normalized.Length - 2), NumberStyles.None, CultureInfo.InvariantCulture, out var count)
            ? Math.Max(0, count)
            : 0;
    }

    private static string NormalizeRegion(string? location) =>
        (location ?? string.Empty).Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant();

    private static List<string> BuildSuggestions(IReadOnlyCollection<SqlDatabaseInfo> databases, string blobRedundancy)
    {
        var suggestions = new List<string>();
        var shortRetention = databases.Where(d => d.PitrRetentionDays is null || d.PitrRetentionDays < 14).ToList();
        if (shortRetention.Count > 0)
            suggestions.Add($"{shortRetention.Count} database(s) have unknown or under-14-day point-in-time retention. Consider 14–35 days when the recovery objective needs it; Basic databases are limited to 7 days.");

        var noLtr = databases.Where(d => d.LtrRead && !d.HasLtr).ToList();
        if (noLtr.Count > 0)
            suggestions.Add($"{noLtr.Count} database(s) have no long-term retention. Add weekly, monthly, or yearly backups only where compliance or recovery needs extend beyond the PITR window.");

        var local = databases.Count(d => d.BackupStorageRedundancy.Equals("Local", StringComparison.OrdinalIgnoreCase));
        if (local > 0)
            suggestions.Add($"{local} database(s) use locally redundant backup storage. Geo-redundancy enables geo-restore; choose it only when cross-region recovery is required and permitted.");

        suggestions.Add("BACPAC exports are portable archives for migration or analysis, not a substitute for transactionally consistent point-in-time recovery.");
        suggestions.Add($"Blob export prices are compared at {blobRedundancy}. General-purpose v2 accounts have 30- and 90-day minimums for Cool and Cold; Archive has a 180-day minimum, higher retrieval charges, and rehydration can take up to 15 hours. Archive isn't available with zone or geo-zone redundancy.");
        if (databases.Any(d => d.Kind == SqlFlowKind.ManagedInstance))
            suggestions.Add("For SQL Managed Instance, customer-managed copy-only full backups to Blob Storage can support immutable storage or retention beyond 10 years, but require scheduling, monitoring, and restore testing.");
        return suggestions;
    }

    private sealed record RegionalPrices(IReadOnlyList<RetailPrice> Sql, IReadOnlyList<RetailPrice> Storage);

    private sealed class RetailPricePage
    {
        [JsonPropertyName("Items")]
        public List<RetailPrice>? Items { get; set; }

        [JsonPropertyName("NextPageLink")]
        public string? NextPageLink { get; set; }
    }

    private sealed class RetailPrice
    {
        [JsonPropertyName("productName")]
        public string ProductName { get; set; } = string.Empty;

        [JsonPropertyName("meterName")]
        public string MeterName { get; set; } = string.Empty;

        [JsonPropertyName("unitOfMeasure")]
        public string UnitOfMeasure { get; set; } = string.Empty;

        [JsonPropertyName("retailPrice")]
        public decimal Amount { get; set; }

        [JsonPropertyName("tierMinimumUnits")]
        public decimal TierMinimumUnits { get; set; }

        [JsonPropertyName("effectiveStartDate")]
        public DateTimeOffset EffectiveStartDate { get; set; }
    }
}