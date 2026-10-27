using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Azure.Core;

namespace RateMyAzureSql.Services.Azure;

/// <summary>Live implementation over HTTPS using the configured TokenCredential (az login by default).</summary>
public sealed class AzureApi : IAzureApi
{
    public const string ArmBase = "https://management.azure.com";
    private static readonly string[] ArmScopes = ["https://management.azure.com/.default"];

    private readonly TokenCredential _credential;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AzureApi> _logger;
    private readonly Dictionary<string, AccessToken> _tokenCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    public AzureApi(TokenCredential credential, IHttpClientFactory httpClientFactory, ILogger<AzureApi> logger)
    {
        _credential = credential;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<List<JsonElement>> QueryResourceGraphAsync(
        string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
    {
        var rows = new List<JsonElement>();
        var client = _httpClientFactory.CreateClient();
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);
        string? skipToken = null;

        do
        {
            var options = new Dictionary<string, object?> { ["resultFormat"] = "objectArray" };
            if (skipToken is not null) options["$skipToken"] = skipToken;

            var body = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["subscriptions"] = subscriptionIds,
                ["query"] = query,
                ["options"] = options
            });

            using var request = new HttpRequestMessage(HttpMethod.Post,
                $"{ArmBase}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");

            using var response = await SendWithRetryAsync(client, request, ct);
            var json = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Azure Resource Graph query failed ({(int)response.StatusCode}): {Truncate(json, 400)}");

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                foreach (var row in data.EnumerateArray())
                    rows.Add(row.Clone());

            skipToken = doc.RootElement.TryGetProperty("$skipToken", out var st) ? st.GetString() : null;
        } while (!string.IsNullOrEmpty(skipToken));

        return rows;
    }

    public async Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default)
    {
        var items = new List<JsonElement>();
        var client = _httpClientFactory.CreateClient();
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);
        var next = url;

        while (!string.IsNullOrEmpty(next))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using var response = await SendWithRetryAsync(client, request, ct);
            var json = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {Truncate(json, 300)}");

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray())
                    items.Add(item.Clone());

            next = doc.RootElement.TryGetProperty("nextLink", out var nl) ? nl.GetString() : null;
        }
        return items;
    }

    public async Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default)
    {
        var client = _httpClientFactory.CreateClient();
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await SendWithRetryAsync(client, request, ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        var json = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {Truncate(json, 300)}");

        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    /// <summary>Maximum retry attempts for throttled (429) or transient (5xx / network) ARM responses.</summary>
    internal const int MaxRetries = 5;
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Sends the request, retrying on ARM throttling (HTTP 429 "SubscriptionRequestsThrottled") and transient
    /// failures (408, 502, 503, 504, socket errors) with exponential backoff. The ARM Retry-After header is
    /// honoured when present. The request is cloned per attempt because HttpRequestMessage is single-use.
    /// </summary>
    private async Task<HttpResponseMessage> SendWithRetryAsync(HttpClient client, HttpRequestMessage request, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            HttpResponseMessage? response = null;
            Exception? transient = null;
            try
            {
                using var clone = await CloneAsync(request, ct);
                response = await client.SendAsync(clone, ct);
                if (!IsRetryable(response.StatusCode) || attempt >= MaxRetries) return response;
            }
            catch (HttpRequestException ex) when (attempt < MaxRetries)
            {
                transient = ex;
            }

            var delay = RetryDelay(attempt, response);
            _logger.LogInformation(
                "ARM request to {Url} {Reason}; retrying in {Delay:0.#}s (attempt {Attempt}/{Max}).",
                request.RequestUri?.AbsolutePath,
                response is not null ? $"returned HTTP {(int)response.StatusCode}" : $"failed ({transient?.Message})",
                delay.TotalSeconds, attempt + 1, MaxRetries);
            response?.Dispose();
            await Task.Delay(delay, ct);
        }
    }

    internal static bool IsRetryable(HttpStatusCode status) => status is
        HttpStatusCode.TooManyRequests or HttpStatusCode.RequestTimeout or
        HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;

    /// <summary>Retry-After (seconds or HTTP date) if ARM supplied one, otherwise 2^attempt seconds with jitter, capped.</summary>
    internal static TimeSpan RetryDelay(int attempt, HttpResponseMessage? response)
    {
        var retryAfter = response?.Headers.RetryAfter;
        TimeSpan? fromHeader = retryAfter?.Delta ??
            (retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        if (fromHeader is { } h && h > TimeSpan.Zero)
            return h < MaxRetryDelay ? h : MaxRetryDelay;

        var seconds = Math.Pow(2, attempt) + Random.Shared.NextDouble();
        var backoff = TimeSpan.FromSeconds(seconds);
        return backoff < MaxRetryDelay ? backoff : MaxRetryDelay;
    }

    private static async Task<HttpRequestMessage> CloneAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri) { Version = request.Version };
        foreach (var header in request.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        if (request.Content is not null)
        {
            var bytes = await request.Content.ReadAsByteArrayAsync(ct);
            var content = new ByteArrayContent(bytes);
            foreach (var header in request.Content.Headers)
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            clone.Content = content;
        }
        return clone;
    }

    private async Task<string> GetTokenAsync(string? tenantId, string[] scopes, CancellationToken ct)
    {
        var key = $"{tenantId}|{scopes[0]}";
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_tokenCache.TryGetValue(key, out var cached) && cached.ExpiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
                return cached.Token;

            var context = new TokenRequestContext(scopes, tenantId: string.IsNullOrEmpty(tenantId) ? null : tenantId);
            var token = await _credential.GetTokenAsync(context, ct);
            _tokenCache[key] = token;
            return token.Token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Token acquisition failed for tenant {TenantId}.", tenantId);
            throw new InvalidOperationException(
                "Could not acquire an Azure token. Run 'az login' (optionally with --tenant) and try again. " + ex.Message, ex);
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
