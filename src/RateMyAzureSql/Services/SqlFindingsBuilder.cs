using RateMyAzureSql.Models;

namespace RateMyAzureSql.Services;

/// <summary>Report-only findings for a scan result, each with concrete remediation guidance attached.</summary>
public static class SqlFindingsBuilder
{
    public static readonly IReadOnlyDictionary<string, string> FixByCategory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        // Security
        ["Open to the internet"] = "Delete the firewall rule that spans 0.0.0.0–255.255.255.255 (Server → Networking → Firewall rules). Replace it with the specific client IP ranges that need access, or better, disable public network access and use a private endpoint.",
        ["Public endpoint"] = "Create a private endpoint for the server (Server → Networking → Private access), update clients and DNS to use it, then set Public network access to Disabled.",
        ["Public data endpoint"] = "Disable the public data endpoint on the managed instance (Instance → Networking → Public endpoint) and connect through the virtual network (VPN, ExpressRoute or peering) instead.",
        ["Allow Azure services"] = "Turn off 'Allow Azure services and resources to access this server' (Server → Networking → Exceptions). Give Azure-hosted clients access through private endpoints, virtual network rules (service endpoints) or their specific outbound IPs.",
        ["Broad firewall rule"] = "Narrow the rule to the address ranges that actually need access (Server → Networking → Firewall rules); a rule wider than a /24 usually covers far more than the intended clients.",
        ["No Entra admin"] = "Set a Microsoft Entra admin (Server → Microsoft Entra ID → Set admin). Use a group rather than a single user so admin access does not depend on one account.",
        ["SQL authentication enabled"] = "Once applications use Entra identities (managed identity or service principal), enable 'Microsoft Entra authentication only' (Server → Microsoft Entra ID) so password-based SQL logins stop working.",
        ["Defender disabled"] = "Enable Microsoft Defender for SQL (Server → Microsoft Defender for Cloud → Enable) or turn on the Defender for SQL plan for the whole subscription in Microsoft Defender for Cloud → Environment settings.",
        ["Vulnerability assessment off"] = "Enable SQL vulnerability assessment with the express configuration (Server → Microsoft Defender for Cloud → Configure) so the server is scanned weekly for misconfigurations.",
        ["Auditing disabled"] = "Enable auditing (Server → Auditing) and send the audit log to a Log Analytics workspace so logins, permission changes and queries can be investigated.",
        ["Weak TLS"] = "Set the minimum TLS version to 1.2 (Server → Networking → Connectivity → Minimum TLS version). Check that client drivers support TLS 1.2 first; everything released in the last decade does.",
        ["TDE disabled"] = "Enable transparent data encryption on the database (Database → Transparent data encryption → On). It is on by default for new databases; it was switched off deliberately on this one.",

        // Backups
        ["Local backup storage"] = "Change the backup storage redundancy to Geo-redundant or Geo-zone-redundant (Database → Compute + storage → Backup storage redundancy). For Hyperscale this requires a database copy; for other tiers it is an in-place change that takes effect for new backups.",
        ["Zone-only backup storage"] = "Change the backup storage redundancy to Geo-zone-redundant (Database → Compute + storage → Backup storage redundancy) so a copy of every backup also exists in the paired region.",
        ["No long-term retention"] = "Configure a long-term retention policy (Server → Backups → Retention policies → select the database → Configure policies): weekly, monthly and/or yearly full backups kept for up to 10 years, stored independently of the database.",
        ["Short PITR retention"] = "Raise the point-in-time restore retention (Server → Backups → Retention policies → Configure policies → PITR) to 14–35 days. Backup storage beyond the included amount is billed per GB-month.",
        ["Basic tier limits"] = "The Basic tier caps point-in-time retention at 7 days and cannot be zone redundant. Move production databases to Standard or General Purpose so retention can go to 35 days.",
        ["No geo-replica"] = "Create a failover group with a partner server in the paired region (Server → Failover groups → Add group) and add the database. Clients connect to the group listener and follow failovers automatically.",
        ["Not zone redundant"] = "Enable zone redundancy (Database → Compute + storage → Zone redundancy, or on the elastic pool for pooled databases) so the database survives the loss of a datacenter without failover.",
        ["Daily differential backups"] = "Set the differential backup interval to 12 hours (Server → Backups → Retention policies → Configure policies → Differential backups) to halve the worst-case restore time.",
        ["Geo-secondary not rated"] = "Backups are taken on the primary database; rate the primary (in its own subscription or server) to assess this replica's protection.",
        ["Data warehouse not rated"] = "Dedicated SQL pools use snapshots rather than automated database backups; review them in Azure Synapse.",
    };

    public static string FixFor(string category) =>
        FixByCategory.TryGetValue(category, out var fix)
            ? fix
            : "Review this finding in the Azure Portal and adjust the configuration accordingly.";

    public static List<SqlFinding> Build(SqlScanResult result)
    {
        var findings = new List<SqlFinding>();

        void Add(string severity, string area, string category, string message, string name, string id, string subId) =>
            findings.Add(new SqlFinding
            {
                Severity = severity, Area = area, Category = category, Message = message,
                ResourceName = name, ResourceId = id, SubscriptionId = subId, Fix = FixFor(category)
            });

        foreach (var s in result.Servers)
        {
            var isMi = s.Kind == SqlFlowKind.ManagedInstance;
            var label = $"{s.KindLabel} '{s.Name}'";
            void Sec(string sev, string cat, string msg) => Add(sev, RatingArea.Security, cat, msg, s.Name, s.Id, s.SubscriptionId);

            if (s.PublicNetworkAccess == true)
            {
                if (isMi)
                    Sec("Medium", "Public data endpoint", $"{label} has the public data endpoint enabled — it is reachable from outside its virtual network.");
                else if (s.OpenToInternet)
                    Sec("High", "Open to the internet", $"{label} has firewall rule(s) {string.Join(", ", s.FirewallRules!.Where(r => r.IsOpenToInternet).Select(r => r.Name))} allowing every IPv4 address.");
                else
                    Sec(s.PrivateEndpointCount > 0 ? "Info" : "Medium", "Public endpoint", $"{label} has public network access enabled{(s.PrivateEndpointCount > 0 ? $" although {s.PrivateEndpointCount} private endpoint(s) exist" : " and no private endpoint")}.");

                if (!isMi && s.AllowAzureServices)
                    Sec("Medium", "Allow Azure services", $"{label} allows all Azure services and resources (0.0.0.0 rule) — any Azure tenant can reach its endpoint.");
                foreach (var r in s.BroadRules)
                    Sec("Info", "Broad firewall rule", $"{label} firewall rule '{r.Name}' covers {r.AddressCount:N0} addresses ({r.Display}).");
            }

            if (!s.HasEntraAdmin)
                Sec("Medium", "No Entra admin", $"{label} has no Microsoft Entra admin — only SQL authentication is possible.");
            else if (s.EntraOnlyAuthentication == false)
                Sec("Info", "SQL authentication enabled", $"{label} still accepts SQL logins{(string.IsNullOrEmpty(s.SqlAdminLogin) ? "" : $" (admin login '{s.SqlAdminLogin}')")} — Microsoft Entra-only authentication is off.");

            if (s.DefenderEnabled == false)
                Sec("High", "Defender disabled", $"{label} does not have Microsoft Defender for SQL enabled.");
            else if (s.DefenderEnabled == true && s.VulnerabilityAssessmentEnabled == false)
                Sec("Medium", "Vulnerability assessment off", $"{label} has Defender for SQL but vulnerability assessment is not enabled.");

            if (!isMi && s.AuditingEnabled == false)
                Sec("Medium", "Auditing disabled", $"{label} has auditing disabled.");

            if (!SqlRatingService.TlsIsModern(s.MinimalTlsVersion))
                Sec("Medium", "Weak TLS", string.IsNullOrEmpty(s.MinimalTlsVersion) || s.MinimalTlsVersion.Equals("None", StringComparison.OrdinalIgnoreCase)
                    ? $"{label} enforces no minimum TLS version."
                    : $"{label} allows TLS {s.MinimalTlsVersion}.");
        }

        foreach (var db in result.Databases)
        {
            var label = $"Database '{db.Name}' on '{db.ServerName}'";
            void Bak(string sev, string cat, string msg) => Add(sev, RatingArea.Backups, cat, msg, $"{db.ServerName}/{db.Name}", db.Id, db.SubscriptionId);
            void Sec(string sev, string cat, string msg) => Add(sev, RatingArea.Security, cat, msg, $"{db.ServerName}/{db.Name}", db.Id, db.SubscriptionId);

            if (db.IsDataWarehouse)
            {
                Bak("Info", "Data warehouse not rated", $"{label} is a dedicated SQL pool (Data Warehouse) and was not rated.");
                continue;
            }
            if (db.IsGeoSecondary)
            {
                Bak("Info", "Geo-secondary not rated", $"{label} is a read-only geo-secondary and was not rated — backups are taken on the primary.");
                continue;
            }

            if (db.TdeEnabled == false)
                Sec("High", "TDE disabled", $"{label} has transparent data encryption disabled.");

            switch (db.BackupStorageRedundancy.ToLowerInvariant())
            {
                case "local":
                    Bak("High", "Local backup storage", $"{label} keeps its backups in locally redundant storage — a regional outage would lose them.");
                    break;
                case "zone":
                    Bak("Medium", "Zone-only backup storage", $"{label} keeps its backups in zone-redundant storage with no copy in the paired region.");
                    break;
            }

            if (db.LtrRead && !db.HasLtr)
                Bak("Medium", "No long-term retention", $"{label} has no long-term retention policy — only the {db.PitrRetentionDays ?? 7}-day point-in-time window exists.");

            if (db.PitrRetentionDays is { } days)
            {
                if (db.IsBasicTier)
                    Bak("Info", "Basic tier limits", $"{label} is on the Basic tier: point-in-time retention is capped at 7 days (currently {days}) and zone redundancy is unavailable.");
                else if (days < 7)
                    Bak("Medium", "Short PITR retention", $"{label} keeps only {days} day(s) of point-in-time backups.");
                else if (days < 14)
                    Bak("Info", "Short PITR retention", $"{label} keeps {days} days of point-in-time backups — 14–35 days is usual for production.");
            }

            if (db.DiffBackupIntervalHours is > 12)
                Bak("Info", "Daily differential backups", $"{label} takes differential backups every 24 h; 12 h shortens restores.");

            if (!db.HasGeoReplica)
                Bak("Info", "No geo-replica", $"{label} has no geo-replica or failover group.");

            if (!db.ZoneRedundant && db.SupportsZoneRedundancy)
                Bak("Info", "Not zone redundant", $"{label} is not zone redundant{(db.ElasticPoolId is not null ? $" (set on elastic pool '{db.ElasticPoolName}')" : "")}.");
        }

        return findings
            .OrderBy(f => SeverityOrder(f.Severity))
            .ThenBy(f => f.ResourceName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static int SeverityOrder(string severity) => severity switch { "High" => 0, "Medium" => 1, _ => 2 };
}
