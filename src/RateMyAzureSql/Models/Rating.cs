namespace RateMyAzureSql.Models;

/// <summary>A-F rating for one database's security and backup setup (host settings included).</summary>
public sealed class SqlRating
{
    public SqlFlowKind TargetKind { get; set; }

    /// <summary>The database resource ID.</summary>
    public string TargetId { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string ServerId { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public string SubscriptionId { get; set; } = string.Empty;

    /// <summary>Total score out of 100 across all categories.</summary>
    public int Score { get; set; }

    /// <summary>Points earned in the security categories (out of 50).</summary>
    public int SecurityScore { get; set; }

    /// <summary>Points earned in the backup categories (out of 50).</summary>
    public int BackupScore { get; set; }

    /// <summary>"A" (best) to "F" (worst), after caps.</summary>
    public string Grade { get; set; } = "F";
    public string GradeLabel { get; set; } = string.Empty;

    /// <summary>Why the grade was capped below what the raw score would give; null when uncapped.</summary>
    public string? CapReason { get; set; }

    public List<SqlRatingCategory> Categories { get; set; } = new();

    /// <summary>Actions that raise the score, largest gain first.</summary>
    public List<SqlImprovement> Improvements { get; set; } = new();

    public IEnumerable<SqlImprovement> BackupImprovements => Improvements.Where(i => i.Area == RatingArea.Backups);
    public IEnumerable<SqlImprovement> SecurityImprovements => Improvements.Where(i => i.Area == RatingArea.Security);
}

public static class RatingArea
{
    public const string Security = "Security";
    public const string Backups = "Backups";
}

public sealed class SqlRatingCategory
{
    public string Name { get; set; } = string.Empty;

    /// <summary>"Security" or "Backups".</summary>
    public string Area { get; set; } = RatingArea.Security;
    public int Earned { get; set; }
    public int Possible { get; set; }
    public List<string> Details { get; set; } = new();
}

public sealed class SqlImprovement
{
    public string Action { get; set; } = string.Empty;
    public int PointsGained { get; set; }

    /// <summary>"Security" or "Backups".</summary>
    public string Area { get; set; } = RatingArea.Security;

    /// <summary>Grade after applying just this improvement (including any cap it lifts).</summary>
    public string ResultingGrade { get; set; } = string.Empty;
}
