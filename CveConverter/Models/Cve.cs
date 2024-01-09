namespace CveConverter.Models;
public class Cve
{
    public string? AffectedPlatforms { get; set; }
    public string? AffectedProduct { get; set; }
    public string? AffectedVendor { get; set; }
    public string?  AffectedVersions { get; set; }
    public string? AssignerShortName { get; set; }
    public string? AttackComplexity { get; set; }
    public string? AttackVector { get; set; }
    public string? BaseScore { get; set; }
    public string? BaseSeverity { get; set; }
    public string? ConfidentialityImpact { get; set; }
    public DateTimeOffset? DatePublished { get; set; }
    public DateTimeOffset?  DatePublicFound { get; set; }
    public DateTimeOffset?  DateUpdated { get; set; }
    public string? IntegrityImpact { get; set; }
    public string? PrivilegesRequired { get; set; }
    public string? Scope { get; set; }
    public string? Title { get; set; }
    public string? Id { get; set; }
}