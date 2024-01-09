using System.Globalization;

namespace CveConverter.Models;

public class CveMapper
{
    /// <summary>
    /// Maps a JsonCve to a CVE
    /// </summary>
    /// <param name="jsCve">Source JsonCve</param>
    /// <returns>Parsed CVE</returns>
    public static Cve JsonToCVE(JsonCve jsCve)
    {
        var cve = new Cve();

        cve.Id = jsCve.CveMetadata.CveId;
        if (jsCve.Containers.Cna.Affected != null)
        {
            if (jsCve.Containers.Cna.Affected.Any(a => a.Platforms != null))
            {
                var affectedPlatformsList = new List<string>();
                
                affectedPlatformsList = jsCve.Containers.Cna.Affected.Where(a => a.Platforms != null).SelectMany(a => a.Platforms).Distinct().ToList();
                cve.AffectedPlatforms = String.Join("$", affectedPlatformsList);
            }
            cve.AffectedProduct = jsCve.Containers.Cna.Affected.Select(a => a.ProductProduct).FirstOrDefault();
            cve.AffectedVendor = jsCve.Containers.Cna.Affected.Select(a => a.Vendor).FirstOrDefault();
            if (jsCve.Containers.Cna.Affected.Any(a => a.Versions != null))
            {
                if (jsCve.Containers.Cna.Affected.Any(a => a.Versions != null))
                {
                    var affectedVersionsList = new List<string>();
                    affectedVersionsList = jsCve.Containers.Cna.Affected.SelectMany(a => a.Versions).Distinct().Where(v => v.Status == Status.Affected)
                        .Select(v => v.Version).Distinct().ToList();   
                    cve.AffectedVersions = string.Join("$", affectedVersionsList);
                }
            }
        }
        cve.AssignerShortName = jsCve.CveMetadata.AssignerShortName;
        if (jsCve.Containers.Cna.Metrics != null)
        {
            var metric = jsCve.Containers.Cna.Metrics.First();
            if (metric.CvssV31 != null)
            {
                cve.AttackComplexity = metric.CvssV31.AttackComplexity.ToString();
                cve.AttackVector = metric.CvssV31.AttackVector.ToString();
                cve.BaseScore = metric.CvssV31.BaseScore.ToString(CultureInfo.InvariantCulture);
                cve.BaseSeverity = metric.CvssV31.AttackComplexity.ToString();
                cve.ConfidentialityImpact = metric.CvssV31.ConfidentialityImpact.ToString();
                cve.IntegrityImpact = metric.CvssV31.IntegrityImpact.ToString();
                cve.PrivilegesRequired = metric.CvssV31.PrivilegesRequired.ToString();
                cve.Scope = metric.CvssV31.Scope.ToString();
            }
            else if (metric.CvssV30 != null)
            {
                cve.AttackComplexity = metric.CvssV30.AttackComplexity.ToString();
                cve.AttackVector = metric.CvssV30.AttackVector.ToString();
                cve.BaseScore = metric.CvssV30.BaseScore.ToString(CultureInfo.InvariantCulture);
                cve.BaseSeverity = metric.CvssV30.AttackComplexity.ToString();
                cve.ConfidentialityImpact = metric.CvssV30.ConfidentialityImpact.ToString();
                cve.IntegrityImpact = metric.CvssV30.IntegrityImpact.ToString();
                cve.PrivilegesRequired = metric.CvssV30.PrivilegesRequired.ToString();
                cve.Scope = metric.CvssV30.Scope.ToString();
            }
            else if (metric.CvssV20 != null)
            {
                cve.AttackComplexity = metric.CvssV20.AccessComplexity.ToString();
                cve.AttackVector = metric.CvssV20.AccessVector.ToString();
                cve.BaseScore = metric.CvssV20.BaseScore.ToString(CultureInfo.InvariantCulture);
                cve.BaseSeverity = metric.CvssV20.AccessComplexity.ToString();
                cve.ConfidentialityImpact = metric.CvssV20.ConfidentialityImpact.ToString();
                cve.IntegrityImpact = metric.CvssV20.IntegrityImpact.ToString();
                cve.PrivilegesRequired = metric.CvssV20.Authentication.ToString();
                cve.Scope = metric.CvssV20.Exploitability.ToString();
            }
        }
        cve.DatePublished = jsCve.CveMetadata.DatePublished;
        cve.DatePublicFound = jsCve.Containers.Cna.DatePublic;
        cve.DateUpdated = jsCve.CveMetadata.DateUpdated;
        cve.Title = jsCve.Containers.Cna.Title;
        cve.Id = jsCve.CveMetadata.CveId;
        return cve;
    }
}