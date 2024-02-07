using System.Globalization;
using CsvHelper;
using CveConverter.Models;

namespace CveConverter;

class Program
{
    static void Main(string[] args)
    {
        var folder = @"C:\CVES\";
        string[] allfiles = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories);
        var cves = new List<Cve>();
        foreach (var file in allfiles)
        {
            var cveJson = File.ReadAllText(file);
            cves.Add(CveMapper.JsonToCVE(JsonCve.FromJson(cveJson)));
        }

        using var csvFile = new StreamWriter(@".\cves.csv");
        using var csvWriter = new CsvWriter(csvFile, CultureInfo.InvariantCulture);
        csvWriter.WriteRecords(cves);
        csvWriter.Flush();
    }
}