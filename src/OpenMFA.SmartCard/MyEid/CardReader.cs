using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenMFA.SmartCard.MyEid;

/// <summary>
/// Helper class for detecting smart card readers and cards
/// </summary>
public static class CardReader
{
    /// <summary>
    /// Detect all available card readers
    /// </summary>
    public static async Task<List<ReaderInfo>> DetectReadersAsync(Action<string>? logger = null)
    {
        var readers = new List<ReaderInfo>();

        try
        {
            var openscTool = FindOpenScTool("opensc-tool");
            var output = await RunCommandAsync(openscTool, "--list-readers", logger);

            // Parse output format:
            // Nr.  Card  Features  Name
            // 0    Yes             ACS ACR39U ICC Reader 0
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            bool inDataSection = false;
            foreach (var line in lines)
            {
                // Skip header line
                if (line.Contains("Nr.") && line.Contains("Card") && line.Contains("Name"))
                {
                    inDataSection = true;
                    continue;
                }

                if (!inDataSection || line.StartsWith("#"))
                    continue;

                // Parse data lines: "0    Yes             ACS ACR39U ICC Reader 0"
                // Split by whitespace, first token is reader number
                var tokens = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length >= 4 && uint.TryParse(tokens[0], out var readerNum))
                {
                    // Card presence is in second column
                    bool hasCard = tokens[1].Equals("Yes", StringComparison.OrdinalIgnoreCase);

                    // Reader name is everything after "Features" column (tokens[2])
                    var readerName = string.Join(" ", tokens.Skip(3));

                    readers.Add(new ReaderInfo
                    {
                        Number = readerNum,
                        Name = readerName,
                        HasCard = hasCard
                    });
                }
            }
        }
        catch (Exception ex)
        {
            logger?.Invoke($"Error detecting readers: {ex.Message}");
        }

        return readers;
    }

    /// <summary>
    /// Get the first reader with a card present
    /// </summary>
    public static async Task<uint?> GetFirstReaderWithCardAsync(Action<string>? logger = null)
    {
        var readers = await DetectReadersAsync(logger);
        return readers.FirstOrDefault(r => r.HasCard)?.Number;
    }

    private static async Task<string> RunCommandAsync(string command, string arguments, Action<string>? logger)
    {
        using var process = new Process();
        process.StartInfo.FileName = command;
        process.StartInfo.Arguments = arguments;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.RedirectStandardInput = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        var output = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                output.AppendLine(e.Data);
        };

        process.Start();
        process.StandardInput.Close();
        process.BeginOutputReadLine();

        await process.WaitForExitAsync();

        return output.ToString();
    }

    private static string FindOpenScTool(string toolName)
    {
        var openScPath = @"C:\Program Files\OpenSC Project\OpenSC\tools";

        if (OperatingSystem.IsWindows())
        {
            var exePath = Path.Combine(openScPath, $"{toolName}.exe");
            if (File.Exists(exePath))
                return exePath;
            return $"{toolName}.exe";
        }

        return toolName;
    }
}

/// <summary>
/// Information about a detected card reader
/// </summary>
public class ReaderInfo
{
    public uint Number { get; init; }
    public string Name { get; init; } = string.Empty;
    public bool HasCard { get; init; }

    /// <summary>
    /// YubiKeys appear as e.g. "Yubico YubiKey OTP+FIDO+CCID 0"
    /// </summary>
    public bool IsYubiKey =>
        Name.Contains("YubiKey", StringComparison.OrdinalIgnoreCase) ||
        Name.Contains("Yubico", StringComparison.OrdinalIgnoreCase);
}
