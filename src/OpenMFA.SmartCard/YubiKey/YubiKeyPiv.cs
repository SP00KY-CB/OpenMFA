using System.Diagnostics;
using System.Text;

namespace OpenMFA.SmartCard.YubiKey;

/// <summary>
/// YubiKey PIV operations using Yubico's ykman CLI.
/// OpenSC's pkcs15-init has no PIV driver, so it cannot erase a YubiKey.
/// </summary>
public class YubiKeyPiv
{
    private readonly string _ykmanPath;
    private Action<string>? _logger;

    public YubiKeyPiv()
    {
        _ykmanPath = FindYkman();
    }

    /// <summary>
    /// Set logging callback for command output
    /// </summary>
    public void SetLogger(Action<string> logger) => _logger = logger;

    /// <summary>
    /// Reset the PIV application to factory defaults.
    /// Deletes all PIV keys and certificates and restores PIN 123456, PUK 12345678
    /// and the default management key. Other YubiKey applications (FIDO, OTP, OpenPGP) are untouched.
    /// </summary>
    public async Task ResetAsync(CancellationToken ct = default)
    {
        await RunCommandAsync("piv reset --force", ct);
    }

    private async Task<string> RunCommandAsync(string arguments, CancellationToken ct)
    {
        _logger?.Invoke($"$ ykman {arguments}");

        using var process = new Process();
        process.StartInfo.FileName = _ykmanPath;
        process.StartInfo.Arguments = arguments;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.RedirectStandardInput = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        var output = new StringBuilder();
        var error = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                output.AppendLine(e.Data);
                _logger?.Invoke($"  > {e.Data}");
            }
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                error.AppendLine(e.Data);
                _logger?.Invoke($"  ! {e.Data}");
            }
        };

        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new FileNotFoundException(
                $"Could not run ykman ({_ykmanPath}). Install YubiKey Manager CLI or add ykman to PATH.", ex);
        }

        process.StandardInput.Close(); // Close stdin to prevent hanging on prompts
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            await process.WaitForExitAsync(linkedCts.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            _logger?.Invoke("  ✗ Command timed out");
            try { process.Kill(); } catch { }
            throw new TimeoutException("ykman command timed out after 1 minute");
        }

        if (process.ExitCode == 0)
        {
            _logger?.Invoke("  ✓ Success");
        }
        else
        {
            _logger?.Invoke($"  ✗ Failed (exit code: {process.ExitCode})");
            var errorMsg = error.ToString().Trim();
            if (!string.IsNullOrEmpty(errorMsg))
                throw new InvalidOperationException($"Command failed: {errorMsg}");
            throw new InvalidOperationException($"Command failed with exit code {process.ExitCode}");
        }

        return output.ToString();
    }

    private static string FindYkman()
    {
        if (OperatingSystem.IsWindows())
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var candidates = new[]
            {
                Path.Combine(programFiles, "Yubico", "YubiKey Manager CLI", "ykman.exe"),
                Path.Combine(programFiles, "Yubico", "YubiKey Manager", "ykman.exe"),
            };

            foreach (var path in candidates)
            {
                if (File.Exists(path))
                    return path;
            }

            return "ykman.exe"; // Assume in PATH
        }

        return "ykman"; // Linux/macOS - assume in PATH
    }
}
