using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OpenMFA.SmartCard.YubiKey;

/// <summary>
/// YubiKey PIV operations for Windows smart card logon, using Yubico's ykman CLI.
/// OpenSC's pkcs15-init has no PIV driver, so it cannot initialize a YubiKey.
/// CSRs are signed on the YubiKey through OpenSC's pkcs11-tool, because
/// ykman cannot add the UPN and smart card logon EKU that Windows needs.
/// </summary>
public class YubiKeyCard : ISmartCard
{
    private const string DefaultPin = "123456";
    private const string DefaultPuk = "12345678";
    private const string DefaultManagementKey = "010203040506070801020304050607080102030405060708";
    private const string Slot = "9a";

    private readonly string _ykmanPath;
    private readonly string _pkcs11ToolPath;
    private Action<string>? _logger;

    public YubiKeyCard()
    {
        _ykmanPath = FindYkman();
        _pkcs11ToolPath = FindOpenScTool("pkcs11-tool");
    }

    /// <summary>
    /// Set logging callback for command output
    /// </summary>
    public void SetLogger(Action<string> logger) => _logger = logger;

    #region Windows Logon Essential Operations

    /// <summary>
    /// Initialize YubiKey for Windows logon use.
    /// Resets PIV, sets the new PIN and PUK, and replaces the default management key
    /// with a random one stored on the YubiKey, protected by the PIN.
    /// YubiKey PIV has no SO-PIN/SO-PUK, so those are ignored.
    /// </summary>
    public async Task InitializeAsync(
        string userPin,
        string userPuk,
        string soPin,
        string soPuk,
        CancellationToken ct = default)
    {
        ValidatePinLength(userPin, "PIN");
        ValidatePinLength(userPuk, "PUK");

        await EraseAsync(ct: ct);

        if (userPin != DefaultPin)
        {
            _logger?.Invoke("Setting PIN...");
            await RunYkmanAsync(ct, "piv", "access", "change-pin", "--pin", DefaultPin, "--new-pin", userPin);
        }

        if (userPuk != DefaultPuk)
        {
            _logger?.Invoke("Setting PUK...");
            await RunYkmanAsync(ct, "piv", "access", "change-puk", "--puk", DefaultPuk, "--new-puk", userPuk);
        }

        // Random management key stored on the YubiKey, so later operations only need the PIN
        _logger?.Invoke("Replacing default management key (stored on YubiKey, protected by PIN)...");
        await RunYkmanAsync(ct, "piv", "access", "change-management-key",
            "--management-key", DefaultManagementKey, "--pin", userPin, "--protect", "--force");
    }

    /// <summary>
    /// Generate RSA key pair in authentication slot (9A) for Windows logon.
    /// Also stores a placeholder self-signed certificate, because OpenSC only exposes
    /// PIV keys that have a certificate. Import the CA-signed certificate to replace it.
    /// </summary>
    public async Task GenerateAuthenticationKeyAsync(
        string pin,
        int keySize = 2048,
        CancellationToken ct = default)
    {
        if (keySize != 2048 && keySize != 3072 && keySize != 4096)
            throw new ArgumentException("Key size must be 2048, 3072, or 4096 bits for Windows logon", nameof(keySize));

        var managementKeyArgs = await GetManagementKeyArgsAsync(ct);
        var publicKeyFile = Path.GetTempFileName();
        try
        {
            await RunYkmanAsync(ct, ["piv", "keys", "generate", "--algorithm", $"RSA{keySize}", "--pin", pin,
                .. managementKeyArgs, Slot, publicKeyFile]);

            _logger?.Invoke("Storing placeholder certificate in slot 9A...");
            await RunYkmanAsync(ct, ["piv", "certificates", "generate", "--subject", "CN=OpenMFA placeholder",
                "--valid-days", "30", "--pin", pin, .. managementKeyArgs, Slot, publicKeyFile]);
        }
        finally
        {
            if (File.Exists(publicKeyFile))
                File.Delete(publicKeyFile);
        }
    }

    /// <summary>
    /// Store certificate in authentication slot (9A).
    /// ykman verifies that the certificate matches the private key in the slot.
    /// </summary>
    public async Task StoreCertificateAsync(
        byte[] certificateData,
        string pin,
        CancellationToken ct = default)
    {
        var managementKeyArgs = await GetManagementKeyArgsAsync(ct);
        var certFile = Path.GetTempFileName();
        try
        {
            // ykman accepts DER or PEM
            await File.WriteAllBytesAsync(certFile, certificateData, ct);
            await RunYkmanAsync(ct, ["piv", "certificates", "import", "--verify", "--pin", pin,
                .. managementKeyArgs, Slot, certFile]);
        }
        finally
        {
            if (File.Exists(certFile))
                File.Delete(certFile);
        }
    }

    /// <summary>
    /// Generate a Certificate Signing Request (CSR) signed by the key in slot 9A.
    /// Matches the MyEID certreq request: UPN in Subject Alternative Name,
    /// Client Authentication and Smart Card Logon EKUs.
    /// </summary>
    public async Task GenerateCSRAsync(
        string commonName,
        string upn,
        string outputPath,
        string pin,
        CancellationToken ct = default)
    {
        var certData = await ReadCertificateAsync(ct);
        if (certData.Length == 0)
            throw new InvalidOperationException("No key found in slot 9A. Generate a key pair first.");

        using var cert = X509CertificateLoader.LoadCertificate(certData);
        using var rsa = cert.GetRSAPublicKey()
            ?? throw new InvalidOperationException("Key in slot 9A is not an RSA key.");

        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(commonName);

        var request = new CertificateRequest(subject.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.2"),       // Client Authentication
            new Oid("1.3.6.1.4.1.311.20.2.2"),  // Smart Card Logon
        }, false));

        var san = new SubjectAlternativeNameBuilder();
        san.AddUserPrincipalName(upn);
        request.CertificateExtensions.Add(san.Build());

        _logger?.Invoke("Signing CSR with the key in slot 9A (via OpenSC pkcs11-tool)...");
        var generator = new CardSignatureGenerator(this, rsa, pin);
        var csr = await Task.Run(() => request.CreateSigningRequest(generator), ct);

        // Loading checks the signature, which catches signing with the wrong card/key
        try
        {
            CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                "CSR signature does not match the key in slot 9A. Make sure only the YubiKey is inserted.", ex);
        }

        await File.WriteAllTextAsync(outputPath, PemEncoding.WriteString("CERTIFICATE REQUEST", csr), ct);
        _logger?.Invoke("  ✓ CSR generated successfully");
    }

    /// <summary>
    /// Read certificate from authentication slot (9A)
    /// </summary>
    public async Task<byte[]> ReadCertificateAsync(CancellationToken ct = default)
    {
        var certFile = Path.GetTempFileName();
        try
        {
            await RunYkmanAsync(ct, "piv", "certificates", "export", "--format", "DER", Slot, certFile);
            return await File.ReadAllBytesAsync(certFile, ct);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("No certificate found"))
        {
            return Array.Empty<byte>();
        }
        finally
        {
            if (File.Exists(certFile))
                File.Delete(certFile);
        }
    }

    /// <summary>
    /// Show PIV status (for verification)
    /// </summary>
    public async Task<string> ListObjectsAsync(CancellationToken ct = default)
    {
        return await RunYkmanAsync(ct, "piv", "info");
    }

    /// <summary>
    /// Reset the PIV application to factory defaults.
    /// Deletes all PIV keys and certificates and restores PIN 123456, PUK 12345678
    /// and the default management key. Other YubiKey applications (FIDO, OTP, OpenPGP) are untouched.
    /// </summary>
    public async Task EraseAsync(string? soPin = null, CancellationToken ct = default)
    {
        await RunYkmanAsync(ct, "piv", "reset", "--force");
    }

    #endregion

    #region Helper Methods

    private static void ValidatePinLength(string value, string name)
    {
        if (value.Length < 6 || value.Length > 8)
            throw new ArgumentException($"YubiKey {name} must be 6-8 characters.");
    }

    /// <summary>
    /// After InitializeAsync the management key is protected by the PIN, so ykman
    /// only needs --pin. Otherwise (e.g. straight after a reset) pass the default key,
    /// because ykman cannot prompt for it.
    /// </summary>
    private async Task<string[]> GetManagementKeyArgsAsync(CancellationToken ct)
    {
        var info = await RunYkmanAsync(ct, logOutput: false, "piv", "info");
        if (info.Contains("protected by PIN") || info.Contains("derived from PIN"))
            return Array.Empty<string>();

        return ["--management-key", DefaultManagementKey];
    }

    private Task<string> RunYkmanAsync(CancellationToken ct, params string[] args)
        => RunCommandAsync(_ykmanPath, args, ct, logOutput: true);

    private Task<string> RunYkmanAsync(CancellationToken ct, bool logOutput, params string[] args)
        => RunCommandAsync(_ykmanPath, args, ct, logOutput);

    /// <summary>
    /// Sign a PKCS#1 DigestInfo with the slot 9A key (OpenSC maps 9A to ID 01).
    /// Synchronous because X509SignatureGenerator.SignData is.
    /// </summary>
    private byte[] SignWithCard(byte[] digestInfo, string pin)
    {
        var inputFile = Path.GetTempFileName();
        var outputFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(inputFile, digestInfo);

            var args = new List<string>();
            var module = FindOpenScPkcs11Module(_pkcs11ToolPath);
            if (module != null)
                args.AddRange(["--module", module]);
            args.AddRange(["--sign", "--mechanism", "RSA-PKCS", "--id", "01", "--login", "--pin", pin,
                "--input-file", inputFile, "--output-file", outputFile]);

            RunCommandAsync(_pkcs11ToolPath, args, CancellationToken.None, logOutput: true).GetAwaiter().GetResult();
            return File.ReadAllBytes(outputFile);
        }
        finally
        {
            File.Delete(inputFile);
            File.Delete(outputFile);
        }
    }

    private async Task<string> RunCommandAsync(string command, IReadOnlyList<string> args, CancellationToken ct, bool logOutput)
    {
        var commandName = Path.GetFileNameWithoutExtension(command);
        _logger?.Invoke($"$ {commandName} {MaskSecrets(args)}");

        using var process = new Process();
        process.StartInfo.FileName = command;
        foreach (var arg in args)
            process.StartInfo.ArgumentList.Add(arg);
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
                if (logOutput)
                    _logger?.Invoke($"  > {e.Data}");
            }
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                error.AppendLine(e.Data);
                if (logOutput)
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
                $"Could not run {commandName} ({command}). Check that it is installed.", ex);
        }

        process.StandardInput.Close(); // Close stdin so prompts fail instead of hanging
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // RSA 4096 key generation on a YubiKey can take a couple of minutes
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            await process.WaitForExitAsync(linkedCts.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            _logger?.Invoke("  ✗ Command timed out");
            try { process.Kill(); } catch { }
            throw new TimeoutException($"{commandName} command timed out after 3 minutes");
        }

        if (process.ExitCode == 0)
        {
            if (logOutput)
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

    private static string MaskSecrets(IReadOnlyList<string> args)
    {
        var masked = new List<string>(args.Count);
        for (int i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            masked.Add(arg.Contains(' ') ? $"\"{arg}\"" : arg);

            if (arg is "--pin" or "--new-pin" or "--puk" or "--new-puk" or "--management-key" && i + 1 < args.Count)
            {
                masked.Add("****");
                i++;
            }
        }
        return string.Join(" ", masked);
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

    private static string FindOpenScTool(string toolName)
    {
        var openScPath = @"C:\Program Files\OpenSC Project\OpenSC\tools";

        if (OperatingSystem.IsWindows())
        {
            var exePath = Path.Combine(openScPath, $"{toolName}.exe");
            if (File.Exists(exePath))
                return exePath;
            return $"{toolName}.exe"; // Assume in PATH
        }

        return toolName; // Linux/macOS - assume in PATH
    }

    /// <summary>
    /// The OpenSC installer puts the PKCS#11 module in OpenSC\pkcs11, next to OpenSC\tools
    /// </summary>
    private static string? FindOpenScPkcs11Module(string pkcs11ToolPath)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathRooted(pkcs11ToolPath))
            return null;

        var toolsDir = Path.GetDirectoryName(pkcs11ToolPath)!;
        var module = Path.GetFullPath(Path.Combine(toolsDir, "..", "pkcs11", "opensc-pkcs11.dll"));
        return File.Exists(module) ? module : null;
    }

    #endregion

    public void Dispose()
    {
        // Nothing held open: each operation runs ykman or pkcs11-tool
    }

    /// <summary>
    /// Signs CSRs on the YubiKey. Hashing and DigestInfo encoding happen here,
    /// the card only does the RSA PKCS#1 v1.5 operation.
    /// </summary>
    private sealed class CardSignatureGenerator : X509SignatureGenerator
    {
        private readonly YubiKeyCard _card;
        private readonly X509SignatureGenerator _publicKeyGenerator;
        private readonly string _pin;

        public CardSignatureGenerator(YubiKeyCard card, RSA publicKey, string pin)
        {
            _card = card;
            _publicKeyGenerator = CreateForRSA(publicKey, RSASignaturePadding.Pkcs1);
            _pin = pin;
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
            => _publicKeyGenerator.GetSignatureAlgorithmIdentifier(hashAlgorithm);

        protected override PublicKey BuildPublicKey()
            => _publicKeyGenerator.PublicKey;

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm != HashAlgorithmName.SHA256)
                throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported");

            // DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2)
            byte[] prefix = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
            byte[] digestInfo = [.. prefix, .. SHA256.HashData(data)];

            return _card.SignWithCard(digestInfo, _pin);
        }
    }
}
