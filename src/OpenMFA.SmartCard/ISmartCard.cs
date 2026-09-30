namespace OpenMFA.SmartCard;

/// <summary>
/// Card operations needed to set up a card for Windows smart card logon.
/// Implemented by MyEidCard (OpenSC PKCS#15) and YubiKeyCard (ykman PIV).
/// </summary>
public interface ISmartCard : IDisposable
{
    /// <summary>
    /// Set logging callback for command output
    /// </summary>
    void SetLogger(Action<string> logger);

    /// <summary>
    /// Erase the card and set new PIN/PUK codes
    /// </summary>
    Task InitializeAsync(string userPin, string userPuk, string soPin, string soPuk, CancellationToken ct = default);

    /// <summary>
    /// Generate RSA key pair in authentication slot (9A)
    /// </summary>
    Task GenerateAuthenticationKeyAsync(string pin, int keySize = 2048, CancellationToken ct = default);

    /// <summary>
    /// Generate a CSR with the UPN in Subject Alternative Name for Windows smart card logon
    /// </summary>
    Task GenerateCSRAsync(string commonName, string upn, string outputPath, string pin, CancellationToken ct = default);

    /// <summary>
    /// Store certificate (DER or PEM) in authentication slot (9A)
    /// </summary>
    Task StoreCertificateAsync(byte[] certificateData, string pin, CancellationToken ct = default);

    /// <summary>
    /// Read certificate (DER) from authentication slot (9A). Empty if none.
    /// </summary>
    Task<byte[]> ReadCertificateAsync(CancellationToken ct = default);

    /// <summary>
    /// Describe card contents (for verification)
    /// </summary>
    Task<string> ListObjectsAsync(CancellationToken ct = default);

    /// <summary>
    /// Erase card completely (factory reset)
    /// </summary>
    Task EraseAsync(string? soPin = null, CancellationToken ct = default);
}
