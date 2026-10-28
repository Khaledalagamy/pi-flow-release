using PiFlow.Release;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length != 6) { Console.Error.WriteLine("usage: seal <manifest> <dll> <pem> <kid-file> <version> <output.pfs>"); return 2; }
byte[]? dll = null, manifest = null, contentKey = null;
try
{
    manifest = File.ReadAllBytes(args[0]);
    dll = File.ReadAllBytes(args[1]);
    if (manifest.Length > 256 * 1024 || dll.LongLength + manifest.Length > SealedFormat.MaxSealedBytes - 128 * 1024)
        throw new InvalidDataException();
    string kid = File.ReadAllText(args[3]).Trim();
    if (!Regex.IsMatch(kid, @"^https://kv-piflow-tools\.vault\.azure\.net/keys/tool-intake/[a-f0-9]{32}$"))
        throw new InvalidDataException();
    using var publicKey = RSA.Create();
    string pem = File.ReadAllText(args[2]);
    if (!pem.StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)) throw new InvalidDataException();
    publicKey.ImportFromPem(pem);
    if (publicKey.KeySize != 3072) throw new InvalidDataException();
    using var json = JsonDocument.Parse(manifest);
    string toolId = json.RootElement.GetProperty("toolId").GetString() ?? throw new InvalidDataException();
    string Env(string name) => Environment.GetEnvironmentVariable(name) ?? throw new InvalidDataException();
    var header = new
    {
        kid,
        repositoryId = long.Parse(Env("GITHUB_REPOSITORY_ID"), System.Globalization.CultureInfo.InvariantCulture),
        repository = Env("GITHUB_REPOSITORY"),
        runId = long.Parse(Env("GITHUB_RUN_ID"), System.Globalization.CultureInfo.InvariantCulture),
        runAttempt = long.Parse(Env("GITHUB_RUN_ATTEMPT"), System.Globalization.CultureInfo.InvariantCulture),
        sha = Env("GITHUB_SHA"),
        @ref = Env("GITHUB_REF"),
        toolId,
        version = args[4],
        manifestSha256 = Convert.ToHexStringLower(SHA256.HashData(manifest)),
        dllSha256 = Convert.ToHexStringLower(SHA256.HashData(dll))
    };
    contentKey = RandomNumberGenerator.GetBytes(SealedFormat.KeySize);
    byte[] sealedBytes = SealedFormat.Seal(JsonSerializer.SerializeToUtf8Bytes(header), manifest, dll,
        publicKey, contentKey, RandomNumberGenerator.GetBytes(SealedFormat.NonceSize));
    using (var output = new FileStream(args[5], FileMode.CreateNew, FileAccess.Write, FileShare.None))
        output.Write(sealedBytes);
    // Only a ciphertext hash is emitted. No payload, key, token or signed URL is logged.
    Console.WriteLine(Convert.ToHexStringLower(SHA256.HashData(sealedBytes)));
    return 0;
}
catch { Console.Error.WriteLine("seal_failed"); return 1; }
finally
{
    if (dll != null) CryptographicOperations.ZeroMemory(dll);
    if (manifest != null) CryptographicOperations.ZeroMemory(manifest);
    if (contentKey != null) CryptographicOperations.ZeroMemory(contentKey);
}
