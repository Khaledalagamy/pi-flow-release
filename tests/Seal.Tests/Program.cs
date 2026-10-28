using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using PiFlow.Release;

int failures = 0;
void Check(bool ok, string code) { if (!ok) { failures++; Console.Error.WriteLine("FAIL " + code); } }
void Refuses(Action run, string code) { try { run(); Check(false, code); } catch (Exception e) when (e is CryptographicException or InvalidDataException or ArgumentException) { } }
using var vector = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "pfs1.json")));
byte[] V(string name) => Convert.FromHexString(vector.RootElement.GetProperty(name).GetString()!);
using var key = RSA.Create(3072); // Test private material exists in memory only.
byte[] bytes = SealedFormat.Seal(V("header"), V("manifest"), V("dll"), key, V("key"), V("nonce"));
var parts = SealedFormat.Parse(bytes);
Check(parts.Ciphertext.SequenceEqual(V("ciphertext")) && parts.Tag.SequenceEqual(V("tag")), "independent-node-aes-gcm-answer");
Check(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)) == V("header").Length, "little-endian-header-length");
byte[] unwrapped = key.Decrypt(parts.WrappedKey, RSAEncryptionPadding.OaepSHA256);
Check(unwrapped.SequenceEqual(V("key")), "rsa-oaep-sha256");
var opened = SealedFormat.Open(parts, unwrapped);
Check(opened.Manifest.SequenceEqual(V("manifest")) && opened.Dll.SequenceEqual(V("dll")), "payload-layout");
parts.Tag[0] ^= 1;
Refuses(() => SealedFormat.Open(parts, unwrapped), "tampered-tag");
parts = SealedFormat.Parse(bytes); parts.Header[0] ^= 1;
Refuses(() => SealedFormat.Open(parts, unwrapped), "tampered-associated-header");
Refuses(() => SealedFormat.Parse(bytes[..7]), "truncated");
byte[] bad = (byte[])bytes.Clone(); BinaryPrimitives.WriteUInt32LittleEndian(bad.AsSpan(4), uint.MaxValue);
Refuses(() => SealedFormat.Parse(bad), "oversized-header");
Refuses(() => SealedFormat.Seal([], V("manifest"), V("dll"), key, V("key"), V("nonce")), "empty-header");
CryptographicOperations.ZeroMemory(unwrapped);
CryptographicOperations.ZeroMemory(opened.Dll);
Console.WriteLine(failures == 0 ? "Sealed format checks passed." : "Sealed format checks failed.");
return failures;
