// PFS1: a tool release sealed by the shared release workflow's build job for the Pi-Flow release API. Only the release API
// can open it (the content key is wrapped to the Key Vault key tool-intake). Integers are little-endian:
//   "PFS1" | headerLength u32 | header (UTF-8 JSON; the AES-GCM associated data)
//   | wrappedKeyLength u16 | wrappedKey (RSA-OAEP-SHA256 of the 32-byte content key)
//   | nonce (12) | ciphertext | tag (16)
// Plaintext payload: manifestLength u32 | manifest (piflow-tool.json bytes) | the tool DLL.
using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

namespace PiFlow.Release
{
    public static class SealedFormat
    {
        public static readonly byte[] Magic = "PFS1"u8.ToArray();
        public const int KeySize = 32;
        public const int NonceSize = 12;
        public const int TagSize = 16;
        public const int MaxHeaderBytes = 64 * 1024;
        public const long MaxSealedBytes = 64L * 1024 * 1024;

        public sealed class Parts
        {
            public byte[] Header { get; init; } = Array.Empty<byte>();
            public byte[] WrappedKey { get; init; } = Array.Empty<byte>();
            public byte[] Nonce { get; init; } = Array.Empty<byte>();
            public byte[] Ciphertext { get; init; } = Array.Empty<byte>();
            public byte[] Tag { get; init; } = Array.Empty<byte>();
        }

        /// <summary>Seals the manifest and DLL. Callers pass a random content key and nonce; tests pass fixed ones.</summary>
        public static byte[] Seal(byte[] header, byte[] manifest, byte[] dll, RSA intakePublicKey, byte[] contentKey, byte[] nonce)
        {
            if (contentKey.Length != KeySize || nonce.Length != NonceSize) throw new ArgumentException("bad content key or nonce size");
            if (header.Length == 0 || header.Length > MaxHeaderBytes) throw new ArgumentException("bad header size");
            byte[] payload = new byte[4 + manifest.Length + dll.Length];
            try
            {
                BinaryPrimitives.WriteUInt32LittleEndian(payload, (uint)manifest.Length);
                manifest.CopyTo(payload, 4);
                dll.CopyTo(payload, 4 + manifest.Length);
                byte[] ciphertext = new byte[payload.Length];
                byte[] tag = new byte[TagSize];
                using (var gcm = new AesGcm(contentKey, TagSize))
                    gcm.Encrypt(nonce, payload, ciphertext, tag, header);
                byte[] wrapped = intakePublicKey.Encrypt(contentKey, RSAEncryptionPadding.OaepSHA256);

                using var output = new MemoryStream();
                output.Write(Magic);
                Span<byte> u32 = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(u32, (uint)header.Length);
                output.Write(u32);
                output.Write(header);
                Span<byte> u16 = stackalloc byte[2];
                BinaryPrimitives.WriteUInt16LittleEndian(u16, (ushort)wrapped.Length);
                output.Write(u16);
                output.Write(wrapped);
                output.Write(nonce);
                output.Write(ciphertext);
                output.Write(tag);
                return output.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }

        /// <summary>Splits a sealed file into its parts without decrypting anything.</summary>
        public static Parts Parse(byte[] sealedBytes)
        {
            if (sealedBytes.LongLength > MaxSealedBytes) throw new InvalidDataException("the sealed file is too large");
            ReadOnlySpan<byte> span = sealedBytes;
            if (span.Length < 8 || !span[..4].SequenceEqual(Magic)) throw new InvalidDataException("not a PFS1 file");
            int pos = 4;
            uint headerLength = BinaryPrimitives.ReadUInt32LittleEndian(span[pos..]);
            pos += 4;
            if (headerLength == 0 || headerLength > MaxHeaderBytes || pos + (long)headerLength + 2 > span.Length)
                throw new InvalidDataException("bad header length");
            byte[] header = span.Slice(pos, (int)headerLength).ToArray();
            pos += (int)headerLength;
            ushort wrappedLength = BinaryPrimitives.ReadUInt16LittleEndian(span[pos..]);
            pos += 2;
            if (wrappedLength == 0 || pos + (long)wrappedLength + NonceSize + TagSize > span.Length)
                throw new InvalidDataException("bad wrapped key length");
            byte[] wrapped = span.Slice(pos, wrappedLength).ToArray();
            pos += wrappedLength;
            byte[] nonce = span.Slice(pos, NonceSize).ToArray();
            pos += NonceSize;
            int ciphertextLength = span.Length - pos - TagSize;
            byte[] ciphertext = span.Slice(pos, ciphertextLength).ToArray();
            pos += ciphertextLength;
            byte[] tag = span.Slice(pos, TagSize).ToArray();
            return new Parts { Header = header, WrappedKey = wrapped, Nonce = nonce, Ciphertext = ciphertext, Tag = tag };
        }

        /// <summary>Decrypts a parsed file with its content key (from Key Vault UnwrapKey RSA-OAEP-256 of Parts.WrappedKey).</summary>
        public static (byte[] Manifest, byte[] Dll) Open(Parts parts, byte[] contentKey)
        {
            byte[] payload = new byte[parts.Ciphertext.Length];
            try
            {
                using (var gcm = new AesGcm(contentKey, TagSize))
                    gcm.Decrypt(parts.Nonce, parts.Ciphertext, parts.Tag, payload, parts.Header);
                if (payload.Length < 4) throw new InvalidDataException("empty payload");
                uint manifestLength = BinaryPrimitives.ReadUInt32LittleEndian(payload);
                if (manifestLength > payload.Length - 4) throw new InvalidDataException("bad manifest length");
                byte[] manifest = payload.AsSpan(4, (int)manifestLength).ToArray();
                byte[] dll = payload.AsSpan(4 + (int)manifestLength).ToArray();
                return (manifest, dll);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }
}
