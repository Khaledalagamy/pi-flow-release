# Pi-Flow shared tool releases

Shared reusable workflows for .NET 10 Civil 3D tools. Each caller pins a full commit SHA. No long-term tool secret is stored in GitHub.

```text
tag → Windows build (no OIDC) → release.pfs only
    → Ubuntu publish (no checkout/tool code) → release API
    → metadata validation → new encrypted .bin + version-pinned Key Vault secret → channels
```

`release-tool.yml` accepts only `project` and optional `tests` csproj paths. The caller is `.github/workflows/release.yml`, triggered by `push` tags `v*`, with `contents: read`, `packages: read`, and `id-token: write`. It passes no secrets, API URLs, keys, or bypass flags. Use `vX.Y.Z-alpha.N` before `vX.Y.Z`; the manifest keeps base `X.Y.Z`. Stable tags must descend from the caller's default branch. Commit project and test lockfiles.

`tool-admin.yml` currently supports **bind**, including `adopt` for an existing legacy tool. Its caller must be `.github/workflows/tool-admin.yml` on `workflow_dispatch`. Only the owner (numeric ID 96947225), first run attempt, and an unseen run ID are accepted. Operations beyond bind belong to Step 6.

The public files under `keys/` are the RSA-3072 intake public key and its exact versioned Key Vault ID. The private key stays in Key Vault. The content key exists in memory on the build runner; only the sealed artifact crosses jobs. Finalize creates a fresh AES key and checks the uploaded encrypted blob by its returned version ID.

The API independently verifies GitHub signature/claims, a reviewed workflow SHA allow-list, repository binding, seal provenance, manifest, DLL metadata, and replay records. An empty allow-list refuses every request. A workflow commit existing on GitHub does not automatically make it trusted: the backend PR must explicitly allow its reviewed SHA. Do not merge backend main without the owner's approval.

Run `dotnet run --project tests/Seal.Tests -c Release -p:RestoreLockedMode=true`. CI also parses PowerShell, exercises leak rejection, and rehearses the actual build/seal helper with a synthetic tool. Nothing is uploaded by CI. The known-answer JSON uses public test values and independently generated AES-GCM ciphertext; no production secret appears in it.

Windows builds set `DebugType=none`, `DebugSymbols=false`, and `Deterministic=false`: the binding contract rejects every PE debug-directory entry, including the reproducible-build marker normally emitted by a deterministic .NET build.

Activation requires owner-managed Firestore TTL/index setup, reviewed SHA allow-lists, and a one-time bind per tool. Delivery to Civil 3D additionally needs Steps 2 and 3. A stable manifest with `security: true` currently fails closed unless the release identity can read the existing `tp-{h12}` policy. Its deployed write-only secret role cannot do that; no permission is widened by this repository. Never grant it read access to `tk-*` AES key secrets.
