// check-contract: does a built tool DLL fit the Pi-Flow connector's launch contract?
//
//   dotnet run --project scripts/check-contract -- <tool.dll> --manifest piflow-tool.json
//       [--allow <AssemblyName>]...      also allow a reference (only for an un-merged build, e.g. CommunityToolkit.Mvvm)
//       [--expect-version <x.y.z>]       the DLL must be stamped with this version (release builds)
//
// It reads the DLL's metadata (System.Reflection.Metadata) and never loads or runs it, and reads piflow-tool.json by the
// release API's own rules (the backend's src/PiFlow.ToolContract/Manifest.cs). Each line is "ok" or "FAIL"; the exit code
// is the number of failures (0 = fits). What each rule protects is in docs/03-launch-contract.md, with the connector's
// file:line for each one.

using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.RegularExpressions;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("usage: check-contract <tool.dll> --manifest piflow-tool.json [--allow Name]... [--expect-version x.y.z]");
    return 2;
}

string dllPath = args[0];
string? manifestPath = null, expectVersion = null;
var extraAllowed = new List<string>();
for (int i = 1; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--manifest" when i + 1 < args.Length: manifestPath = args[++i]; break;
        case "--allow" when i + 1 < args.Length: extraAllowed.Add(args[++i]); break;
        case "--expect-version" when i + 1 < args.Length: expectVersion = args[++i]; break;
        default: Console.Error.WriteLine($"unknown argument: {args[i]}"); return 2;
    }
}
if (manifestPath == null) { Console.Error.WriteLine("--manifest piflow-tool.json is required"); return 2; }
if (!File.Exists(dllPath)) { Console.Error.WriteLine($"no such file: {dllPath}"); return 2; }

// The exact bytes the seal carries, parsed as the release API parses them. Parse does not decode names and strings, so
// every one is read here: invalid UTF-8 or a lone surrogate is a FAIL, not a crash later.
byte[] manifestBytes = File.ReadAllBytes(manifestPath);
JsonElement manifest;
try
{
    manifest = JsonDocument.Parse(manifestBytes, new JsonDocumentOptions { MaxDepth = 16 }).RootElement;
    Decode(manifest);
}
catch (Exception e) when (e is JsonException or InvalidOperationException)
{
    Console.WriteLine($"FAIL piflow-tool.json is not JSON text: {e.Message}");
    return 1;
}
static void Decode(JsonElement e)
{
    if (e.ValueKind == JsonValueKind.Object) foreach (var p in e.EnumerateObject()) { _ = p.Name; Decode(p.Value); }
    else if (e.ValueKind == JsonValueKind.Array) foreach (var x in e.EnumerateArray()) Decode(x);
    else if (e.ValueKind == JsonValueKind.String) _ = e.GetString();
}
bool manifestIsObject = manifest.ValueKind == JsonValueKind.Object;
string Field(string name) => manifestIsObject && manifest.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
string entryClass = Field("entryClass"), entryMethod = Field("entryMethod");

int fails = 0;
void Check(bool ok, string what)
{
    Console.WriteLine((ok ? "ok   " : "FAIL ") + what);
    if (!ok) fails++;
}

using var stream = File.OpenRead(dllPath);
using var pe = new PEReader(stream);
if (!pe.HasMetadata) { Console.WriteLine("FAIL not a .NET assembly: " + dllPath); return 1; }
MetadataReader md = pe.GetMetadataReader();
string assemblyName = md.GetString(md.GetAssemblyDefinition().Name);
Console.WriteLine($"check-contract: {Path.GetFileName(dllPath)} (assembly {assemblyName})");

// ── 0. The manifest, by the release API's rules (backend src/PiFlow.ToolContract/Manifest.cs) ───────────
// The API reads it only after the build was sealed and uploaded, and refuses it as contract_failed:<rule>; each line
// names that rule. The API also matches toolId to the repository's binding, and build.ps1 matches version to the tag.
Check(manifestBytes.Length <= 256 * 1024, "piflow-tool.json is at most 256 KB (manifest_size)");
Check(manifestIsObject, "piflow-tool.json is a JSON object (manifest_object)");
if (manifestIsObject)
{
    string[] fields = ["toolId", "name", "description", "category", "subcategory", "discipline", "version",
        "entryClass", "entryMethod", "commandName", "isMcpTool", "security"];
    var seen = new HashSet<string>(StringComparer.Ordinal);
    var badFields = manifest.EnumerateObject().Select(p => p.Name).Where(n => !seen.Add(n) || !fields.Contains(n)).Distinct().ToList();
    Check(badFields.Count == 0, "piflow-tool.json has only the fields a release reads, each once (manifest_fields)"
        + (badFields.Count == 0 ? "" : ": " + string.Join(", ", badFields)));

    // Text fields: required ones set, optional ones may be left out or empty; none longer than its limit or with control characters.
    (string Name, int Max, bool Optional)[] texts =
    [
        ("toolId", 128, false), ("name", 36, false), ("description", 200, false), ("category", 128, false),
        ("subcategory", 128, true), ("discipline", 128, true), ("version", 64, false), ("entryClass", 256, false),
        ("entryMethod", 64, false), ("commandName", 128, true),
    ];
    var badTexts = new List<string>();
    foreach (var (name, max, optional) in texts)
    {
        if (!manifest.TryGetProperty(name, out var v)) { if (!optional) badTexts.Add($"{name} is missing (manifest_{name})"); continue; }
        string? text = v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        string? problem = text == null ? "is not text"
            : text.Length > max ? $"is longer than {max} characters"
            : !optional && string.IsNullOrWhiteSpace(text) ? "is empty"
            : text.Any(char.IsControl) ? "has a control character" : null;
        if (problem != null) badTexts.Add($"{name} {problem} (manifest_{name})");
    }
    Check(badTexts.Count == 0, badTexts.Count == 0
        ? "text fields are set and short enough (name at most 36 characters, description 200)"
        : "text fields: " + string.Join("; ", badTexts));

    string toolId = Field("toolId");
    Check(toolId.Length is > 0 and <= 128 && toolId != "MCP_tools" && !toolId.Contains("..", StringComparison.Ordinal)
        && !string.IsNullOrWhiteSpace(toolId) && toolId.IndexOfAny("<>:\"/\\|?*".ToCharArray()) < 0 && !toolId.Any(char.IsControl),
        $"toolId '{toolId}' is a valid tool ID (tool_id)");
    Check(Regex.IsMatch(Field("version"), @"^\d+\.\d+\.\d+$"), $"version '{Field("version")}' is x.y.z (manifest_version)");
    Check(Field("description").TrimEnd().EndsWith('.'), "description ends with a full stop (manifest_description)");
    Check(entryClass.EndsWith(".ToolEntry", StringComparison.Ordinal) && entryMethod == "Execute",
        $"entryClass ends in .ToolEntry and entryMethod is Execute: '{entryClass}.{entryMethod}' (manifest_entry)");
    Check(manifest.TryGetProperty("isMcpTool", out var mcp) && mcp.ValueKind == JsonValueKind.False, "isMcpTool is false (manifest_mcp)");
    Check(!manifest.TryGetProperty("security", out var security) || security.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "security is left out, true or false (manifest_security)");
}

// ── Types, by the names the connector uses ──────────────────────────────────────────────────────────────
// Full name as Assembly.GetType(string) reads it: Namespace.Outer+Inner. Simple name as Type.Name.
var types = md.TypeDefinitions.Select(h => (Handle: h, Def: md.GetTypeDefinition(h))).ToList();
string FullName(TypeDefinition t)
{
    string name = md.GetString(t.Name);
    if (t.GetDeclaringType() is { IsNil: false } outer) return FullName(md.GetTypeDefinition(outer)) + "+" + name;
    string ns = md.GetString(t.Namespace);
    return ns.Length == 0 ? name : ns + "." + name;
}

static int ParameterCount(MetadataReader md, MethodDefinition m)
{
    var blob = md.GetBlobReader(m.Signature);
    var header = blob.ReadSignatureHeader();
    if (header.IsGeneric) blob.ReadCompressedInteger();
    return blob.ReadCompressedInteger();
}

static bool OnlyParameterIsString(MetadataReader md, MethodDefinition m)
{
    var blob = md.GetBlobReader(m.Signature);
    var header = blob.ReadSignatureHeader();
    if (header.IsGeneric) return false;
    if (blob.ReadCompressedInteger() != 1) return false;
    blob.ReadSignatureTypeCode();                          // return type (any)
    // a return type other than a primitive has more bytes; tools return void, so only that shape is read precisely
    return blob.RemainingBytes > 0 && blob.ReadSignatureTypeCode() == SignatureTypeCode.String;
}

static bool IsPublicStatic(MethodDefinition m) =>
    (m.Attributes & MethodAttributes.MemberAccessMask) == MethodAttributes.Public && (m.Attributes & MethodAttributes.Static) != 0;

// ── 1. The entry point (ConnectorPlugin.cs:99-109) ──────────────────────────────────────────────────────
Check(entryClass.Contains('.'), $"piflow-tool.json entryClass is a full name (namespace + class): '{entryClass}'");
var entry = types.Where(t => FullName(t.Def) == entryClass).ToList();
if (entry.Count == 0)
    entry = types.Where(t => md.GetString(t.Def.Name) == entryClass).Take(1).ToList();   // the connector's fallback
Check(entry.Count == 1, $"entry class '{entryClass}' exists");
if (entry.Count == 1)
{
    var t = entry[0].Def;
    Check(t.GetGenericParameters().Count == 0 && (t.Attributes & TypeAttributes.Interface) == 0,
        "entry class is a plain (non-generic) class");
    var candidates = t.GetMethods().Select(md.GetMethodDefinition)
        .Where(m => md.GetString(m.Name) == entryMethod && IsPublicStatic(m)).ToList();
    Check(candidates.Count == 1,
        $"exactly one public static method '{entryMethod}' (found {candidates.Count}; more than one is an AmbiguousMatchException in the connector)");
    if (candidates.Count == 1)
    {
        Check(ParameterCount(md, candidates[0]) == 0 && candidates[0].GetGenericParameters().Count == 0,
            $"'{entryMethod}' takes no parameters and is not generic (the connector invokes it with none)");
    }
}

// ── 2. ConnectorAuth.Authorize(string) (DllLoader.cs:159-169) ───────────────────────────────────────────
var auth = types.Where(t => md.GetString(t.Def.Name) == "ConnectorAuth").ToList();
Check(auth.Count == 1, $"exactly one type named ConnectorAuth (found {auth.Count}; the connector takes the first one)");
if (auth.Count >= 1)
{
    var authorize = auth[0].Def.GetMethods().Select(md.GetMethodDefinition)
        .Where(m => md.GetString(m.Name) == "Authorize" && IsPublicStatic(m)).ToList();
    Check(authorize.Count == 1, $"ConnectorAuth has exactly one public static Authorize (found {authorize.Count})");
    if (authorize.Count == 1)
        Check(OnlyParameterIsString(md, authorize[0]), "ConnectorAuth.Authorize takes one string (the session token)");
}

// ── 3. No second way in ─────────────────────────────────────────────────────────────────────────────────
string AttributeTypeName(CustomAttribute a)
{
    EntityHandle ctorParent = a.Constructor.Kind switch
    {
        HandleKind.MemberReference => md.GetMemberReference((MemberReferenceHandle)a.Constructor).Parent,
        HandleKind.MethodDefinition => md.GetMethodDefinition((MethodDefinitionHandle)a.Constructor).GetDeclaringType(),
        _ => default,
    };
    return TypeName(ctorParent);
}
string TypeName(EntityHandle h) => h.Kind switch
{
    HandleKind.TypeReference => md.GetString(md.GetTypeReference((TypeReferenceHandle)h).Namespace) + "." + md.GetString(md.GetTypeReference((TypeReferenceHandle)h).Name),
    HandleKind.TypeDefinition => FullName(md.GetTypeDefinition((TypeDefinitionHandle)h)),
    _ => "",
};
string Owner(EntityHandle parent) => parent.Kind switch
{
    HandleKind.MethodDefinition => FullName(md.GetTypeDefinition(md.GetMethodDefinition((MethodDefinitionHandle)parent).GetDeclaringType()))
                                   + "." + md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)parent).Name),
    HandleKind.TypeDefinition => FullName(md.GetTypeDefinition((TypeDefinitionHandle)parent)),
    HandleKind.AssemblyDefinition => "the assembly",
    _ => parent.Kind.ToString(),
};

string[] forbiddenAttributes =
{
    "Autodesk.AutoCAD.Runtime.CommandMethodAttribute",
    "Autodesk.AutoCAD.Runtime.LispFunctionAttribute",
    "Autodesk.AutoCAD.Runtime.CommandClassAttribute",
    "Autodesk.AutoCAD.Runtime.ExtensionApplicationAttribute",
};
var found = md.CustomAttributes.Select(md.GetCustomAttribute)
    .Select(a => (Type: AttributeTypeName(a), Where: Owner(a.Parent)))
    .Where(x => forbiddenAttributes.Contains(x.Type)).ToList();
Check(found.Count == 0, "no [CommandMethod], [LispFunction], [CommandClass] or [ExtensionApplication]"
    + (found.Count == 0 ? "" : ": " + string.Join(", ", found.Select(f => $"{f.Type.Split('.').Last()} on {f.Where}"))));

var extensionApps = types.Where(t => t.Def.GetInterfaceImplementations()
        .Any(i => TypeName(md.GetInterfaceImplementation(i).Interface) == "Autodesk.AutoCAD.Runtime.IExtensionApplication"))
    .Select(t => FullName(t.Def)).ToList();
Check(extensionApps.Count == 0, "no IExtensionApplication" + (extensionApps.Count == 0 ? "" : ": " + string.Join(", ", extensionApps)));

// ── 4. One DLL: references only to .NET, WPF, Civil 3D (and Newtonsoft.Json, which Civil 3D 2027 loads) ─
var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
using (var list = typeof(Program).Assembly.GetManifestResourceStream("framework-assemblies.txt")!)
using (var reader = new StreamReader(list))
{
    while (reader.ReadLine() is { } line)
        if (line.Length > 0 && !line.StartsWith('#')) allowed.Add(line.Trim());
}
string[] autodesk =
{
    "acdbmgd", "acmgd", "accoremgd", "acdbmgdbrep", "AcCui", "AdWindows", "AcWindows",       // AutoCAD 2027
    "AecBaseMgd", "AeccDbMgd", "AecPropDataMgd", "AeccPressurePipesMgd",                       // Civil 3D 2027
};
foreach (var a in autodesk) allowed.Add(a);
allowed.Add("Newtonsoft.Json");   // only 13.0.x: Civil 3D 2027 loads 13.0.3 (the build pins the package to 13.0.3)
foreach (var a in extraAllowed) allowed.Add(a);

var refs = md.AssemblyReferences.Select(h => md.GetAssemblyReference(h))
    .Select(r => (Name: md.GetString(r.Name), r.Version)).ToList();
var unknown = refs.Where(r => !allowed.Contains(r.Name)).Select(r => $"{r.Name} {r.Version}").ToList();
Check(unknown.Count == 0, unknown.Count == 0
    ? $"references only .NET, WPF and Civil 3D ({refs.Count} references)"
    : "references assemblies the connector cannot find (merge them, or remove them): " + string.Join(", ", unknown));
var newtonsoft = refs.Where(r => r.Name.Equals("Newtonsoft.Json", StringComparison.OrdinalIgnoreCase)).ToList();
if (newtonsoft.Count > 0)
    Check(newtonsoft.All(r => r.Version.Major == 13), $"Newtonsoft.Json is the 13.x line Civil 3D 2027 loads (found {newtonsoft[0].Version})");
foreach (var a in extraAllowed.Where(a => refs.Any(r => r.Name.Equals(a, StringComparison.OrdinalIgnoreCase))))
    Console.WriteLine($"note {a} is referenced and allowed by --allow: fine for an un-merged build, never for a release");

// WPF finds a window's XAML in "<assembly>.g.resources", by the assembly's own name (the merge must keep it).
if (refs.Any(r => r.Name == "PresentationFramework"))
{
    var resources = md.ManifestResources.Select(h => md.GetString(md.GetManifestResource(h).Name)).ToList();
    Check(resources.Contains(assemblyName + ".g.resources"), $"the WPF resources ({assemblyName}.g.resources) are in the DLL");
}

// ── 5. Built for Civil 3D 2027 (.NET 10) and stamped with the release version ───────────────────────────
var assemblyAttrs = md.GetAssemblyDefinition().GetCustomAttributes().Select(md.GetCustomAttribute).ToList();
string? StringAttribute(string typeName)
{
    var a = assemblyAttrs.FirstOrDefault(x => AttributeTypeName(x) == typeName);
    if (a.Constructor.IsNil) return null;
    var blob = md.GetBlobReader(a.Value);
    blob.ReadUInt16();                     // prolog
    return blob.ReadSerializedString();
}
string? tfm = StringAttribute("System.Runtime.Versioning.TargetFrameworkAttribute");
Check(tfm == ".NETCoreApp,Version=v10.0", $"targets .NET 10, the runtime of Civil 3D 2027 (found '{tfm}')");
string? informational = StringAttribute("System.Reflection.AssemblyInformationalVersionAttribute");
if (expectVersion != null)
    Check(informational != null && informational.Split('+')[0] == expectVersion,
        $"stamped with version {expectVersion} (found '{informational}')");
else
    Console.WriteLine($"note version {informational}");

Console.WriteLine(fails == 0 ? "The tool fits the launch contract." : $"{fails} check(s) failed.");
return fails;
