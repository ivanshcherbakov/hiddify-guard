using System.Text.Json;
using System.Text.Json.Serialization;

namespace HiddifyGuard.Core.Storage;

public sealed record GuardSettings
{
    public int SchemaVersion { get; init; } = 1;
    public bool AllowLan { get; init; } = true;
    public string Language { get; init; } = "auto";
    public string? HiddifyDirectory { get; init; }
    public void Validate()
    {
        if (SchemaVersion != 1) throw new InvalidDataException("Unsupported configuration version.");
        if (Language is not ("auto" or "ru" or "en")) throw new InvalidDataException("Language must be auto, ru or en.");
        if (HiddifyDirectory is not null &&
            (!Path.IsPathFullyQualified(HiddifyDirectory) || HiddifyDirectory.StartsWith(@"\\", StringComparison.Ordinal)))
            throw new InvalidDataException("Select a local, absolute Hiddify directory.");
    }
}

public sealed class ConfigStore(string? root = null, bool secure = true)
{
    public static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "HiddifyGuard");
    public string Root { get; } = root ?? DefaultRoot;
    public string FilePath => Path.Combine(Root, "config.json");
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    public GuardSettings Load()
    {
        if (!File.Exists(FilePath)) return new();
        try
        {
            var settings = JsonSerializer.Deserialize<GuardSettings>(File.ReadAllText(FilePath), Options)
                ?? throw new InvalidDataException("Configuration is empty.");
            settings.Validate();
            return settings;
        }
        catch (JsonException error) { throw new InvalidDataException("Configuration is damaged; protection was not changed.", error); }
    }
    public void Save(GuardSettings settings)
    {
        settings.Validate();
        PrepareDirectory();
        var temporary = Path.Combine(Root, $"config.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, settings, Options);
                stream.Flush(true);
            }
            File.Move(temporary, FilePath, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    internal void PrepareDirectory()
    {
        var directory = Directory.CreateDirectory(Root);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("The configuration directory must not be a symbolic link.");
        if (!secure) return;
        var acl = new System.Security.AccessControl.DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var role in new[] { System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
                     System.Security.Principal.WellKnownSidType.LocalSystemSid,
                     System.Security.Principal.WellKnownSidType.AuthenticatedUserSid })
        {
            var rights = role == System.Security.Principal.WellKnownSidType.AuthenticatedUserSid
                ? System.Security.AccessControl.FileSystemRights.ReadAndExecute
                : System.Security.AccessControl.FileSystemRights.FullControl;
            acl.AddAccessRule(new(new System.Security.Principal.SecurityIdentifier(role, null), rights,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        }
        directory.SetAccessControl(acl);
    }
}
