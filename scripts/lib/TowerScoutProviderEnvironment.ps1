Set-StrictMode -Version Latest

$script:TowerScoutProviderEnvironmentMaximumBytes = 262144
$script:TowerScoutProviderEnvironmentWaitMilliseconds = 10000
$script:TowerScoutProviderEnvironmentEntropy = [System.Text.Encoding]::ASCII.GetBytes(
    "TowerScout.ProviderEnvironmentJournal.v1"
)

if ($null -eq ("TowerScout.ProviderEnvironmentNative" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TowerScout {
    public static class ProviderEnvironmentNative {
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint READ_CONTROL = 0x00020000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_INFO {
            public UInt64 VolumeSerialNumber;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] FileId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string name,
            uint access,
            uint share,
            IntPtr security,
            uint creation,
            uint flags,
            IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle handle,
            int infoClass,
            out FILE_ID_INFO information,
            uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileExW(string existing, string destination, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ReplaceFileW(
            string replaced,
            string replacement,
            string backup,
            uint flags,
            IntPtr exclude,
            IntPtr reserved);

        [DllImport("shell32.dll")]
        private static extern int SHGetKnownFolderPath(
            ref Guid folderId,
            uint flags,
            IntPtr token,
            out IntPtr path);

        public static string Identity(string path, bool directory) {
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT;
            if (directory) flags |= FILE_FLAG_BACKUP_SEMANTICS;
            using (SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                flags,
                IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                return IdentityFromHandle(handle);
            }
        }

        public static SafeFileHandle OpenDirectoryLease(string path) {
            SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);
            if (handle.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }

        public static string IdentityFromHandle(SafeFileHandle handle) {
            if (handle == null || handle.IsInvalid || handle.IsClosed) {
                throw new ArgumentException("Directory lease is invalid.");
            }
            FILE_ID_INFO information;
            if (!GetFileInformationByHandleEx(
                handle,
                18,
                out information,
                (uint)Marshal.SizeOf(typeof(FILE_ID_INFO)))) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return information.VolumeSerialNumber.ToString("x16") + ":" +
                BitConverter.ToString(information.FileId).Replace("-", "").ToLowerInvariant();
        }

        public static uint LinkCount(string path) {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                BY_HANDLE_FILE_INFORMATION information;
                if (!GetFileInformationByHandle(handle, out information)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return information.NumberOfLinks;
            }
        }

        public static void MoveNewWriteThrough(string existing, string destination) {
            if (!MoveFileExW(existing, destination, MOVEFILE_WRITE_THROUGH)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static void ReplaceWithoutBackup(string replacement, string destination) {
            if (!ReplaceFileW(destination, replacement, null, 0, IntPtr.Zero, IntPtr.Zero)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static string LocalAppData() {
            Guid folderId = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
            IntPtr path;
            int result = SHGetKnownFolderPath(ref folderId, 0, IntPtr.Zero, out path);
            if (result != 0 || path == IntPtr.Zero) {
                throw new Win32Exception(result);
            }
            try {
                return Marshal.PtrToStringUni(path);
            }
            finally {
                Marshal.FreeCoTaskMem(path);
            }
        }
    }
}
"@
}

function New-TowerScoutProviderFileSecurity {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentUser) {
        throw "Protected provider environment storage is unavailable."
    }
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($currentUser)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($principal in @(
        $currentUser,
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void] $security.AddAccessRule($rule)
    }
    return $security
}

function New-TowerScoutProviderDirectorySecurity {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentUser) {
        throw "Protected provider environment storage is unavailable."
    }
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($currentUser)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($principal in @(
        $currentUser,
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void] $security.AddAccessRule($rule)
    }
    return $security
}

function Assert-TowerScoutProviderRestrictedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [switch] $Directory
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        [bool] ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        ($Directory -and -not $item.PSIsContainer) -or
        (-not $Directory -and $item.PSIsContainer) -or
        (-not $Directory -and [TowerScout.ProviderEnvironmentNative]::LinkCount($item.FullName) -ne 1)
    ) {
        throw "Protected provider environment storage is unsafe."
    }
    $security = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $owner = $security.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (
        $null -eq $currentUser -or
        $null -eq $owner -or
        -not $security.AreAccessRulesProtected -or
        -not $owner.Value.Equals($currentUser.Value, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Protected provider environment storage is unsafe."
    }
    $rules = @($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $accepted = @($currentUser.Value.ToUpperInvariant(), "S-1-5-18")
    if ($rules.Count -ne 2) {
        throw "Protected provider environment storage is unsafe."
    }
    foreach ($rule in $rules) {
        if (
            $rule.IsInherited -or
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $accepted -notcontains $rule.IdentityReference.Value.ToUpperInvariant() -or
            ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne
                [System.Security.AccessControl.FileSystemRights]::FullControl
        ) {
            throw "Protected provider environment storage is unsafe."
        }
    }
    return [TowerScout.ProviderEnvironmentNative]::Identity($item.FullName, [bool] $Directory)
}

function Initialize-TowerScoutProviderRecoveryRoot {
    $localAppData = [TowerScout.ProviderEnvironmentNative]::LocalAppData()
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw "Protected provider environment storage is unavailable."
    }
    $current = $localAppData
    foreach ($component in @("TowerScout", "Recovery", "v1")) {
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) {
            [System.IO.DirectoryInfo]::new($current).Create((New-TowerScoutProviderDirectorySecurity))
        }
        [void] (Assert-TowerScoutProviderRestrictedPath -Path $current -Directory)
    }
    return $current
}

function Get-TowerScoutProviderLengthPrefixedSha256 {
    param([Parameter(Mandatory = $true)][byte[][]] $Values)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($value in $Values) {
            $length = [BitConverter]::GetBytes([uint64] $value.Length)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
            [void] $sha256.TransformBlock($length, 0, $length.Length, $null, 0)
            [void] $sha256.TransformBlock($value, 0, $value.Length, $null, 0)
        }
        [void] $sha256.TransformFinalBlock([byte[]]@(), 0, 0)
        return ([BitConverter]::ToString($sha256.Hash)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-TowerScoutProviderEnvironmentBinding {
    param([Parameter(Mandatory = $true)][string] $RootPath)

    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or [bool] ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "The package environment root is unsafe."
    }
    $identity = [TowerScout.ProviderEnvironmentNative]::Identity($resolvedRoot, $true)
    $parts = $identity.Split(":", 2)
    $volume = [Convert]::ToUInt64($parts[0], 16)
    $volumeBytes = [BitConverter]::GetBytes($volume)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($volumeBytes) }
    $fileId = New-Object byte[] ($parts[1].Length / 2)
    for ($index = 0; $index -lt $fileId.Length; $index++) {
        $fileId[$index] = [Convert]::ToByte($parts[1].Substring($index * 2, 2), 16)
    }
    $ascii = [System.Text.Encoding]::ASCII
    $digest = Get-TowerScoutProviderLengthPrefixedSha256 -Values @(
        $ascii.GetBytes("TowerScout.EnvironmentMutex"),
        $ascii.GetBytes("1"),
        $ascii.GetBytes("parent-volume"),
        $volumeBytes,
        $ascii.GetBytes("parent-file-id"),
        $fileId,
        $ascii.GetBytes("leaf"),
        $ascii.GetBytes(".env")
    )
    return [pscustomobject]@{
        RootPath = $resolvedRoot
        RootIdentity = $identity
        Digest = $digest
        MutexName = "Global\TowerScoutEnv-v1-$digest"
    }
}

function Enter-TowerScoutProviderEnvironmentMutex {
    param([Parameter(Mandatory = $true)][string] $Name)

    $security = [System.Security.AccessControl.MutexSecurity]::new()
    foreach ($principal in @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    )) {
        if ($null -eq $principal) { throw "The package environment lock is unavailable." }
        $rule = [System.Security.AccessControl.MutexAccessRule]::new(
            $principal,
            [System.Security.AccessControl.MutexRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void] $security.AddAccessRule($rule)
    }
    $created = $false
    $mutex = [System.Threading.Mutex]::new($false, $Name, [ref] $created, $security)
    try {
        try {
            $acquired = $mutex.WaitOne($script:TowerScoutProviderEnvironmentWaitMilliseconds)
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            throw "Another package environment update is active."
        }
        return $mutex
    }
    catch {
        $mutex.Dispose()
        throw
    }
}

function New-TowerScoutProviderRestrictedFile {
    param([Parameter(Mandatory = $true)][string] $Path)

    return [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::WriteThrough,
        (New-TowerScoutProviderFileSecurity)
    )
}

function Write-TowerScoutProviderRestrictedFile {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][byte[]] $Contents
    )

    $stream = New-TowerScoutProviderRestrictedFile -Path $Path
    try {
        if ($Contents.Length -gt 0) { $stream.Write($Contents, 0, $Contents.Length) }
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    [void] (Assert-TowerScoutProviderRestrictedPath -Path $Path)
    $reread = [System.IO.File]::ReadAllBytes($Path)
    if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($Contents, $reread)) {
        throw "Protected provider environment data could not be verified."
    }
}

function Get-TowerScoutProviderJournalPrefix {
    param([Parameter(Mandatory = $true)][string] $Digest)
    return "provider-env-$Digest"
}

function Protect-TowerScoutProviderJournalRecord {
    param([Parameter(Mandatory = $true)][object] $Record)

    Add-Type -AssemblyName System.Security
    $plain = [System.Text.Encoding]::UTF8.GetBytes(($Record | ConvertTo-Json -Compress -Depth 8))
    return [System.Security.Cryptography.ProtectedData]::Protect(
        $plain,
        $script:TowerScoutProviderEnvironmentEntropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Unprotect-TowerScoutProviderJournalRecord {
    param([Parameter(Mandatory = $true)][byte[]] $Ciphertext)

    Add-Type -AssemblyName System.Security
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $Ciphertext,
        $script:TowerScoutProviderEnvironmentEntropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return ([System.Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json)
}

function Get-TowerScoutProviderFileSha256 {
    param([Parameter(Mandatory = $true)][byte[]] $Contents)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha256.ComputeHash($Contents))).Replace("-", "").ToLowerInvariant() }
    finally { $sha256.Dispose() }
}

function Get-TowerScoutProviderJournalChain {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $Digest
    )

    $prefix = Get-TowerScoutProviderJournalPrefix -Digest $Digest
    $names = @(Get-ChildItem -LiteralPath $RootPath -Force -File | ForEach-Object { $_.Name })
    if ($names.Count -gt 256) { throw "Provider environment recovery state is invalid." }
    $generationPattern = "^" + [regex]::Escape($prefix) + "-([0-9]{20})\.generation$"
    $selected = @($names | Where-Object { $_ -match $generationPattern } | Sort-Object)
    if ($selected.Count -gt 4) { throw "Provider environment recovery state is invalid." }
    $allowed = @($selected + @("$prefix.pointer", "$prefix.pointer.tmp"))
    $unexpected = @($names | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) -and $allowed -notcontains $_ })
    if ($unexpected.Count -gt 0) { throw "Provider environment recovery state is ambiguous." }
    $chain = @()
    $previous = "genesis"
    for ($index = 0; $index -lt $selected.Count; $index++) {
        $name = $selected[$index]
        if ($name -notmatch $generationPattern -or [int64] $Matches[1] -ne ($index + 1)) {
            throw "Provider environment recovery state is invalid."
        }
        $path = Join-Path $RootPath $name
        [void] (Assert-TowerScoutProviderRestrictedPath -Path $path)
        $ciphertext = [System.IO.File]::ReadAllBytes($path)
        if ($ciphertext.Length -lt 1 -or $ciphertext.Length -gt 1048576) {
            throw "Provider environment recovery state is invalid."
        }
        $cipherHash = Get-TowerScoutProviderFileSha256 -Contents $ciphertext
        try { $record = Unprotect-TowerScoutProviderJournalRecord -Ciphertext $ciphertext }
        catch { throw "Provider environment recovery state is invalid." }
        if (
            $record.schema -ne 1 -or
            $record.target -ne $Digest -or
            $record.sequence -ne ($index + 1) -or
            $record.previous -ne $previous -or
            $record.state -notin @("planned", "created", "verified", "applied")
        ) { throw "Provider environment recovery state is invalid." }
        $chain += [pscustomobject]@{ Record = $record; CipherSha256 = $cipherHash; Name = $name }
        $previous = $cipherHash
    }
    return @($chain)
}

function Set-TowerScoutProviderJournalPointer {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $Digest,
        [Parameter(Mandatory = $true)][int] $Sequence,
        [Parameter(Mandatory = $true)][string] $CipherSha256
    )

    $prefix = Get-TowerScoutProviderJournalPrefix -Digest $Digest
    $pointerPath = Join-Path $RootPath "$prefix.pointer"
    $temporaryPath = Join-Path $RootPath "$prefix.pointer.tmp"
    if (Test-Path -LiteralPath $temporaryPath) {
        [void] (Assert-TowerScoutProviderRestrictedPath -Path $temporaryPath)
        Remove-Item -LiteralPath $temporaryPath -Force
    }
    $pointer = [System.Text.Encoding]::ASCII.GetBytes("1`n$Sequence`n$CipherSha256`n")
    Write-TowerScoutProviderRestrictedFile -Path $temporaryPath -Contents $pointer
    if (Test-Path -LiteralPath $pointerPath -PathType Leaf) {
        [void] (Assert-TowerScoutProviderRestrictedPath -Path $pointerPath)
        [TowerScout.ProviderEnvironmentNative]::ReplaceWithoutBackup($temporaryPath, $pointerPath)
    }
    else {
        [TowerScout.ProviderEnvironmentNative]::MoveNewWriteThrough($temporaryPath, $pointerPath)
    }
    [void] (Assert-TowerScoutProviderRestrictedPath -Path $pointerPath)
    if (-not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($pointer, [System.IO.File]::ReadAllBytes($pointerPath))) {
        throw "Provider environment recovery state could not be verified."
    }
}

function Add-TowerScoutProviderJournalGeneration {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $Digest,
        [Parameter(Mandatory = $true)][string] $State,
        [Parameter(Mandatory = $true)][hashtable] $Values
    )

    $chain = @(Get-TowerScoutProviderJournalChain -RootPath $RootPath -Digest $Digest)
    $sequence = $chain.Count + 1
    $previous = if ($chain.Count -eq 0) { "genesis" } else { $chain[-1].CipherSha256 }
    $record = [ordered]@{
        schema = 1
        target = $Digest
        sequence = $sequence
        previous = $previous
        state = $State
    }
    foreach ($key in ($Values.Keys | Sort-Object)) { $record[$key] = $Values[$key] }
    $ciphertext = Protect-TowerScoutProviderJournalRecord -Record ([pscustomobject] $record)
    $prefix = Get-TowerScoutProviderJournalPrefix -Digest $Digest
    $name = "{0}-{1:D20}.generation" -f $prefix, $sequence
    $path = Join-Path $RootPath $name
    Write-TowerScoutProviderRestrictedFile -Path $path -Contents $ciphertext
    $cipherHash = Get-TowerScoutProviderFileSha256 -Contents $ciphertext
    Set-TowerScoutProviderJournalPointer `
        -RootPath $RootPath `
        -Digest $Digest `
        -Sequence $sequence `
        -CipherSha256 $cipherHash
    $verified = @(Get-TowerScoutProviderJournalChain -RootPath $RootPath -Digest $Digest)
    if ($verified.Count -ne $sequence -or $verified[-1].CipherSha256 -ne $cipherHash) {
        throw "Provider environment recovery state could not be verified."
    }
    return $verified[-1]
}

function Remove-TowerScoutProviderJournalChain {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][string] $Digest
    )

    $chain = @(Get-TowerScoutProviderJournalChain -RootPath $RootPath -Digest $Digest)
    $prefix = Get-TowerScoutProviderJournalPrefix -Digest $Digest
    foreach ($name in @("$prefix.pointer.tmp", "$prefix.pointer")) {
        $path = Join-Path $RootPath $name
        if (Test-Path -LiteralPath $path) {
            [void] (Assert-TowerScoutProviderRestrictedPath -Path $path)
            Remove-Item -LiteralPath $path -Force
        }
    }
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $path = Join-Path $RootPath $chain[$index].Name
        [void] (Assert-TowerScoutProviderRestrictedPath -Path $path)
        Remove-Item -LiteralPath $path -Force
    }
}

function Test-TowerScoutRepairRecoveryArtifactsPending {
    param([Parameter(Mandatory = $true)][string] $RootPath)

    $names = @(Get-ChildItem -LiteralPath $RootPath -Force -File | ForEach-Object { $_.Name })
    if ($names.Count -gt 256) {
        throw "TowerScout recovery state is ambiguous."
    }
    foreach ($name in $names) {
        if (
            $name.StartsWith("journal-", [System.StringComparison]::Ordinal) -or
            $name.StartsWith(".journal-pointer-", [System.StringComparison]::Ordinal) -or
            $name.StartsWith("pointer-transition-", [System.StringComparison]::Ordinal) -or
            $name.StartsWith("recovery-backup-", [System.StringComparison]::Ordinal)
        ) {
            return $true
        }
    }
    return $false
}

function Get-TowerScoutProviderEnvironmentObservation {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Present = $false
            Contents = $null
            Sha256 = "absent"
            Identity = $null
            SecuritySha256 = $null
            FileAttributes = $null
        }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        $item.PSIsContainer -or
        [bool] ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        $item.Length -gt $script:TowerScoutProviderEnvironmentMaximumBytes -or
        [TowerScout.ProviderEnvironmentNative]::LinkCount($item.FullName) -ne 1
    ) {
        throw "The package environment file cannot be updated safely."
    }
    $contents = [System.IO.File]::ReadAllBytes($item.FullName)
    $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $securitySha256 = Get-TowerScoutProviderFileSha256 -Contents $security.GetSecurityDescriptorBinaryForm()
    return [pscustomobject]@{
        Present = $true
        Contents = $contents
        Sha256 = Get-TowerScoutProviderFileSha256 -Contents $contents
        Identity = [TowerScout.ProviderEnvironmentNative]::Identity($item.FullName, $false)
        SecuritySha256 = $securitySha256
        FileAttributes = [int] $item.Attributes
    }
}

function Test-TowerScoutProviderBytesEqual {
    param([byte[]] $Left, [byte[]] $Right)
    if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
    return [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($Left, $Right)
}

function Repair-TowerScoutProviderEnvironmentJournal {
    param(
        [Parameter(Mandatory = $true)][string] $RecoveryRoot,
        [Parameter(Mandatory = $true)][object] $Binding,
        [Parameter(Mandatory = $true)][string] $EnvPath
    )

    $chain = @(Get-TowerScoutProviderJournalChain -RootPath $RecoveryRoot -Digest $Binding.Digest)
    if ($chain.Count -eq 0) { return }
    $expectedStates = @("planned", "created", "verified", "applied")
    if ($chain.Count -gt $expectedStates.Count) {
        throw "Provider environment recovery state is invalid."
    }
    for ($index = 0; $index -lt $chain.Count; $index++) {
        if ($chain[$index].Record.state -ne $expectedStates[$index]) {
            throw "Provider environment recovery state is invalid."
        }
    }
    $first = $chain[0].Record
    $last = $chain[-1].Record
    if (
        $first.state -ne "planned" -or
        $first.root_identity -ne $Binding.RootIdentity -or
        $first.temp_name -notmatch '^\.towerscout-provider-env-[0-9a-f]{32}\.tmp$' -or
        $first.original_present -isnot [bool] -or
        $first.original_sha256 -notmatch '^(?:absent|[0-9a-f]{64})$' -or
        $first.original_identity -isnot [string] -or
        $first.original_security_sha256 -notmatch '^(?:absent|[0-9a-f]{64})$' -or
        $first.candidate_sha256 -notmatch '^[0-9a-f]{64}$' -or
        -not ($first.candidate_size -is [int] -or $first.candidate_size -is [long]) -or
        $first.candidate_size -lt 1 -or
        $first.candidate_size -gt $script:TowerScoutProviderEnvironmentMaximumBytes
    ) { throw "Provider environment recovery state is invalid." }
    if (
        ($first.original_present -and (
            $first.original_sha256 -eq "absent" -or
            [string]::IsNullOrWhiteSpace($first.original_identity) -or
            $first.original_security_sha256 -eq "absent" -or
            $first.original_file_attributes -isnot [int] -and
                $first.original_file_attributes -isnot [long]
        )) -or
        (-not $first.original_present -and (
            $first.original_sha256 -ne "absent" -or
            $first.original_identity -ne "absent" -or
            $first.original_security_sha256 -ne "absent" -or
            $first.original_file_attributes -ne -1
        ))
    ) { throw "Provider environment recovery state is invalid." }
    $identityPattern = '^[0-9a-f]{16}:[0-9a-f]{32}$'
    if (
        $first.root_identity -notmatch $identityPattern -or
        ($first.original_present -and $first.original_identity -notmatch $identityPattern)
    ) { throw "Provider environment recovery state is invalid." }
    if ($chain.Count -ge 2) {
        $created = $chain[1].Record
        if ($created.temp_identity -notmatch $identityPattern) {
            throw "Provider environment recovery state is invalid."
        }
    }
    if ($chain.Count -ge 3) {
        $verified = $chain[2].Record
        if (
            $verified.temp_identity -ne $created.temp_identity -or
            $verified.candidate_sha256 -ne $first.candidate_sha256 -or
            $verified.candidate_size -ne $first.candidate_size
        ) { throw "Provider environment recovery state is invalid." }
    }
    if ($chain.Count -eq 4) {
        $applied = $chain[3].Record
        if (
            $applied.final_identity -ne $created.temp_identity -or
            $applied.final_sha256 -ne $first.candidate_sha256
        ) { throw "Provider environment recovery state is invalid." }
    }
    $tempPath = Join-Path $Binding.RootPath $first.temp_name
    if (Test-Path -LiteralPath $tempPath) {
        $tempItem = Get-Item -LiteralPath $tempPath -Force
        if ($tempItem.Length -gt $script:TowerScoutProviderEnvironmentMaximumBytes) {
            throw "Provider environment recovery state is ambiguous."
        }
        $tempIdentity = Assert-TowerScoutProviderRestrictedPath -Path $tempPath
        if ($last.state -eq "planned") {
            if ($tempItem.Length -ne 0) { throw "Provider environment recovery state is ambiguous." }
        }
        elseif ($chain.Count -lt 2 -or $chain[1].Record.temp_identity -ne $tempIdentity) {
            throw "Provider environment recovery state is ambiguous."
        }
        Remove-Item -LiteralPath $tempPath -Force
    }
    $observed = Get-TowerScoutProviderEnvironmentObservation -Path $EnvPath
    $state = "third"
    if (-not $observed.Present -and -not $first.original_present) {
        $state = "original"
    }
    elseif (
        $observed.Present -and
        $first.original_present -and
        $observed.Sha256 -eq $first.original_sha256 -and
        $observed.Identity -eq $first.original_identity -and
        $observed.SecuritySha256 -eq $first.original_security_sha256 -and
        $observed.FileAttributes -eq $first.original_file_attributes
    ) {
        $state = "original"
    }
    elseif ($observed.Present -and $observed.Sha256 -eq $first.candidate_sha256) {
        $expectedCandidateIdentity = if ($last.state -eq "applied") {
            $last.final_identity
        }
        elseif ($chain.Count -ge 2) {
            $chain[1].Record.temp_identity
        }
        else {
            ""
        }
        $candidateSecurityMatches = if ($first.original_present) {
            $observed.SecuritySha256 -eq $first.original_security_sha256 -and
            $observed.FileAttributes -eq $first.original_file_attributes
        }
        else {
            try {
                (Assert-TowerScoutProviderRestrictedPath -Path $EnvPath) -eq $observed.Identity
            }
            catch {
                $false
            }
        }
        if ($observed.Identity -eq $expectedCandidateIdentity -and $candidateSecurityMatches) {
            $state = "candidate"
        }
    }
    if ($state -eq "third") { throw "Provider environment recovery is pending because the package environment changed unexpectedly." }
    if ($state -eq "candidate" -and $last.state -ne "applied") {
        [void] (Add-TowerScoutProviderJournalGeneration -RootPath $RecoveryRoot -Digest $Binding.Digest -State "applied" -Values @{
            final_identity = $observed.Identity
            final_sha256 = $observed.Sha256
        })
    }
    Remove-TowerScoutProviderJournalChain -RootPath $RecoveryRoot -Digest $Binding.Digest
}

function Invoke-TowerScoutProviderEnvironmentReplacement {
    param(
        [Parameter(Mandatory = $true)][string] $RootPath,
        [Parameter(Mandatory = $true)][object] $Plan
    )

    $binding = Get-TowerScoutProviderEnvironmentBinding -RootPath $RootPath
    $rootLease = [TowerScout.ProviderEnvironmentNative]::OpenDirectoryLease($binding.RootPath)
    $mutex = $null
    try {
        if (
            [TowerScout.ProviderEnvironmentNative]::IdentityFromHandle($rootLease) -ne
                $binding.RootIdentity
        ) {
            throw "The package environment root changed before the update."
        }
        $mutex = Enter-TowerScoutProviderEnvironmentMutex -Name $binding.MutexName
        $recoveryRoot = Initialize-TowerScoutProviderRecoveryRoot
        $envPath = Join-Path $binding.RootPath ".env"
        Repair-TowerScoutProviderEnvironmentJournal -RecoveryRoot $recoveryRoot -Binding $binding -EnvPath $envPath
        if (Test-TowerScoutRepairRecoveryArtifactsPending -RootPath $recoveryRoot) {
            throw "A TowerScout repair recovery transaction must be reconciled before updating the provider setting."
        }
        $original = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
        if (
            $original.Present -ne ($null -ne $Plan.OriginalContents) -or
            -not (Test-TowerScoutProviderBytesEqual -Left $original.Contents -Right $Plan.OriginalContents)
        ) { throw "The package environment changed before the provider update." }
        $template = $null
        $templatePath = $null
        if (-not $original.Present) {
            $templatePath = Join-Path $binding.RootPath ".env.example"
            $template = Get-TowerScoutProviderEnvironmentObservation -Path $templatePath
            if (
                -not $template.Present -or
                $template.Sha256 -ne $Plan.SourceSha256 -or
                -not (Test-TowerScoutProviderBytesEqual -Left $template.Contents -Right $Plan.SourceContents)
            ) {
                throw "The package environment template changed before the provider update."
            }
        }

        $tempName = ".towerscout-provider-env-$([guid]::NewGuid().ToString('N')).tmp"
        [void] (Add-TowerScoutProviderJournalGeneration -RootPath $recoveryRoot -Digest $binding.Digest -State "planned" -Values @{
            root_identity = $binding.RootIdentity
            original_present = $original.Present
            original_sha256 = if ($original.Present) { $original.Sha256 } else { "absent" }
            original_identity = if ($original.Present) { $original.Identity } else { "absent" }
            original_security_sha256 = if ($original.Present) { $original.SecuritySha256 } else { "absent" }
            original_file_attributes = if ($original.Present) { $original.FileAttributes } else { -1 }
            candidate_sha256 = $Plan.CandidateSha256
            candidate_size = $Plan.CandidateContents.Length
            temp_name = $tempName
        })
        $tempPath = Join-Path $binding.RootPath $tempName
        $tempStream = New-TowerScoutProviderRestrictedFile -Path $tempPath
        try {
            $tempIdentity = Assert-TowerScoutProviderRestrictedPath -Path $tempPath
            [void] (Add-TowerScoutProviderJournalGeneration -RootPath $recoveryRoot -Digest $binding.Digest -State "created" -Values @{
                temp_identity = $tempIdentity
            })
            $tempStream.Write($Plan.CandidateContents, 0, $Plan.CandidateContents.Length)
            $tempStream.Flush($true)
        }
        finally { $tempStream.Dispose() }
        if (
            (Assert-TowerScoutProviderRestrictedPath -Path $tempPath) -ne $tempIdentity -or
            (Get-TowerScoutProviderFileSha256 -Contents ([System.IO.File]::ReadAllBytes($tempPath))) -ne $Plan.CandidateSha256
        ) { throw "The provider environment candidate could not be verified." }
        [void] (Add-TowerScoutProviderJournalGeneration -RootPath $recoveryRoot -Digest $binding.Digest -State "verified" -Values @{
            temp_identity = $tempIdentity
            candidate_sha256 = $Plan.CandidateSha256
            candidate_size = $Plan.CandidateContents.Length
        })

        $before = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
        if (
            $before.Present -ne $original.Present -or
            $before.Identity -ne $original.Identity -or
            $before.SecuritySha256 -ne $original.SecuritySha256 -or
            $before.FileAttributes -ne $original.FileAttributes -or
            -not (Test-TowerScoutProviderBytesEqual -Left $before.Contents -Right $original.Contents)
        ) { throw "The package environment changed before atomic replacement." }
        if ($null -ne $template -and $null -ne $templatePath) {
            $templateBefore = Get-TowerScoutProviderEnvironmentObservation -Path $templatePath
            if (
                -not $templateBefore.Present -or
                $templateBefore.Identity -ne $template.Identity -or
                $templateBefore.SecuritySha256 -ne $template.SecuritySha256 -or
                $templateBefore.FileAttributes -ne $template.FileAttributes -or
                -not (Test-TowerScoutProviderBytesEqual -Left $templateBefore.Contents -Right $template.Contents)
            ) {
                throw "The package environment template changed before atomic replacement."
            }
        }
        try {
            if ($original.Present) {
                [TowerScout.ProviderEnvironmentNative]::ReplaceWithoutBackup($tempPath, $envPath)
            }
            else {
                [TowerScout.ProviderEnvironmentNative]::MoveNewWriteThrough($tempPath, $envPath)
            }
        }
        catch {
            $afterFailure = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
            if (-not $afterFailure.Present -and -not $original.Present) { throw }
            if ($afterFailure.Sha256 -ne $Plan.CandidateSha256) { throw }
        }
        $final = Get-TowerScoutProviderEnvironmentObservation -Path $envPath
        if (-not $final.Present -or $final.Sha256 -ne $Plan.CandidateSha256) {
            throw "Provider environment recovery is pending because atomic replacement could not be verified."
        }
        if ($original.Present) {
            if (
                $final.SecuritySha256 -ne $original.SecuritySha256 -or
                $final.FileAttributes -ne $original.FileAttributes
            ) {
                throw "Provider environment recovery is pending because file security changed unexpectedly."
            }
        }
        else {
            [void] (Assert-TowerScoutProviderRestrictedPath -Path $envPath)
        }
        [void] (Add-TowerScoutProviderJournalGeneration -RootPath $recoveryRoot -Digest $binding.Digest -State "applied" -Values @{
            final_identity = $final.Identity
            final_sha256 = $final.Sha256
        })
        Remove-TowerScoutProviderJournalChain -RootPath $recoveryRoot -Digest $binding.Digest
        return [pscustomobject]@{ Applied = $true }
    }
    finally {
        if ($null -ne $mutex) {
            try { $mutex.ReleaseMutex() } catch [System.ApplicationException] { }
            $mutex.Dispose()
        }
        $rootLease.Dispose()
    }
}
