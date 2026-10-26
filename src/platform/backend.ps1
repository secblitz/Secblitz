$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
Set-StrictMode -Version 2
# Every module path is rooted in GetWindowsDirectoryW by the Rust launcher.
$moduleRoot = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$env:PSModulePath = $moduleRoot
$PSModuleAutoLoadingPreference = 'None'
$null = Import-Module ([IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')) -ErrorAction Stop
$null = Import-Module ([IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
$value = if ($null -ne $inputJson) { ConvertFrom-Json -InputObject $inputJson } else { $null }
function Load([string]$name) {
    $relative = if ($name -ceq 'Microsoft.PowerShell.LocalAccounts') { 'Microsoft.PowerShell.LocalAccounts\1.0.0.0\Microsoft.PowerShell.LocalAccounts.psd1' } else { "$name\$name.psd1" }
    $null = Import-Module (Join-Path $moduleRoot $relative) -ErrorAction Stop
}
function Emit($value) { ConvertTo-Json -InputObject $value -Depth 8 -Compress }
function ThrowGate([string]$message) {
    # Only call at positively established management/policy evidence sites.
    # Probe errors and ambiguous artifacts retain unknown authority, regardless
    # of their localized exception text. This helper emits no pipeline output.
    $exception = [InvalidOperationException]::new($message)
    $exception.Data['SecblitzAuthority'] = 'managed'
    throw $exception
}
function GateAuthority($errorRecord) {
    # Native invocation can wrap the original exception or its ErrorRecord.
    # Inspect typed evidence only, never localized text. Bound traversal even
    # when RuntimeException.ErrorRecord refers back to the same exception.
    $pending = [Collections.Generic.Queue[object]]::new()
    $pending.Enqueue($errorRecord)
    $seen = [Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0 -and $seen.Count -lt 32) {
        $item = $pending.Dequeue()
        if ($null -eq $item -or $seen.Contains($item)) { continue }
        $seen.Add($item)
        if ($item -is [Management.Automation.ErrorRecord]) {
            $pending.Enqueue($item.Exception)
        } elseif ($item -is [Exception]) {
            if ($item.Data['SecblitzAuthority'] -is [string] -and $item.Data['SecblitzAuthority'] -ceq 'managed') { return 'managed' }
            $pending.Enqueue($item.InnerException)
            if ($item -is [Management.Automation.RuntimeException]) { $pending.Enqueue($item.ErrorRecord) }
        }
    }
    return 'unknown'
}
function HasValues([string]$path) {
    if (!(Test-Path -LiteralPath $path)) { return $false }
    $k = Get-Item -LiteralPath $path
    if ($k.ValueCount -gt 0) { return $true }
    foreach ($child in @(Get-ChildItem -LiteralPath $path -Recurse)) { if ($child.ValueCount -gt 0) { return $true } }
    return $false
}
function BootRenamePending {
    # PendingFileRenameOperations lists files replaced or deleted at the next
    # boot. App updaters (browsers, installers) queue their own clean-up there
    # all the time; that never needs a restart before Windows servicing. Only
    # entries positively under app or profile folders are ignored: Windows
    # files, device paths, short names and unreadable values stay pending.
    $windows = [Environment]::GetFolderPath('Windows').TrimEnd('\') + '\'
    $roots = @()
    $profiles = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').ProfilesDirectory
    foreach ($root in @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('ProgramFilesX86'),
        [Environment]::GetFolderPath('CommonApplicationData'), $profiles)) {
        if ($root -isnot [string] -or $root -notmatch '^[A-Za-z]:\\[^\\]') { continue }
        $root = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if (!$root.StartsWith($windows, [StringComparison]::OrdinalIgnoreCase) -and !$windows.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $roots += $root }
    }
    $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    foreach ($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')) {
        $entries = $key.GetValue($name)
        if ($null -eq $entries) { continue }
        if ($entries -isnot [string[]]) { return $true }
        foreach ($entry in $entries) {
            if ($entry.Length -eq 0) { continue } # an empty target means delete
            $path = $entry -replace '^[*!]\d*', ''
            if ($path -notmatch '^\\\?\?\\[A-Za-z]:\\' -or $path.Contains('~')) { return $true }
            try { $path = [IO.Path]::GetFullPath($path.Substring(4)) } catch { return $true }
            if (!@($roots | Where-Object { $path.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) { return $true }
        }
    }
    return $false
}
function QueryMdmRegistration {
    # Documented Windows 8.1+ MDMRegistration API. Reflection.Emit creates only
    # a P/Invoke stub: unlike Add-Type on 5.1 it needs no csc.exe subprocess (the
    # launcher intentionally prohibits descendants). Use the trusted DLL path,
    # preserve HRESULT, and omit the optional UPN to avoid collecting identity.
    if ($null -eq ('Secblitz.MdmRegistration' -as [type])) {
        $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly([Reflection.AssemblyName]::new('Secblitz.MdmRegistration'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $module = $assembly.DefineDynamicModule('Secblitz.MdmRegistration')
        $type = $module.DefineType('Secblitz.MdmRegistration', [Reflection.TypeAttributes]'Public, Abstract, Sealed')
        $method = $type.DefinePInvokeMethod('IsDeviceRegisteredWithManagement', [IO.Path]::Combine($env:SystemRoot, 'System32\MDMRegistration.dll'), 'IsDeviceRegisteredWithManagement', [Reflection.MethodAttributes]'Public, Static, PinvokeImpl', [Reflection.CallingConventions]::Standard, [int], [Type[]]@([int].MakeByRefType(), [uint32], [IntPtr]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
        $null = $type.CreateType()
    }
    $registered = [int]0
    $hr = [Secblitz.MdmRegistration]::IsDeviceRegisteredWithManagement([ref]$registered, [uint32]0, [IntPtr]::Zero)
    return @{result=$hr;registered=$registered}
}
function MdmRegistered {
    $probe = QueryMdmRegistration
    if ($probe.result -isnot [int] -or $probe.result -ne 0 -or $probe.registered -isnot [int] -or $probe.registered -notin @(0,1)) { throw "MDM registration state is unknown (API result=$($probe.result))" }
    return ($probe.registered -eq 1)
}
function PolicyValues([string]$path) {
    $values = @{}
    if (Test-Path -LiteralPath $path) {
        $key = Get-Item -LiteralPath $path
        foreach ($name in $key.GetValueNames()) { $values[$name] = @{kind=[string]$key.GetValueKind($name);value=$key.GetValue($name)} }
    }
    return $values
}
function CheckPolicyValues($values, [string]$pattern, [bool]$current) {
    foreach ($name in @($values.Keys)) {
        if ($name -notmatch $pattern) { continue }
        $base = $name -replace '_(ProviderSet|WinningProvider)$',''
        $flag = $base + '_ProviderSet'; $winner = $base + '_WinningProvider'
        # Only explicit inactive current metadata is accepted. A default-valued
        # policy can still be enforced; comparing the value to Windows defaults
        # is not evidence of absence. Missing/contradictory metadata is unknown.
        if ($current -and $values.ContainsKey($flag) -and $values[$flag].kind -eq 'DWord' -and $values[$flag].value -is [int] -and $values[$flag].value -eq 0 -and
            (!$values.ContainsKey($winner) -or ($values[$winner].kind -eq 'String' -and $values[$winner].value -ceq ''))) { continue }
        if ($current -and $values.ContainsKey($base) -and $values.ContainsKey($flag) -and
            $values[$flag].kind -eq 'DWord' -and $values[$flag].value -is [int] -and $values[$flag].value -eq 1) {
            ThrowGate 'Relevant policy is configured: assessment only'
        }
        throw 'Relevant policy is configured or its authority is unknown: assessment only'
    }
}
function CheckScopedPolicy([string]$id) {
    $spec = PrivilegeRegistrySpec $id
    $service = PermissionService $id
    $areas = if ($null -ne $service) { @('SystemServices') + $(if ($service -eq 'BITS') { @('ADMX_BITS') } else { @('Update','ADMX_WindowsUpdate') }) }
        elseif ($null -ne $spec) { $spec.areas } elseif ($id.StartsWith('uac.')) { @('LocalPoliciesSecurityOptions') } elseif ($id.StartsWith('defender.')) { @('Defender','ADMX_MicrosoftDefenderAntivirus') } else { @('Firewall') }
    $pattern = if ($null -ne $spec) { $spec.policyPattern } elseif ($id.StartsWith('uac.')) { '^UserAccountControl_' } else { '.' }
    foreach ($area in $areas) {
        CheckPolicyValues (PolicyValues "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$area") $pattern $true
    }
    # Provider registration, schema/default catalogs, and power knobs are not
    # applied security policy. Inspect only relevant per-provider device areas;
    # a staged/orphaned relevant setting remains a conservative veto.
    $root = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
    if (Test-Path -LiteralPath $root) {
        foreach ($provider in @(Get-ChildItem -LiteralPath $root)) {
            foreach ($area in $areas) {
                CheckPolicyValues (PolicyValues (Join-Path $provider.PSPath "default\device\$area")) $pattern $false
            }
        }
    }
    $paths = if ($id.StartsWith('defender.')) { @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender') }
        elseif ($id.StartsWith('firewall.')) { @('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall','HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm') }
        elseif ($service -eq 'BITS') { @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\BITS') }
        elseif ($service -eq 'wuauserv') { @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') }
        else { @() }
    foreach ($path in $paths) { if (HasValues $path) { ThrowGate 'Configured management/security policy: assessment only' } }
    # AlwaysInstallElevated itself is the local preference being repaired. Its
    # presence (including our own target) cannot establish management authority.
    # Preserve other configured Installer policies rather than overriding them.
    if ($id -eq 'installer.always_install_elevated' -and (Test-Path -LiteralPath $spec.path)) {
        $key = Get-Item -LiteralPath $spec.path
        if (@($key.GetValueNames() | Where-Object { $_ -ne $spec.name }).Count -gt 0 -or $key.SubKeyCount -gt 0) { ThrowGate 'Other machine Installer policy is configured: assessment only' }
    }
}
function MissingRsopNamespace($exception) {
    # MI_RESULT_INVALID_NAMESPACE=3 / WBEM_E_INVALID_NAMESPACE=0x8004100E.
    # Never classify access denied, invalid class, provider failure, or a
    # localized exception message as an absent policy namespace.
    if ($exception -is [Microsoft.Management.Infrastructure.CimException]) {
        return ([int]$exception.NativeErrorCode -eq 3 -or $exception.HResult -eq 0x8004100E)
    }
    return ($exception -is [Runtime.InteropServices.COMException] -and $exception.HResult -eq 0x8004100E)
}
function CheckRsop([string]$id) {
    # A missing resultant namespace is normal on an unconfigured client. This
    # exception is considered only after domain/MDM/cloud and local artifacts
    # have been checked. All other query failures remain fatal.
    try { $gpos = @(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_GPO) }
    catch { if (MissingRsopNamespace $_.Exception) { return }; throw }
    foreach ($gpo in $gpos) {
        if ($gpo.id -isnot [string] -or [string]::IsNullOrWhiteSpace($gpo.id)) { throw 'Group Policy authority is unknown: assessment only' }
        if ($gpo.enabled -isnot [bool] -or $gpo.accessDenied -isnot [bool] -or $gpo.filterAllowed -isnot [bool] -or $gpo.accessDenied) { throw 'Group Policy authority is unknown: assessment only' }
        if ($null -ne (PermissionService $id) -and $gpo.id -ne 'LocalGPO') { ThrowGate 'Computer Group Policy evidence: service permissions are assessment only' }
        if ($gpo.enabled -and $gpo.filterAllowed -and $gpo.id -ne 'LocalGPO') { ThrowGate 'Applied computer Group Policy: assessment only' }
    }
    if ($null -ne (PermissionService $id)) {
        # RSOP_PolicySetting is the documented base for all client-side policy
        # extension settings. Enumerating derived instances catches security /
        # system-service policy too, rather than guessing an RSOP_SystemService
        # class name or treating INVALID_CLASS as absence. Only an empty local
        # policy is accepted for service DACL writes; any result is a veto.
        if (@(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_PolicySetting).Count -gt 0) { ThrowGate 'Applied computer policy settings: service permissions are assessment only' }
        return
    }
    # LocalGPO exists even when it has no settings. Inspect actual registry
    # policy and security-options results, not just the GPO container count.
    $pattern = if ($id.StartsWith('uac.')) { '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System(\\|$)' }
        elseif ($id.StartsWith('defender.')) { '\\SOFTWARE\\Policies\\Microsoft\\Windows Defender(\\|$)' }
        else { '\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall(\\|$)|\\Services\\SharedAccess\\Parameters\\FirewallPolicy(\\|$)' }
    $spec = PrivilegeRegistrySpec $id
    if ($null -ne $spec) { $pattern = [regex]::Escape($spec.path.Substring(5)) + '(\\|$)' }
    foreach ($setting in @(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_RegistryPolicySetting)) {
        if ($setting.registryKey -isnot [string] -or $setting.valueName -isnot [string]) { throw 'Group Policy authority is unknown: assessment only' }
        if (('\\' + $setting.registryKey) -match $pattern -and ($null -eq $spec -or $setting.valueName -eq $spec.name)) { ThrowGate 'Relevant resultant Group Policy: assessment only' }
    }
    foreach ($setting in @(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_RegistryValue)) {
        if ($setting.Path -isnot [string]) { throw 'Group Policy authority is unknown: assessment only' }
        if (('\\' + $setting.Path) -match $pattern -and ($null -eq $spec -or $setting.Path -match ('\\' + [regex]::Escape($spec.name) + '$'))) { ThrowGate 'Relevant resultant Group Policy: assessment only' }
    }
}
function Gate([string]$id) {
    $permissionService = PermissionService $id
    Load 'CimCmdlets'
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 10240 -or ![Environment]::Is64BitProcess) { throw 'Unsupported Windows client capability' }
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -isnot [bool]) { throw 'Domain membership is not readable' }
    if ($cs.PartOfDomain) { ThrowGate 'Domain-managed machine: assessment only' }
    # Enrollments contains built-in enrollment/provider templates on clean
    # Windows installations. Their mere presence does not mean active MDM.
    if (MdmRegistered) { ThrowGate 'Device is registered with MDM: assessment only' }
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts','HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo')) {
        if ((Test-Path -LiteralPath $p) -and @(Get-ChildItem -LiteralPath $p).Count -gt 0) { ThrowGate 'Enrollment or cloud-management evidence: assessment only' }
    }
    CheckScopedPolicy $id
    foreach ($pol in @('System32\GroupPolicy\Machine\Registry.pol','System32\GroupPolicy\gpt.ini')) {
        if (Test-Path -LiteralPath ([IO.Path]::Combine($env:SystemRoot, $pol))) { throw 'Local computer policy artifacts: assessment only' }
    }
    if ($null -ne (PrivilegeRegistrySpec $id) -or $null -ne $permissionService) {
        foreach ($pol in @('System32\GroupPolicy\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf','System32\GroupPolicy\Machine\Preferences\Registry\Registry.xml')) {
            if (Test-Path -LiteralPath ([IO.Path]::Combine($env:SystemRoot, $pol))) { throw 'Local computer policy artifacts: assessment only' }
        }
    }
    if ($null -ne $permissionService) {
        if (Test-Path -LiteralPath ([IO.Path]::Combine($env:SystemRoot, 'System32\GroupPolicy\Machine\Preferences\Services\Services.xml'))) { throw 'Local computer service policy artifacts: assessment only' }
    }
    CheckRsop $id
    if ($id.StartsWith('defender.') -or $id.StartsWith('firewall.')) {
        $class = if ($id.StartsWith('defender.')) { 'AntiVirusProduct' } else { 'FirewallProduct' }
        $providers = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName $class)
        foreach ($p in $providers) {
            # Exact built-in registration identity; unfamiliar providers, even inactive, block changes.
            if ($class -eq 'FirewallProduct' -or $p.instanceGuid -ne '{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}') { throw 'Additional or unrecognized security provider: assessment only' }
        }
        if ($class -eq 'AntiVirusProduct' -and $providers.Count -ne 1) { throw 'Defender provider registration cannot be established' }
    }
    if ($id.StartsWith('defender.')) {
        Load 'Defender'
        $s = Get-MpComputerStatus
        if ($s.IsTamperProtected -isnot [bool]) { throw 'Defender tamper-protection state is unknown' }
        if ($s.AMServiceEnabled -isnot [bool] -or $s.AntivirusEnabled -isnot [bool] -or !$s.AMServiceEnabled -or !$s.AntivirusEnabled -or $s.AMRunningMode -ne 'Normal' -or ($s.IsTamperProtected -and !(TamperExempt $id))) { throw 'Defender unavailable, passive, or tamper protected: assessment only' }
        $null = Get-MpPreference
    }
    if ($id.StartsWith('firewall.')) {
        Load 'NetSecurity'
        if ((Get-Service MpsSvc).Status -ne 'Running' -or (Get-Service BFE).Status -ne 'Running') { throw 'Firewall services unavailable' }
        $profile = $id.Split('.')[1]
        # Profile objects do not consistently expose rule-level source metadata.
        # Enumerate the store first: filtering an empty store with -Name throws
        # CmdletizationQuery_NotFound_Name on clean Windows. An empty successful
        # enumeration is no policy; an actual store/provider failure is fatal.
        $policy = @(Get-NetFirewallProfile -PolicyStore RSOP)
        foreach ($p in $policy) {
            if ([string]$p.Name -notin @('Domain','Private','Public')) { throw 'Firewall profile capability cannot be established' }
            if ([string]$p.Name -ne $profile) { continue }
            if ([string]$p.Enabled -notin @('True','False','NotConfigured') -or [string]$p.DefaultInboundAction -notin @('Block','Allow','NotConfigured') -or [string]$p.DefaultOutboundAction -notin @('Block','Allow','NotConfigured')) { throw 'Firewall profile capability cannot be established' }
            if ([string]$p.Enabled -ne 'NotConfigured' -or [string]$p.DefaultInboundAction -ne 'NotConfigured' -or [string]$p.DefaultOutboundAction -ne 'NotConfigured') { ThrowGate 'Firewall profile has resultant Group Policy: assessment only' }
        }
        $null = ReadEffectiveFirewall $id
    }
}
function TamperExempt([string]$id) {
    # Defender preferences that tamper protection does not guard.
    # Kept equal to src/hardening.rs (a Rust test enforces it).
    return ($id -in @('defender.pua','defender.script_nis','defender.asr.standard','defender.asr.web_script_email','defender.asr.office','defender.asr.ransomware_usb','defender.network_protection','defender.cloud_block_level','defender.cfa_watch','defender.cfa_block','defender.cfa_allowed_apps'))
}
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$defenderNames = @{ 'defender.realtime'='DisableRealtimeMonitoring'; 'defender.behavior'='DisableBehaviorMonitoring'; 'defender.ioav'='DisableIOAVProtection'; 'defender.archive'='DisableArchiveScanning' }
function PermissionService([string]$id) {
    switch -CaseSensitive ($id) {
        'permissions.service.bits' { return 'BITS' }
        'permissions.service.wuauserv' { return 'wuauserv' }
    }
    if ($id.StartsWith('permissions.', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unknown service permission control id' }
    return $null
}
function PermissionGate([string]$id, $inputValue) {
    if ($null -eq (PermissionService $id) -or $null -ne $inputValue) { throw 'Invalid service permission gate request' }
    $null = Gate $id
    return @{ok=$true}
}
function PrivilegeRegistrySpec([string]$id) {
    switch -CaseSensitive ($id) {
        'installer.always_install_elevated' { return @{path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer';name='AlwaysInstallElevated';target=0;unsafe=1;areas=@('ADMX_MSI','ApplicationManagement');policyPattern='.'} }
        'lsa.restrict_anonymous_sam' { return @{path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';name='RestrictAnonymousSAM';target=1;unsafe=0;areas=@('LocalPoliciesSecurityOptions');policyPattern='^NetworkAccess_DoNotAllowAnonymousEnumerationOfSAMAccounts($|_)'} }
        'lsa.limit_blank_password_use' { return @{path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';name='LimitBlankPasswordUse';target=1;unsafe=0;areas=@('LocalPoliciesSecurityOptions');policyPattern='^Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly($|_)'} }
        'wdigest.use_logon_credential' { return @{path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';name='UseLogonCredential';target=0;unsafe=1;areas=@('MSSecurityGuide');policyPattern='^WDigestAuthentication($|_)'} }
    }
    return $null
}
function ValidateBinaryRegistryState($state) {
    $names = if ($state -is [System.Collections.IDictionary]) { @($state.Keys) } else { @($state.PSObject.Properties.Name) }
    if ($names.Count -ne 2 -or $names -cnotcontains 'present' -or $names -cnotcontains 'value' -or $state.present -isnot [bool]) { throw 'Invalid binary registry state' }
    if ($state.present) {
        if (($state.value -isnot [int] -and $state.value -isnot [long] -and $state.value -isnot [uint32]) -or $state.value -notin @(0,1)) { throw 'Invalid binary registry DWORD' }
    } elseif ($null -ne $state.value) { throw 'Absent registry value must be null' }
}
function PrivilegeRepairable([string]$id, $state) {
    $spec = PrivilegeRegistrySpec $id
    if ($null -eq $spec) { throw 'Unknown privilege control' }
    ValidateBinaryRegistryState $state
    return ($state.present -and $state.value -eq $spec.unsafe)
}
function ReadControl([string]$id) {
    if ($null -ne (PermissionService $id)) { throw 'Service permissions require the native wrapper' }
    $spec = PrivilegeRegistrySpec $id
    if ($null -ne $spec) {
        if (!(Test-Path -LiteralPath $spec.path -ErrorAction Stop)) { return @{present=$false;value=$null} }
        $key = Get-Item -LiteralPath $spec.path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains $spec.name) { return @{present=$false;value=$null} }
        if ($key.GetValueKind($spec.name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'Privilege preference is not a DWORD' }
        $state = @{present=$true;value=$key.GetValue($spec.name)}
        ValidateBinaryRegistryState $state
        return $state
    }
    if ($defenderNames.ContainsKey($id)) {
        Load 'Defender'; $v=(Get-MpPreference).($defenderNames[$id])
        if ($v -isnot [bool]) { throw 'Defender preference is not a readable boolean' }
        return $v
    }
    if ($id -match '^firewall\.(domain|private|public)\.(enabled|inbound)$') {
        $profile=$Matches[1]; $kind=$Matches[2]
        Load 'NetSecurity'; $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -Name $profile)
        if ($profiles.Count -ne 1 -or $profiles[0].Name -isnot [string] -or $profiles[0].Name -ine $profile) { throw 'Firewall stored profile cannot be established' }
        $p=$profiles[0]
        if ($kind -eq 'enabled') {
            if ([string]$p.Enabled -notin @('True','False')) { throw 'Firewall enabled preference is not a concrete boolean' }
            return ([string]$p.Enabled -eq 'True')
        }
        if ([string]$p.DefaultInboundAction -notin @('Block','Allow','NotConfigured')) { throw 'Firewall inbound preference is not readable' }
        return [string]$p.DefaultInboundAction
    }
    $name = switch ($id) { 'uac.enabled' { 'EnableLUA' }; 'uac.consent' { 'ConsentPromptBehaviorAdmin' }; default { throw 'Unknown control' } }
    $k = Get-Item -LiteralPath $uacPath
    if ($k.GetValueNames() -notcontains $name) { return @{present=$false; value=$null} }
    if ($k.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'UAC value is not a DWORD' }
    return @{present=$true; value=$k.GetValue($name)}
}
function ReadEffectiveFirewall([string]$id) {
    if ($id -cnotmatch '^firewall\.(domain|private|public)\.(enabled|inbound)$') { throw 'Unknown firewall control' }
    $profile=$Matches[1]; $kind=$Matches[2]
    Load 'NetSecurity'
    foreach ($service in @('MpsSvc','BFE')) {
        $services = @(Get-Service $service)
        if ($services.Count -ne 1 -or [string]$services[0].Status -cne 'Running') { throw 'Firewall services unavailable' }
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $profile)
    if ($profiles.Count -ne 1 -or $profiles[0].Name -isnot [string] -or $profiles[0].Name -ine $profile) { throw 'Firewall effective profile cannot be established' }
    $p=$profiles[0]
    if ([string]$p.Enabled -cnotin @('True','False') -or [string]$p.DefaultInboundAction -cnotin @('Block','Allow')) { throw 'Firewall effective profile cannot be established' }
    if ($kind -ceq 'enabled') { return @{kind='enabled';value=([string]$p.Enabled -ceq 'True')} }
    return @{kind='inbound';value=([string]$p.DefaultInboundAction).ToLowerInvariant()}
}
function ObserveControl([string]$id) {
    $v=ReadControl $id
    $observation=@{value=$v;eligible=$true;reason='Eligible unmanaged local preference'}
    $firewall=$id -cmatch '^firewall\.(domain|private|public)\.(enabled|inbound)$'
    if ($firewall) {
        $observation.authority='unknown'; $observation.effective=$null
        # Independent of Gate: managed devices can still report verified runtime
        # evidence, but that evidence can never grant permission to change them.
        try { $observation.effective=ReadEffectiveFirewall $id } catch { }
    }
    try {
        $null = Gate $id
        if ($firewall) {
            # Authority probes can take time. Do not grant local eligibility
            # using only the effective snapshot taken before those probes.
            $observation.effective=$null
            $observation.effective=ReadEffectiveFirewall $id
            $observation.authority='local'
        }
        if ($id.StartsWith('uac.') -and (!$v.present -or $v.value -ne 0)) { $observation.eligible=$false; $observation.reason='Preserving absent or nonzero UAC preference' }
        if ($null -ne (PrivilegeRegistrySpec $id) -and !(PrivilegeRepairable $id $v)) { $observation.eligible=$false; $observation.reason='Preserving absent or already-safe machine preference' }
    } catch {
        $observation.eligible=$false; $observation.reason=$_.Exception.Message
        if ($firewall) { $observation.authority=GateAuthority $_ }
    }
    if ($firewall -and $observation.authority -ceq 'local') {
        if ($null -eq $observation.effective) {
            $observation.eligible=$false; $observation.authority='unknown'; $observation.reason='EffectiveFirewallUnavailable'
        } else {
            $effective=$observation.effective
            $mismatch=if ($effective.kind -ceq 'enabled') { $v -isnot [bool] -or $v -ne $effective.value }
                else { $v -cne 'NotConfigured' -and $v.ToLowerInvariant() -cne $effective.value }
            if ($mismatch) {
                $observation.eligible=$false; $observation.authority='unknown'; $observation.reason='EffectiveFirewallMismatch'
            }
        }
    }
    return $observation
}
function WriteControl([string]$id, $value) {
    if ($null -ne (PermissionService $id)) { throw 'Service permissions require the native wrapper' }
    $null = Gate $id
    $spec = PrivilegeRegistrySpec $id
    if ($null -ne $spec) {
        ValidateBinaryRegistryState $value
        $current = ReadControl $id
        ValidateBinaryRegistryState $current
        $repair = $value.present -and $value.value -eq $spec.target
        if ($repair -and !(PrivilegeRepairable $id $current)) { throw 'Privilege repair requires an explicitly unsafe current setting' }
        if (!$repair -and (!$current.present -or $current.value -ne $spec.target)) { throw 'Privilege restore requires the current target setting; preference changed before restore' }
        # No key creation: a repair requires an existing explicit unsafe value;
        # a restore requires an existing target. Only the fixed named value moves.
        if ($value.present) { New-ItemProperty -LiteralPath $spec.path -Name $spec.name -PropertyType DWord -Value ([int]$value.value) -Force -ErrorAction Stop | Out-Null }
        else { Remove-ItemProperty -LiteralPath $spec.path -Name $spec.name -ErrorAction Stop }
        $actual = ReadControl $id
        ValidateBinaryRegistryState $actual
        if ($actual.present -ne $value.present -or $actual.value -ne $value.value) { throw 'Privilege registry readback did not match; mutation outcome requires review' }
        return
    }
    if ($defenderNames.ContainsKey($id)) {
        $p = @{}; $p[$defenderNames[$id]] = [bool]$value
        Set-MpPreference @p
        # Set-MpPreference can succeed without applying a protected change. Check
        # the preference AND the available runtime status before acknowledging it.
        # Archive scanning has no corresponding runtime status field.
        $statusName = switch ($id) {
            'defender.realtime' { 'RealTimeProtectionEnabled' }
            'defender.behavior' { 'BehaviorMonitorEnabled' }
            'defender.ioav' { 'IoavProtectionEnabled' }
        }
        $verified = $false
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            $actual = ReadControl $id
            $status = Get-MpComputerStatus
            if ($status.IsTamperProtected -isnot [bool] -or $status.IsTamperProtected) { throw 'Defender tamper state changed or is unknown; mutation outcome requires review' }
            if ($status.AMServiceEnabled -isnot [bool] -or $status.AntivirusEnabled -isnot [bool] -or $status.AMServiceEnabled -ne $true -or $status.AntivirusEnabled -ne $true -or $status.AMRunningMode -ne 'Normal') { throw 'Defender became unavailable or passive; mutation outcome requires review' }
            $runtimeMatches = $true
            if ($null -ne $statusName) {
                $runtime = $status.($statusName)
                $runtimeMatches = $runtime -is [bool] -and $runtime -eq (!$value)
            }
            if ($actual -eq $value -and $runtimeMatches) { $verified = $true; break }
            if ($attempt -lt 9) { Start-Sleep -Milliseconds 500 }
        }
        if (!$verified) { throw 'Defender preference/runtime readback did not match; mutation outcome requires review' }
        return
    }
    if ($id -match '^firewall\.(domain|private|public)\.(enabled|inbound)$') {
        $profile=$Matches[1]; $enabled=$Matches[2] -eq 'enabled'
        if ($enabled) {
            if ($value -isnot [bool]) { throw 'Firewall enabled value must be a boolean' }
        } elseif ($value -isnot [string] -or $value -cnotin @('Block','Allow','NotConfigured')) { throw 'Invalid inbound action' }
        $p = @{PolicyStore='PersistentStore'; Name=$profile}
        # NetSecurity's GpoBoolean binder on Windows PowerShell 5.1 requires
        # enum-name tokens, not System.Boolean (including during restore).
        if ($enabled) { $p.Enabled = if ($value) { 'True' } else { 'False' } } else { $p.DefaultInboundAction = [string]$value }
        # Requery both stores and authority immediately before apply or restore.
        $current = ObserveControl $id
        if (!$current.eligible) { throw $current.reason }
        $null = Set-NetFirewallProfile @p
        $verified=$false
        for ($attempt=0; $attempt -lt 10; $attempt++) {
            $actual=ReadControl $id
            $effective=$null
            try { $effective=ReadEffectiveFirewall $id } catch { }
            # NotConfigured is a stored absence, not an effective action. Do
            # not replace it with Block/Allow during restore or invent a default.
            $runtimeMatches=if ($null -eq $effective) { $false }
                elseif ($enabled) { $effective.value -eq $value }
                elseif ($value -ceq 'NotConfigured') { $true }
                else { $effective.value -ceq $value.ToLowerInvariant() }
            if ($actual -eq $value -and $runtimeMatches) { $verified=$true; break }
            if ($attempt -lt 9) { Start-Sleep -Milliseconds 500 }
        }
        if (!$verified) { throw 'Firewall preference/effective readback did not match; mutation outcome requires review' }
        return
    }
    $name = if ($id -eq 'uac.enabled') { 'EnableLUA' } else { 'ConsentPromptBehaviorAdmin' }
    # A target write never lowers an existing nonzero consent mode. Restoration of
    # other values is permitted only through the typed Rust allowlist + engine journal.
    $current = ReadControl $id
    $target = if ($id -eq 'uac.enabled') { 1 } else { 5 }
    if ($value.present -and $value.value -eq $target -and (!$current.present -or $current.value -ne 0)) { throw 'UAC repair requires an explicitly disabled current setting' }
    if ((!$value.present -or $value.value -ne $target) -and (!$current.present -or $current.value -ne $target)) { throw 'UAC restore requires the current target setting; preference changed before restore' }
    if ($value.present) { New-ItemProperty -LiteralPath $uacPath -Name $name -PropertyType DWord -Value ([int]$value.value) -Force | Out-Null }
    else { Remove-ItemProperty -LiteralPath $uacPath -Name $name -ErrorAction Stop }
}
function Finding([string]$title, [scriptblock]$probe) {
    # Buffer the probe so output emitted before a provider failure cannot leak
    # into the JSON findings array alongside its unknown/error result.
    try {
        $result = @(& $probe)
        if ($result.Count -ne 1 -or $result[0] -isnot [System.Collections.IDictionary] -or $result[0].title -ne $title -or $result[0].status -notin @('ok','info','attention','unknown') -or $result[0].detail -isnot [string]) { throw 'Probe returned an invalid finding' }
        $result[0]
    } catch { @{title=$title; status='unknown'; detail=('Assessment unavailable: ' + $_.Exception.Message)} }
}
function FeatureState([string]$name) {
    # Windows optional features via WMI (served by the WMI service). The DISM
    # cmdlets start DismHost.exe, which the single-process job forbids.
    if ($name -cnotmatch '^[A-Za-z0-9-]+$') { throw 'Invalid feature name' }
    Load 'CimCmdlets'
    $hit = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='$name'" -OperationTimeoutSec 30)
    if ($hit.Count -gt 1) { throw 'The Windows feature list is ambiguous' }
    if ($hit.Count -eq 0) {
        if (@(Get-CimInstance -ClassName Win32_OptionalFeature -OperationTimeoutSec 60).Count -lt 5) { throw 'The Windows feature list is not readable' }
        return 'Missing'
    }
    switch ([int]$hit[0].InstallState) { 1 { return 'Enabled' } 2 { return 'Disabled' } 3 { return 'Missing' } }
    throw 'The Windows feature state is not readable'
}
function AutoLogonFinding {
    $key = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
    $names = @($key.GetValueNames())
    # Enumerate names only for DefaultPassword: never read, serialize or journal
    # its data, user names, domain names, or LSA secrets.
    $secretPresent = $names -contains 'DefaultPassword'
    $enabled = $false
    if ($names -contains 'AutoAdminLogon') {
        if ($key.GetValueKind('AutoAdminLogon') -ne [Microsoft.Win32.RegistryValueKind]::String) { throw 'AutoAdminLogon is not a string' }
        $flag = $key.GetValue('AutoAdminLogon')
        if ($flag -cnotin @('0','1')) { throw 'AutoAdminLogon has an unknown configuration' }
        $enabled = $flag -ceq '1'
    }
    return @{title='Automatic logon';status=$(if ($enabled -or $secretPresent) {'attention'} else {'info'});detail="AutoAdminLogon enabled=$enabled; Winlogon DefaultPassword value present=$secretPresent. Presence only: no password data is read. Passwords kept in the Windows secret store are not checked. Review who can use this computer; automatic logon is kept to avoid disrupting kiosk or sign-in workflows."}
}
function Findings {
    Finding 'Automatic logon' { AutoLogonFinding }
    Finding 'Security providers' {
        Load 'CimCmdlets'
        $av=@(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct)
        $fw=@(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct)
        @{title='Security providers';status='info';detail="Registered antivirus: $(($av | ForEach-Object { $_.displayName }) -join ', '); registered firewall: $(($fw | ForEach-Object { $_.displayName }) -join ', '). Registration alone does not establish provider health. Additional or unrecognized registrations block the corresponding Defender/firewall changes, even when reported inactive."}
    }
    Finding 'Windows Firewall' {
        Load 'NetSecurity'; $p=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
        if ($p.Count -ne 3) { throw 'Cannot read all effective firewall profiles' }
        @{title='Windows Firewall';status=$(if (@($p | Where-Object { [string]$_.Enabled -notin @('True','False') -or [string]$_.DefaultInboundAction -notin @('Block','Allow') }).Count) {'unknown'} elseif (@($p | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block' }).Count) {'attention'} else {'ok'});detail=(($p | ForEach-Object { "$($_.Name): enabled=$($_.Enabled), inbound=$($_.DefaultInboundAction), outbound=$($_.DefaultOutboundAction)" }) -join '; ') + '. ActiveStore values are shown; NotConfigured does not establish the effective default action. Rules and outbound preferences are preserved.'}
    }
    Finding 'Defender' {
        Load 'Defender'; $s=Get-MpComputerStatus; $p=Get-MpPreference
        $age = [math]::Floor(((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays)
        $paths=@($p.ExclusionPath | Where-Object { $null -ne $_ }).Count
        $processes=@($p.ExclusionProcess | Where-Object { $null -ne $_ }).Count
        $extensions=@($p.ExclusionExtension | Where-Object { $null -ne $_ }).Count
        @{title='Defender'; status=$(if ($s.AntivirusEnabled -and $s.RealTimeProtectionEnabled -and $s.BehaviorMonitorEnabled -and $s.IoavProtectionEnabled -and !$p.DisableArchiveScanning -and $age -ge 0 -and $age -le 7) {'ok'} else {'attention'}); detail="Mode=$($s.AMRunningMode); service=$($s.AMServiceEnabled); antivirus=$($s.AntivirusEnabled); realtime=$($s.RealTimeProtectionEnabled); behavior=$($s.BehaviorMonitorEnabled); IOAV=$($s.IoavProtectionEnabled); archive preference disabled=$($p.DisableArchiveScanning); tamper protected=$($s.IsTamperProtected); signatures=$($s.AntivirusSignatureVersion), updated=$($s.AntivirusSignatureLastUpdated), age days=$age. Check Windows Security for effective protection and signature updates. Exclusion counts: paths=$paths, processes=$processes, extensions=$extensions; hidden exclusions cannot be ruled out. Exclusions are preserved."}
    }
    Finding 'Windows lifecycle' {
        Load 'CimCmdlets'; $s=Get-CimInstance Win32_OperatingSystem
        @{title='Windows lifecycle'; status=$(if ([int]$s.BuildNumber -lt 22000) {'attention'} else {'info'}); detail="OS=$($s.Caption); version=$($s.Version); build=$($s.BuildNumber). Standard Windows 10 support ended October 14, 2025. ESU enrollment and LTSC/IoT editions have different support terms; enrollment/support entitlement is not verified. Windows 11 support depends on release and edition; check Microsoft's lifecycle information."}
    }
    Finding 'Device encryption' {
        # Two documented read-only WMI methods. Get-BitLockerVolume needs module
        # autoloading (off here) and materializes key-protector data internally.
        Load 'CimCmdlets'
        $rows=@(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -OperationTimeoutSec 5 | Select-Object -First 65)
        if ($rows.Count -eq 0 -or $rows.Count -gt 64) { throw 'No readable volume status' }
        $protection=@('Off','On','Unknown'); $conversion=@('FullyDecrypted','FullyEncrypted','EncryptionInProgress','DecryptionInProgress','EncryptionPaused','DecryptionPaused')
        $v=@(foreach ($row in $rows) {
            $p=Invoke-CimMethod -InputObject $row -MethodName GetProtectionStatus -OperationTimeoutSec 5
            $c=Invoke-CimMethod -InputObject $row -MethodName GetConversionStatus -OperationTimeoutSec 5
            if ($p.ReturnValue -ne 0 -or $c.ReturnValue -ne 0) { throw 'Cannot read volume status' }
            $pi=[int]$p.ProtectionStatus; $ci=[int]$c.ConversionStatus
            if ($pi -lt 0 -or $pi -ge $protection.Count -or $ci -lt 0 -or $ci -ge $conversion.Count) { throw 'Unknown volume status' }
            @{MountPoint=[string]$row.DriveLetter; ProtectionStatus=$protection[$pi]; VolumeStatus=$conversion[$ci]}
        })
        @{title='Device encryption'; status=$(if (@($v | Where-Object {$_.ProtectionStatus -ne 'On'}).Count) {'attention'} else {'ok'}); detail=(($v | ForEach-Object { "$($_.MountPoint): protection=$($_.ProtectionStatus), state=$($_.VolumeStatus)" }) -join '; ') + '. Recovery-key backup is not verified.'}
    }
    Finding 'Secure Boot' { Load 'SecureBoot'; $v=Confirm-SecureBootUEFI; @{title='Secure Boot';status=$(if ($v) {'ok'} else {'attention'});detail="Secure Boot enabled=$v. Unsupported firmware or inaccessible status is reported as unknown."} }
    Finding 'Windows updates' {
        $session=New-Object -ComObject Microsoft.Update.Session
        $search=$session.CreateUpdateSearcher(); $search.Online=$false
        $r=$search.Search('IsInstalled=0 and IsHidden=0')
        if ($r.ResultCode -ne 2) { throw 'Offline update query did not fully succeed' }
        @{title='Windows updates';status='info';detail="Locally cached pending updates=$($r.Updates.Count). This offline result does not establish current patch compliance; open Windows Update and check for updates."}
    }
    Finding 'Remote Desktop' { $v=Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'; $homeEdition=([string](Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID')) -cmatch '^Core'; @{title='Remote Desktop';status=$(if ($v -eq 1 -or $homeEdition) {'ok'} else {'attention'});detail="Deny incoming Remote Desktop connections=$v; Windows Home=$homeEdition. Review need, network use and Network Level Authentication; no changes made."} }
    Finding 'SMB1' { $v=FeatureState 'SMB1Protocol'; @{title='SMB1';status=$(if ($v -cin @('Disabled','Missing')) {'ok'} else {'attention'});detail="SMB1 optional feature state=$v. Review dependencies before removing legacy protocol support."} }
    @{title='SmartScreen';status='info';detail='Review reputation-based protection and SmartScreen in Windows Security and your browser. Per-user, browser and policy settings differ; effective protection is not inferred from a single registry value.'}
    Finding 'Memory integrity' { Load 'CimCmdlets'; $v=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; @{title='Memory integrity';status=$(if ($v.SecurityServicesRunning -contains 2) {'ok'} else {'attention'});detail="HVCI running=$($v.SecurityServicesRunning -contains 2); configured=$($v.SecurityServicesConfigured -contains 2). Review Core isolation in Windows Security and driver compatibility before enabling."} }
    Finding 'Management and mutation eligibility' { Gate 'uac.enabled'; @{title='Management and mutation eligibility';status='info';detail='No device-management registration or UAC policy authority found by the available probes. Each control repeats scoped policy and capability checks before mutation.'} }
}
try {
    switch -CaseSensitive ($action) {
        'permission_gate' { Emit (PermissionGate $id $value) }
        'machine' { $v=Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid'; if ($v -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Invalid MachineGuid' }; Emit $v }
        'observe' { Emit (ObserveControl $id) }
        'write' { WriteControl $id $value; Emit @{ok=$true} }
        'findings' { Emit @(Findings) }
        default { throw 'Unknown operation' }
    }
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
