# Extended hardening controls, appended to the backend definitions (never the backend dispatcher)
# for ids in the compiled Rust catalog. $hardeningSpecJson comes from that catalog; all state is a
# slice {items: {key: int|string|null}}; null is "not configured", a string is a REG_SZ value (rule 'text').
# Other kinds are never read as text or replaced. Writes can only move a key
# between its recorded unsafe original and the fixed value (HFixOf). No native child processes,
# except the DISM feature writes, ReAgentc.exe and netsh.exe (one adapter's random Wi-Fi address).
$spec = ConvertFrom-Json -InputObject $hardeningSpecJson

function HEq($a, $b) {
    if ($null -eq $a -or $null -eq $b) { return ($null -eq $a -and $null -eq $b) }
    if ($a -is [string] -or $b -is [string]) { return ($a -is [string] -and $b -is [string] -and $a -ceq $b) }
    return ([int64]$a -eq [int64]$b)
}
function HDef([string]$name) {
    if ($spec.dynamic) { return $spec.keys[0] }
    foreach ($k in @($spec.keys)) { if ($k.name -ceq $name) { return $k } }
    throw 'Unknown hardening item'
}
function HNameOk([string]$name) {
    if (!$spec.dynamic) { foreach ($k in @($spec.keys)) { if ($k.name -ceq $name) { return $true } }; return $false }
    if ($spec.source -ceq 'FirewallExposure') { return ($name -cmatch '^(FPS|NETDIS)-[A-Za-z0-9_.-]{1,92}$') }
    if ($spec.source -ceq 'NetbiosAdapters' -or $spec.source -ceq 'WifiRandomAddress') { return ($name -cmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') }
    if ($spec.source -ceq 'LegacyServices') { return ((HServiceNames) -ccontains $name) }
    if ($spec.source -ceq 'DefenderExclusions') { return (HExclusionNameOk $name) }
    if ($spec.source -ceq 'UnquotedServices') { return ($name.Length -ge 1 -and $name.Length -le 256 -and $name -cnotmatch '[\x00-\x1f\x7f-\x9f"\\/*?\[\]]' -and $name.Trim() -ceq $name) }
    if ($spec.source -ceq 'UserDirFirewall') { return ($name.Length -ge 1 -and $name.Length -le 200 -and $name -cnotmatch '[\x00-\x1f\x7f"*?\[\]]' -and $name.Trim() -ceq $name) }
    if ($spec.source -ceq 'HostsFile') { return ($name -ceq 'hosts') }
    if ($spec.source -ceq 'StartupItems') {
        if ($name.Length -gt 260 -or $name -cnotmatch '^(run-machine|run-machine32|run-user|folder-machine|folder-user|task):[^\x00-\x1f\x7f"*?\[\]]+$' -or $name.Trim() -cne $name) { return $false }
        if ($name.StartsWith('task:') -and !$name.StartsWith('task:\')) { return $false }
        return !$name.EndsWith('\')
    }
    if ($spec.source -ceq 'StaleAccounts') { return (HStaleNameOk $name) }
    if ($spec.source -ceq 'ShareGrants') { return (HShareNameOk $name) }
    if ($spec.source -ceq 'BrowserExtensions') { return (HAddonNameOk $name) }
    if ($spec.source -ceq 'CfaAllowedApps') { return (HCfaAppNameOk $name) }
    return ($name.Length -ge 1 -and $name.Length -le 64 -and $name -cnotmatch '[\x00-\x1f\x7f"]' -and $name.Trim() -ceq $name)
}
function HIsSafe($def, $v) {
    if ($def.rule -ceq 'text') {
        if ($null -eq $v) { return [bool]$def.absentSafe }
        if ($v -isnot [string]) { return $false }
        return (@($def.safe) -ccontains $v)
    }
    if ($v -is [string]) { return $false }
    if ($def.rule -ceq 'exposure') {
        if ($null -eq $v) { return $false }
        return !((([int]$v -band 8) -ne 0) -and (([int]$v -band 4) -ne 0))
    }
    if ($null -eq $v) { return [bool]$def.absentSafe }
    return (@($def.safe) -contains [int64]$v)
}
function HFixOf($def, $v) {
    if (HIsSafe $def $v) { return $v }
    if ($def.rule -ceq 'exposure') {
        if ($null -eq $v) { return $null }
        if (([int]$v -band 3) -eq 0) { return ([int]$v -band (-bnot 8)) }
        return ([int]$v -band (-bnot 4))
    }
    return $def.fix
}
function HAnyUnsafe($slice) {
    foreach ($name in @($slice.Keys)) { if (!(HIsSafe (HDef $name) $slice[$name])) { return $true } }
    return $false
}

function HValueName($def) {
    if ($null -ne $def.PSObject.Properties['valueName'] -and [string]$def.valueName) { return [string]$def.valueName }
    return [string]$def.name
}
function HReadRegistry($def) {
    if (!(Test-Path -LiteralPath $def.path -ErrorAction Stop)) { return $null }
    $key = Get-Item -LiteralPath $def.path -ErrorAction Stop
    $vn = HValueName $def
    if ($key.GetValueNames() -notcontains $vn) { return $null }
    if ($def.rule -ceq 'text') {
        if ($key.GetValueKind($vn) -ne [Microsoft.Win32.RegistryValueKind]::String) { throw "$vn is not text" }
        $text = $key.GetValue($vn)
        if ($text -isnot [string]) { throw "$vn is not text" }
        return $text
    }
    if ($key.GetValueKind($vn) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw "$vn is not a DWORD" }
    $n = [int64]$key.GetValue($vn)
    # DWORDs are unsigned: 0xFFFFFFFF reads back as -1.
    if ($n -lt 0) { $n += 4294967296 }
    return $n
}
$hMaps = @('Disabled','Basic','Advanced')
$hPua = @('Disabled','Enabled','AuditMode')
$hNp = @('Disabled','Enabled','AuditMode')
$hCfa = @('Disabled','Enabled','AuditMode','BlockDiskModificationsOnly','AuditDiskModificationsOnly')
$hCfaMaxApps = 24
$hCfaEventDays = 7
$hCfaSeen = @{}
$hCbl = @{ Default = 0; Moderate = 1; High = 2; HighPlus = 4; ZeroTolerance = 6 }
function HCloudLevel($v) {
    if ($null -eq $v) { throw 'Defender preference is not readable' }
    if ($v -is [string]) {
        if (!$hCbl.ContainsKey($v)) { throw 'Defender preference is not readable' }
        return [int]$hCbl[$v]
    }
    $n = [int]$v
    if (@(0,1,2,4,6) -notcontains $n) { throw 'Defender preference is not readable' }
    return $n
}
function HEnumNumber($v, [string[]]$names) {
    if ($null -eq $v) { throw 'Defender preference is not readable' }
    if ($v -is [string]) {
        $i = [array]::IndexOf($names, $v)
        if ($i -lt 0) { throw 'Defender preference is not readable' }
        return $i
    }
    return [int]$v
}
function HReadDefenderPref() {
    Load 'Defender'
    $p = Get-MpPreference
    $out = @{}
    foreach ($def in @($spec.keys)) {
        # Newer Defender platforms drop retired preferences (for example
        # DisableIntrusionPreventionSystem); a missing property reads as unset.
        $prop = $p.PSObject.Properties[$def.name]
        $raw = if ($null -ne $prop) { $prop.Value } else { $null }
        if ($def.name -ceq 'MAPSReporting') { $out[$def.name] = HEnumNumber $raw $hMaps }
        elseif ($def.name -ceq 'PUAProtection') { $out[$def.name] = HEnumNumber $raw $hPua }
        elseif ($def.name -ceq 'EnableNetworkProtection') {
            # Editions without the feature may not report it: treat as off, never as protected.
            if ($null -eq $raw) { $out[$def.name] = 0 } else { $out[$def.name] = HEnumNumber $raw $hNp }
        }
        elseif ($def.name -ceq 'EnableControlledFolderAccess') { $out[$def.name] = HCfaModeNumber $raw }
        elseif ($def.name -ceq 'CloudBlockLevel') { $out[$def.name] = HCloudLevel $raw }
        elseif ($def.name -ceq 'CloudExtendedTimeout') {
            if ($null -eq $raw) { throw 'Defender preference is not readable' }
            $out[$def.name] = [int]$raw
        }
        else {
            # Disable* preferences: absent means Defender's default (feature on).
            if ($null -eq $raw) { $out[$def.name] = 0 }
            elseif ($raw -isnot [bool]) { throw 'Defender preference is not a readable boolean' }
            else { $out[$def.name] = [int]$raw }
        }
    }
    return $out
}
function HReadAsr() {
    Load 'Defender'
    $p = Get-MpPreference
    $ids = @($p.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
    $acts = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    if ($ids.Count -ne $acts.Count) { throw 'Attack surface rule lists are inconsistent' }
    $out = @{}
    foreach ($def in @($spec.keys)) { $out[$def.name] = $null }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $guid = ([string]$ids[$i]).ToLowerInvariant()
        if ($out.ContainsKey($guid)) { $out[$guid] = [int]$acts[$i] }
    }
    return $out
}
function HNetModals() {
    # Documented NetUserModalsGet/Set (netapi32) for the local account policy.
    # ADSI cannot reach it on workgroup PCs. Reflection.Emit creates only a
    # P/Invoke stub: no Add-Type, so no csc.exe child process.
    if ($null -ne ('Secblitz.NetModals' -as [type])) { return }
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly([Reflection.AssemblyName]::new('Secblitz.NetModals'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('Secblitz.NetModals')
    $type = $module.DefineType('Secblitz.NetModals', [Reflection.TypeAttributes]'Public, Abstract, Sealed')
    $dll = [IO.Path]::Combine($env:SystemRoot, 'System32\netapi32.dll')
    $signatures = @(
        @{ name = 'NetUserModalsGet'; args = [Type[]]@([IntPtr], [uint32], [IntPtr].MakeByRefType()) },
        @{ name = 'NetUserModalsSet'; args = [Type[]]@([IntPtr], [uint32], [IntPtr], [uint32].MakeByRefType()) },
        @{ name = 'NetApiBufferFree'; args = [Type[]]@([IntPtr]) }
    )
    foreach ($sig in $signatures) {
        $method = $type.DefinePInvokeMethod($sig.name, $dll, $sig.name, [Reflection.MethodAttributes]'Public, Static, PinvokeImpl', [Reflection.CallingConventions]::Standard, [uint32], $sig.args, [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
    }
    $null = $type.CreateType()
}
function HLockoutInfo() {
    # Level 3: USER_MODALS_INFO_3 { duration; observation window; threshold }.
    HNetModals
    $buffer = [IntPtr]::Zero
    $status = [Secblitz.NetModals]::NetUserModalsGet([IntPtr]::Zero, [uint32]3, [ref]$buffer)
    if ($status -ne 0 -or $buffer -eq [IntPtr]::Zero) { throw 'Lockout threshold is not readable' }
    try { $info = @(0, 4, 8 | ForEach-Object { [Runtime.InteropServices.Marshal]::ReadInt32($buffer, $_) }) }
    finally { $null = [Secblitz.NetModals]::NetApiBufferFree($buffer) }
    if ($info[2] -lt 0) { throw 'Lockout threshold is not readable' }
    return $info
}
function HReadLockout() {
    return @{ LockoutThreshold = [int](HLockoutInfo)[2] }
}
function HBuiltinAdmin() {
    Load 'Microsoft.PowerShell.LocalAccounts'
    $found = @(Get-LocalUser | Where-Object { $_.SID.Value -cmatch '^S-1-5-21-[0-9-]+-500$' })
    if ($found.Count -ne 1) { throw 'Built-in Administrator account cannot be identified' }
    return $found[0]
}
function HReadBuiltinAdmin() {
    $a = HBuiltinAdmin
    if ($a.Enabled -isnot [bool]) { throw 'Administrator state is not readable' }
    return @{ Enabled = [int]$a.Enabled }
}
function HReadFirewall() {
    Load 'NetSecurity'
    $out = @{}
    $rules = @()
    foreach ($pattern in @('FPS-*','NETDIS-*')) {
        try { $rules += @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $pattern -ErrorAction Stop) }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    }
    foreach ($r in $rules) {
        $name = [string]$r.Name
        if (!(HNameOk $name)) { continue }
        if ([string]$r.Direction -cne 'Inbound' -or [string]$r.Action -cne 'Allow') { continue }
        $bits = [int]$r.Profile -band 7
        if ($bits -eq 0) { $bits = 7 }
        $enabled = [string]$r.Enabled -ceq 'True'
        if ([string]$r.Enabled -cnotin @('True','False')) { continue }
        $out[$name] = $bits + $(if ($enabled) { 8 } else { 0 })
    }
    return $out
}
function HWlanRoot() {
    return [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'Microsoft\Wlansvc\Profiles\Interfaces')
}
function HLoadXml([string]$path) {
    # DTDs prohibited and no resolver: profile files are data, never instructions.
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($path, $settings)
    try { $doc = [Xml.XmlDocument]::new(); $doc.Load($reader) } finally { $reader.Dispose() }
    return $doc
}
function HXmlText($doc, [string]$name) {
    $node = $doc.SelectSingleNode("//*[local-name()='$name']")
    if ($null -eq $node) { return '' }
    return [string]$node.InnerText
}
function HWlanProfiles() {
    # Saved all-user profiles with a weak or no security type. Reads profile
    # files only (never key material) so no external process is needed.
    $root = HWlanRoot
    $list = @()
    if (!(Test-Path -LiteralPath $root)) { return $list }
    foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory)) {
        $iface = [Guid]::Empty
        if (![Guid]::TryParse($dir.Name, [ref]$iface)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir.FullName -Filter '*.xml' -File)) {
            $doc = HLoadXml $file.FullName
            $name = HXmlText $doc 'name'
            $mode = HXmlText $doc 'connectionMode'
            $auth = HXmlText $doc 'authentication'
            $enc = HXmlText $doc 'encryption'
            $oneX = HXmlText $doc 'useOneX'
            if (!(HNameOk $name) -or $mode -cnotin @('auto','manual') -or $oneX -ceq 'true') { continue }
            $risky = ($auth -ceq 'open' -and $enc -ceq 'none') -or ($enc -ceq 'WEP') -or ($auth -ceq 'shared') -or
                (($auth -ceq 'WPAPSK' -or $auth -ceq 'WPA') -and $enc -ceq 'TKIP')
            if ($risky) { $list += @{ name = $name; value = $(if ($mode -ceq 'auto') { 1 } else { 0 }); iface = $iface; file = $file.FullName } }
        }
    }
    return $list
}
function HReadWifi() {
    $out = @{}
    $dupes = @{}
    foreach ($p in @(HWlanProfiles)) {
        if ($out.ContainsKey($p.name) -or $dupes.ContainsKey($p.name)) { $dupes[$p.name] = $true; $out.Remove($p.name); continue }
        $out[$p.name] = $p.value
    }
    return $out
}
# Adapters are found by media type (Native 802.11), which is the same in every language. The setting is read from the
# Wi-Fi service's own key (a DWORD; absent means off). The display text of netsh is never parsed.
function HWifiAdapters() {
    Load 'CimCmdlets'
    $list = @()
    foreach ($a in @(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetAdapter')) {
        if ($null -eq $a.NdisPhysicalMedium -or [int64]$a.NdisPhysicalMedium -ne 9) { continue }
        $guid = [Guid]::Empty
        if (![Guid]::TryParse([string]$a.InterfaceGuid, [ref]$guid)) { continue }
        $id = '{' + $guid.ToString().ToUpperInvariant() + '}'
        if (!(HNameOk $id)) { continue }
        $list += @{ id = $id; name = [string]$a.Name }
    }
    return $list
}
function HWifiRandomState([string]$id) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SOFTWARE\Microsoft\WlanSvc\Interfaces\' + $id), $false)
    if ($null -eq $key) { return $null }
    try {
        if (@($key.GetValueNames()) -notcontains 'RandomMacState') { return 0 }
        if ($key.GetValueKind('RandomMacState') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { return $null }
        return [int]$key.GetValue('RandomMacState')
    } finally { $key.Dispose() }
}
function HReadWifiRandom() {
    $out = @{}
    $dupes = @{}
    foreach ($a in @(HWifiAdapters)) {
        $n = HWifiRandomState $a.id
        if ($null -eq $n -or @(0,1) -notcontains [int]$n) { continue }
        # Two adapters with one id are ambiguous: leave them alone.
        if ($out.ContainsKey($a.id) -or $dupes.ContainsKey($a.id)) { $dupes[$a.id] = $true; $out.Remove($a.id); continue }
        $out[$a.id] = [int]$n
    }
    return $out
}
function HWifiRandomPreflight() {
    if (@(HWifiAdapters).Count -eq 0) { throw 'Not offered: this computer has no Wi-Fi adapter' }
    if ((HReadWifiRandom).Count -eq 0) { throw 'Not offered: the Wi-Fi settings of this computer could not be read' }
}
function HReadNetbios() {
    Load 'CimCmdlets'
    $out = @{}
    $dupes = @{}
    foreach ($c in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True')) {
        $id = [string]$c.SettingID
        if (!(HNameOk $id) -or $null -eq $c.TcpipNetbiosOptions) { continue }
        $n = [int]$c.TcpipNetbiosOptions
        if (@(0,1,2) -notcontains $n) { continue }
        # Two configurations with one id are ambiguous: leave them alone.
        if ($out.ContainsKey($id) -or $dupes.ContainsKey($id)) { $dupes[$id] = $true; $out.Remove($id); continue }
        $out[$id] = $n
    }
    return $out
}
$hOutboundRule = 'Secblitz-Block-Outbound-SMB-Internet'
$hOutboundName = 'Secblitz: block outbound file sharing to the internet'
function HReadOutbound() {
    Load 'NetSecurity'
    try { $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $hOutboundRule -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; return @{ RulePresent = 0 } }
    if ($rules.Count -eq 0) { return @{ RulePresent = 0 } }
    if ($rules.Count -ne 1) { throw 'The Secblitz firewall rule exists more than once' }
    $r = $rules[0]
    $ports = @($r | Get-NetFirewallPortFilter | ForEach-Object { $_.RemotePort } | ForEach-Object { [string]$_ })
    $proto = @($r | Get-NetFirewallPortFilter | ForEach-Object { [string]$_.Protocol })
    $addr = @($r | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress } | ForEach-Object { [string]$_ })
    $same = [string]$r.Direction -ceq 'Outbound' -and [string]$r.Action -ceq 'Block' -and [string]$r.Enabled -ceq 'True' -and
        $proto.Count -eq 1 -and $proto[0] -ceq 'TCP' -and $ports.Count -eq 2 -and $ports -contains '445' -and $ports -contains '139' -and
        $addr.Count -eq 1 -and $addr[0] -ieq 'Internet'
    if (!$same) { throw 'A firewall rule with the Secblitz name exists but is different; it was left alone' }
    return @{ RulePresent = 1 }
}
function HRead() {
    switch -CaseSensitive ($spec.source) {
        'Registry' { $out = @{}; foreach ($def in @($spec.keys)) { $out[$def.name] = HReadRegistry $def }; return $out }
        'DefenderPref' { return (HReadDefenderPref) }
        'DefenderAsr' { return (HReadAsr) }
        'Lockout' { return (HReadLockout) }
        'BuiltinAdmin' { return (HReadBuiltinAdmin) }
        'FirewallExposure' { return (HReadFirewall) }
        'WifiProfiles' { return (HReadWifi) }
        'NetbiosAdapters' { return (HReadNetbios) }
        'WifiRandomAddress' { return (HReadWifiRandom) }
        'FirewallOutbound' { return (HReadOutbound) }
        'ExploitMitigations' { return (HReadMitigations) }
        'PowerShellV2' { return (HReadPowerShellV2) }
        'LegacyServices' { return (HReadServices) }
        'LockOnWake' { return (HReadLockOnWake) }
        'UpdatePause' { return (HReadPause) }
        'SmartScreen' { return (HReadSmartScreen) }
        'DefenderExclusions' { return (HReadExclusions) }
        'WinlogonAutoLogon' { return (HReadAutoLogon) }
        'SmbFeature' { return (HReadSmb1) }
        'UnquotedServices' { return (HReadUnquoted) }
        'UserDirFirewall' { return (HReadUserDirFirewall) }
        'HostsFile' { return (HReadHosts) }
        'StartupItems' { return (HReadStartup) }
        'StaleAccounts' { return (HReadStale) }
        'ShareGrants' { return (HReadShares) }
        'BrowserExtensions' { return (HReadExtensions) }
        'CfaAllowedApps' { return (HReadCfaApps) }
        'RecoveryTools' { return (HReadRecovery) }
    }
    throw 'Unknown hardening source'
}

function HGateCommon() {
    Load 'CimCmdlets'
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 10240 -or ![Environment]::Is64BitProcess) { throw 'Unsupported Windows client capability' }
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -isnot [bool]) { throw 'Domain membership is not readable' }
    if ($cs.PartOfDomain) { ThrowGate 'Domain-managed machine: assessment only' }
    if (MdmRegistered) { ThrowGate 'Device is registered with MDM: assessment only' }
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts','HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo')) {
        if ((Test-Path -LiteralPath $p) -and @(Get-ChildItem -LiteralPath $p).Count -gt 0) { ThrowGate 'Enrollment or cloud-management evidence: assessment only' }
    }
}
function HRegistryPaths() {
    $paths = @()
    foreach ($def in @($spec.keys)) { if ($def.path) { $paths += @{ path = [string]$def.path; name = (HValueName $def) } } }
    foreach ($pv in @($spec.gate.policyValues)) { $paths += @{ path = [string]$pv.path; name = [string]$pv.name } }
    return $paths
}
function HRsop() {
    try { $gpos = @(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_GPO) }
    catch { if (MissingRsopNamespace $_.Exception) { return }; throw }
    foreach ($gpo in $gpos) {
        if ($gpo.id -isnot [string] -or [string]::IsNullOrWhiteSpace($gpo.id)) { throw 'Group Policy authority is unknown: assessment only' }
        if ($gpo.enabled -isnot [bool] -or $gpo.accessDenied -isnot [bool] -or $gpo.filterAllowed -isnot [bool] -or $gpo.accessDenied) { throw 'Group Policy authority is unknown: assessment only' }
        if ($gpo.enabled -and $gpo.filterAllowed -and $gpo.id -ne 'LocalGPO') { ThrowGate 'Applied computer Group Policy: assessment only' }
    }
    $watch = @(HRegistryPaths)
    if ($watch.Count -eq 0) { return }
    foreach ($setting in @(Get-CimInstance -Namespace root\rsop\computer -ClassName RSOP_RegistryPolicySetting)) {
        if ($setting.registryKey -isnot [string] -or $setting.valueName -isnot [string]) { throw 'Group Policy authority is unknown: assessment only' }
        foreach ($w in $watch) {
            $pattern = [regex]::Escape($w.path.Substring(5)) + '(\\|$)'
            if (('\' + $setting.registryKey) -match $pattern -and $setting.valueName -eq $w.name) { ThrowGate 'Relevant resultant Group Policy: assessment only' }
        }
    }
}
function HGatePolicy() {
    foreach ($area in @($spec.gate.areas)) {
        CheckPolicyValues (PolicyValues "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\$area") $spec.gate.pattern $true
    }
    $root = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
    if ((@($spec.gate.areas)).Count -gt 0 -and (Test-Path -LiteralPath $root)) {
        foreach ($provider in @(Get-ChildItem -LiteralPath $root)) {
            foreach ($area in @($spec.gate.areas)) {
                CheckPolicyValues (PolicyValues (Join-Path $provider.PSPath "default\device\$area")) $spec.gate.pattern $false
            }
        }
    }
    foreach ($pv in @($spec.gate.policyValues)) {
        if (Test-Path -LiteralPath $pv.path) {
            $key = Get-Item -LiteralPath $pv.path
            if ($key.GetValueNames() -contains $pv.name) { ThrowGate 'Relevant policy is configured: assessment only' }
        }
    }
    $own = [string]$spec.gate.ownPolicyKey
    if ($own) {
        if (Test-Path -LiteralPath $own) {
            $key = Get-Item -LiteralPath $own
            $ours = @(@($spec.keys) | ForEach-Object { $_.name })
            if ($null -ne $spec.gate.PSObject.Properties['sharedValues']) { $ours += @($spec.gate.sharedValues) }
            if (@($key.GetValueNames() | Where-Object { $_ -and $ours -cnotcontains $_ }).Count -gt 0 -or $key.SubKeyCount -gt 0) { ThrowGate 'Relevant policy is configured: assessment only' }
        }
    }
    $artifacts = @('System32\GroupPolicy\Machine\Registry.pol','System32\GroupPolicy\gpt.ini')
    if ($spec.gate.secedit) { $artifacts += @('System32\GroupPolicy\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf') }
    foreach ($pol in $artifacts) {
        if (Test-Path -LiteralPath ([IO.Path]::Combine($env:SystemRoot, $pol))) { throw 'Local computer policy artifacts: assessment only' }
    }
}
function HGateFirewall() {
    Load 'CimCmdlets'; Load 'NetSecurity'
    foreach ($service in @('MpsSvc','BFE')) {
        $s = @(Get-Service $service)
        if ($s.Count -ne 1 -or [string]$s[0].Status -cne 'Running') { throw 'Firewall services unavailable' }
    }
    if (@(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct).Count -gt 0) { throw 'Additional or unrecognized security provider: assessment only' }
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore RSOP)) {
        if ([string]$p.Enabled -ne 'NotConfigured' -or [string]$p.DefaultInboundAction -ne 'NotConfigured' -or [string]$p.DefaultOutboundAction -ne 'NotConfigured') { ThrowGate 'Firewall profile has resultant Group Policy: assessment only' }
    }
    try { $rsopRules = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $rsopRules = @() }
    if ($rsopRules.Count -gt 0) { ThrowGate 'Firewall profile has resultant Group Policy: assessment only' }
}
function HGateWifi() {
    foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Wireless','HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc')) {
        if (HasValues $p) { ThrowGate 'Configured management/security policy: assessment only' }
    }
}
function HGate() {
    if ($spec.id.StartsWith('defender.')) { $null = Gate $spec.id; return }
    HGateCommon
    HGatePolicy
    HRsop
    if ($spec.source -ceq 'FirewallExposure' -or $spec.source -ceq 'FirewallOutbound' -or $spec.source -ceq 'UserDirFirewall') { HGateFirewall }
    if ($spec.source -ceq 'WifiProfiles') { HGateWifi }
}

function HPreflight() {
    switch -CaseSensitive ($spec.id) {
        'lsa.run_as_ppl' {
            Load 'SecureBoot'
            if (!(Confirm-SecureBootUEFI)) { throw 'Not offered: Secure Boot is off' }
            $sac = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
            if (Test-Path -LiteralPath $sac) {
                $k = Get-Item -LiteralPath $sac
                if ($k.GetValueNames() -contains 'VerifiedAndReputablePolicyState' -and [int]$k.GetValue('VerifiedAndReputablePolicyState') -ne 0) { throw 'Not offered: Smart App Control is on' }
            }
            Load 'Microsoft.PowerShell.Diagnostics'
            $hit = $false
            try {
                $null = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033,3063,3065,3066; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 1 -ErrorAction Stop
                $hit = $true
            } catch { if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
            if ($hit) { throw 'Not offered: some sign-in add-ons would stop working' }
            $lsa = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            $allowed = @{
                'Authentication Packages' = @('msv1_0')
                'Notification Packages' = @('scecli','rassfm')
                'Security Packages' = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','negoexts','livessp')
            }
            foreach ($name in $allowed.Keys) {
                if ($lsa.GetValueNames() -notcontains $name) { continue }
                foreach ($entry in @($lsa.GetValue($name))) {
                    foreach ($pkg in ([string]$entry -split '[,\s"]+')) {
                        if ($pkg -and $allowed[$name] -cnotcontains $pkg.ToLowerInvariant()) { throw 'Not offered: sign-in add-ons from other companies are installed' }
                    }
                }
            }
        }
        { $_ -in @('defender.asr.standard','defender.asr.web_script_email','defender.asr.office','defender.asr.ransomware_usb','defender.network_protection','defender.cloud_block_level') } {
            Load 'Defender'
            $status = Get-MpComputerStatus
            if ($status.RealTimeProtectionEnabled -ne $true) { throw 'Not offered: Defender real-time protection is off' }
            if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\CCM') { throw 'Not offered: this computer uses Configuration Manager' }
            if (@('defender.asr.web_script_email','defender.asr.ransomware_usb','defender.network_protection','defender.cloud_block_level') -ccontains $spec.id) {
                $maps = HEnumNumber (Get-MpPreference).MAPSReporting $hMaps
                if ($maps -eq 0) { throw 'Not offered: Defender cloud protection is off' }
            }
            if ($spec.id -ceq 'defender.asr.office' -and !(HOfficeInstalled)) { throw 'Not offered: Microsoft Office was not found' }
            if ($spec.id -ceq 'defender.network_protection') {
                if (!(HEditionHasNetworkProtection)) { throw 'Not offered: this edition of Windows does not include it' }
                if ($status.BehaviorMonitorEnabled -ne $true) { throw 'Not offered: Defender behavior monitoring is off' }
            }
        }
        { $_ -in @('defender.cfa_watch','defender.cfa_block','defender.cfa_allowed_apps') } {
            Load 'Defender'
            $status = Get-MpComputerStatus
            if ($status.RealTimeProtectionEnabled -ne $true) { throw 'Not offered: Defender real-time protection is off' }
            if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\CCM') { throw 'Not offered: this computer uses Configuration Manager' }
            $mode = HCfaMode
            if ($spec.id -ceq 'defender.cfa_allowed_apps' -and $mode -eq 0) { throw 'Not offered: folder protection is off' }
        }
        'browser.dns_bypass' {
            # Only offered while the filter is really answering lookups.
            if (!(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{0EE85A24-B573-4712-97FF-CC4BC51D8757}')) { throw 'Not offered: Web protection is off' }
        }
        'net.netbios' { HNetbiosPreflight }
        'privacy.wifi_random_address' { HWifiRandomPreflight }
        'accounts.stale_enabled' { HStalePreflight }
        'smb.shares_exposed' { HSharesPreflight }
        'accounts.builtin_administrator' {
            Load 'Microsoft.PowerShell.LocalAccounts'
            HBuiltinAdminIdle
            $other = $false
            try {
                foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544')) {
                    $sid = [string]$m.SID.Value
                    if ($sid -cmatch '^S-1-5-21-[0-9-]+$' -and $sid -cnotmatch '-500$' -and [string]$m.ObjectClass -ceq 'User') {
                        if ((Get-LocalUser -SID $m.SID).Enabled -eq $true) { $other = $true }
                    }
                }
            } catch { throw 'Not offered: no other administrator account could be confirmed' }
            if (!$other) { throw 'Not offered: no other administrator account is enabled' }
        }
        'accounts.lockout_policy' {
            # A lockout length of 0 (or "forever") keeps a locked account locked
            # until an administrator unlocks it: on a one-account PC that is a lock-out.
            $lockInfo = HLockoutInfo
            if ($lockInfo[0] -le 0) { throw 'Not offered: a locked sign-in would stay locked until an administrator unlocks it' }
        }
        'printer.spooler_remote' {
            Load 'PrintManagement'
            if (@(Get-Printer -ErrorAction Stop | Where-Object { $_.Shared -eq $true }).Count -gt 0) { throw 'Not offered: a printer on this computer is shared with other computers' }
            if (HPrintBusy) { throw 'Not offered: printing is busy right now' }
        }
        'privacy.recall' {
            if ((HFeatureState 'Recall') -ceq 'Missing') { throw 'Not offered: Recall is not available on this computer' }
        }
        'ai.click_to_do' {
            Load 'CimCmdlets'
            if ([int](Get-CimInstance Win32_OperatingSystem).BuildNumber -lt 26100) { throw 'Not offered: this version of Windows does not have it' }
        }
        'ai.paint' {
            if (!(HPackageInstalled 'Microsoft.Paint')) { throw 'Not offered: Paint was not found on this computer' }
        }
        'ai.notepad' {
            if (!(HPackageInstalled 'Microsoft.WindowsNotepad')) { throw 'Not offered: Notepad was not found on this computer' }
        }
        'debloat.widgets_policy' {
            $edition = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID' -ErrorAction Stop).EditionID
            if ($edition -cmatch '^Core') { throw 'Not offered: this setting is not available on Windows Home' }
            # Windows' user choice protection driver refuses this value from scripts, so only the person can change it.
            $ucpd = Get-Service -Name 'UCPD' -ErrorAction SilentlyContinue
            if ($null -ne $ucpd -and [string]$ucpd.Status -ceq 'Running') { throw 'Not offered: Windows keeps this setting for you to change yourself' }
        }
        { $_ -in @('privacy.clipboard_sync','privacy.online_speech','privacy.typing_inking','privacy.lock_screen_notifications','privacy.signin_email') } {
            $edition = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID' -ErrorAction Stop).EditionID
            if ($edition -cmatch '^Core') { throw 'Not offered: this setting is not available on Windows Home' }
        }
        'accounts.autologon' {
            $kiosk = 'HKLM:\SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration'
            if (Test-Path -LiteralPath $kiosk) {
                $item = Get-Item -LiteralPath $kiosk -ErrorAction Stop
                # Windows 11 ships this key with empty Configs, GroupConfigs,
                # Profiles and RawData folders. Only something inside them is
                # a kiosk; a folder that cannot be read counts as one.
                $set = @($item.GetValueNames()).Count -gt 0
                foreach ($name in @($item.GetSubKeyNames())) {
                    if ($set) { break }
                    $sub = $item.OpenSubKey($name)
                    if ($null -eq $sub) { $set = $true; break }
                    try { $set = @($sub.GetValueNames()).Count -gt 0 -or @($sub.GetSubKeyNames()).Count -gt 0 } finally { $sub.Close() }
                }
                if ($set) { throw 'Not offered: this computer is set up as a kiosk' }
            }
        }
        'remote_desktop.disabled' {
            $edition = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID' -ErrorAction Stop).EditionID
            if ($edition -cmatch '^Core') { throw 'Not offered: Windows Home cannot accept Remote Desktop connections' }
            if (HRemoteSessionActive) { throw 'Not offered: you are connected to this computer from another device right now' }
        }
        'smb1.disabled' {
            if ($script:hSmb1Unreadable) { throw 'Not offered: the old file-sharing version could not be checked' }
            if (HSmb1InUse) { throw 'Not offered: something is using the old file sharing right now' }
        }
        'net.hosts_file' { HHostsPreflight }
        'recovery.winre_enabled' {
            # Windows can only turn the tools back on from the image it keeps
            # while they are off, with its own ReAgentc.exe.
            if (!(HRecoveryImageReady) -or ![IO.File]::Exists((HReagentPath))) { throw 'Not offered: the recovery tools are missing from this computer' }
        }
        'persistence.run_and_tasks' { HStartupPreflight }
        'browser.extensions_off' { HAddonPreflight }
        'session.lock_on_wake' {
            Load 'CimCmdlets'; Load 'Microsoft.PowerShell.LocalAccounts'
            $who = [string](Get-CimInstance Win32_ComputerSystem).UserName
            $parts = $who.Split([char]92)
            if ($parts.Count -ne 2 -or $parts[1] -eq '') { throw 'Not offered: Secblitz cannot tell who is signed in' }
            $account = Get-LocalUser -Name $parts[1] -ErrorAction Stop
            if ($account.PasswordRequired -ne $true -or $null -eq $account.PasswordLastSet) { throw 'Not offered: your account has no password' }
        }
    }
}

function HOfficeInstalled() {
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') { return $true }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (!$root) { continue }
        foreach ($sub in @('Microsoft Office\root\Office16\WINWORD.EXE','Microsoft Office\Office16\WINWORD.EXE','Microsoft Office\Office15\WINWORD.EXE')) {
            if (Test-Path -LiteralPath ([IO.Path]::Combine($root, $sub))) { return $true }
        }
    }
    return $false
}
function HEditionHasNetworkProtection() {
    # Pro, Enterprise and Education family SKUs only. Anything unknown (Home
    # included) is treated as not supported.
    Load 'CimCmdlets'
    $os = Get-CimInstance Win32_OperatingSystem
    $sku = [int]$os.OperatingSystemSKU
    return (@(4,27,48,49,70,84,121,122,125,126,161,162,164,165,175) -contains $sku)
}
function HRemoteHost([string]$path) {
    if ($path -cmatch '^\\\\([^\\/]+)[\\/]') { return $Matches[1] }
    return ''
}
function HBareName([string]$hostName) {
    # A name with no dot that is not an address can only be found through NetBIOS.
    if (!$hostName) { return $false }
    $ip = $null
    if ([Net.IPAddress]::TryParse($hostName, [ref]$ip)) { return $false }
    return !$hostName.Contains('.')
}
function HRemoteHosts() {
    $paths = @()
    Load 'SmbShare'
    try { $paths += @(Get-SmbMapping -ErrorAction Stop | ForEach-Object { [string]$_.RemotePath }) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    try { $paths += @(Get-SmbConnection -ErrorAction Stop | ForEach-Object { '\\' + [string]$_.ServerName + '\x' }) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
    # Persistent mapped drives live in each signed-in user's hive.
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS')) {
        if ($hive.PSChildName -cnotmatch '^S-1-5-21-[0-9-]+$') { continue }
        $net = "Registry::HKEY_USERS\$($hive.PSChildName)\Network"
        if (!(Test-Path -LiteralPath $net)) { continue }
        foreach ($drive in @(Get-ChildItem -LiteralPath $net)) {
            $p = (Get-ItemProperty -LiteralPath $drive.PSPath).RemotePath
            if ($p) { $paths += [string]$p }
        }
    }
    return @($paths | ForEach-Object { HRemoteHost $_ } | Where-Object { $_ })
}
function HNetbiosPreflight() {
    Load 'SmbShare'
    $server = Get-SmbServerConfiguration
    if ($server.EnableSMB1Protocol -isnot [bool]) { throw 'Not offered: the old file-sharing version could not be checked' }
    if ($server.EnableSMB1Protocol) { throw 'Not offered: the old file-sharing version (SMB1) is still on' }
    $mr = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    if (Test-Path -LiteralPath $mr) {
        $k = Get-Item -LiteralPath $mr
        if ($k.GetValueNames() -notcontains 'Start' -or [int]$k.GetValue('Start') -ne 4) { throw 'Not offered: the old file-sharing version (SMB1) is still on' }
    }
    foreach ($h in @(HRemoteHosts)) {
        if (HBareName $h) { throw 'Not offered: a shared folder or drive may rely on the old name service' }
    }
}

function HObserve() {
    $script:hLabels = @{}
    $script:hLeft = @()
    $slice = HRead
    $o = @{ value = @{ items = $slice }; eligible = $true; reason = 'Eligible unmanaged local preference' }
    try {
        HGate
        if ((HAnyUnsafe $slice) -or ($spec.source -ceq 'WifiRandomAddress' -and $slice.Count -eq 0)) {
            HPreflight
            $labels = @(HLabelList $slice)
            if ($labels.Count -gt 0) { $o.labels = $labels }
        }
    } catch {
        $o.eligible = $false
        $o.reason = $_.Exception.Message
    }
    return $o
}

function HSetRegistry($def, $v) {
    $vn = HValueName $def
    if ($null -eq $v) { Remove-ItemProperty -LiteralPath $def.path -Name $vn -ErrorAction Stop; return }
    if (!(Test-Path -LiteralPath $def.path)) { $null = New-Item -Path $def.path -Force -ErrorAction Stop }
    if ($def.rule -ceq 'text') {
        if ($v -isnot [string]) { throw 'Invalid text setting' }
        # Leave it alone unless it was read as text a moment ago.
        $key = Get-Item -LiteralPath $def.path -ErrorAction Stop
        if (($key.GetValueNames() -contains $vn) -and $key.GetValueKind($vn) -ne [Microsoft.Win32.RegistryValueKind]::String) { throw "$vn is not text" }
        New-ItemProperty -LiteralPath $def.path -Name $vn -PropertyType String -Value $v -Force -ErrorAction Stop | Out-Null
        return
    }
    # DWORDs are unsigned; the cmdlet wants the same 32 bits as a signed int.
    $bits = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32][int64]$v), 0)
    New-ItemProperty -LiteralPath $def.path -Name $vn -PropertyType DWord -Value $bits -Force -ErrorAction Stop | Out-Null
}
function HSetDefenderPref($def, $v) {
    Load 'Defender'
    $p = @{}
    if ($def.name -ceq 'MAPSReporting') { $p[$def.name] = $hMaps[[int]$v] }
    elseif ($def.name -ceq 'PUAProtection') { $p[$def.name] = $hPua[[int]$v] }
    elseif ($def.name -ceq 'EnableNetworkProtection') { $p[$def.name] = $hNp[[int]$v] }
    elseif ($def.name -ceq 'EnableControlledFolderAccess') { $p[$def.name] = $hCfa[[int]$v] }
    elseif ($def.name -ceq 'CloudBlockLevel') {
        $level = @($hCbl.Keys | Where-Object { $hCbl[$_] -eq [int]$v })
        if ($level.Count -ne 1) { throw 'Invalid cloud block level' }
        $p[$def.name] = [string]$level[0]
    }
    elseif ($def.name -ceq 'CloudExtendedTimeout') { $p[$def.name] = [uint32]$v }
    else { $p[$def.name] = [bool]([int]$v) }
    Set-MpPreference @p
}
function HSetAsr($def, $v) {
    Load 'Defender'
    if ($null -eq $v) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $def.name; return }
    $action = switch ([int]$v) { 0 { 'Disabled' } 1 { 'Enabled' } 2 { 'AuditMode' } 6 { 'Warn' } default { throw 'Invalid attack surface rule action' } }
    Add-MpPreference -AttackSurfaceReductionRules_Ids $def.name -AttackSurfaceReductionRules_Actions $action
}
function HSetLockout($def, $v) {
    # Level 3 carries all three lockout fields: write back the current duration
    # and observation window unchanged, with only the new threshold.
    $info = HLockoutInfo
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(12)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt32($buffer, 0, $info[0])
        [Runtime.InteropServices.Marshal]::WriteInt32($buffer, 4, $info[1])
        [Runtime.InteropServices.Marshal]::WriteInt32($buffer, 8, [int]$v)
        [uint32]$field = 0
        $status = [Secblitz.NetModals]::NetUserModalsSet([IntPtr]::Zero, [uint32]3, $buffer, [ref]$field)
        if ($status -ne 0) { throw "Lockout threshold could not be set (status $status)" }
    } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
}
function HBuiltinAdminIdle() {
    # Switching off the account someone is signed in with locks them out at
    # their next sign-in, and autologon setups never get back in.
    try { $inUse = HAccountsInUse } catch { throw 'Not offered: Secblitz cannot tell who is signed in' }
    if ($inUse.ContainsKey([string](HBuiltinAdmin).SID.Value)) { throw 'Not offered: you are signed in with the built-in Administrator account' }
}
function HSetBuiltinAdmin($def, $v) {
    $a = HBuiltinAdmin
    if ([int]$v -eq 1) { Enable-LocalUser -SID $a.SID } else { HBuiltinAdminIdle; Disable-LocalUser -SID $a.SID }
}
function HSetFirewall($name, $v) {
    Load 'NetSecurity'
    $bits = [int]$v -band 7
    $profiles = if ($bits -eq 7) { 'Any' } else {
        @(@(@{ b = 1; n = 'Domain' }, @{ b = 2; n = 'Private' }, @{ b = 4; n = 'Public' }) | Where-Object { ($bits -band $_.b) -ne 0 } | ForEach-Object { $_.n })
    }
    $enabled = if (([int]$v -band 8) -ne 0) { 'True' } else { 'False' }
    Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Profile $profiles -Enabled $enabled -ErrorAction Stop
}
function HSetNetbios($name, $v) {
    if (!(HNameOk $name) -or @(0,1,2) -notcontains [int]$v) { throw 'Invalid NetBIOS setting' }
    Load 'CimCmdlets'
    $found = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "SettingID = '$name'")
    if ($found.Count -ne 1) { throw 'Network adapter not found exactly once' }
    $r = Invoke-CimMethod -InputObject $found[0] -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]$v }
    if ($null -eq $r -or @(0,1) -notcontains [int]$r.ReturnValue) { throw "NetBIOS setting was refused (code $($r.ReturnValue))" }
}
function HNetshPath() { return [IO.Path]::Combine($env:SystemRoot, 'System32\netsh.exe') }
function HSetWifiRandom($name, $v) {
    if (!(HNameOk $name) -or $null -eq $v -or @(0,1) -notcontains [int]$v) { throw 'Invalid Wi-Fi address setting' }
    $found = @(HWifiAdapters | Where-Object { $_.id -ceq $name })
    if ($found.Count -ne 1) { throw 'Wi-Fi adapter not found exactly once' }
    $iface = [string]$found[0].name
    # The adapter name goes into a quoted argument: refuse anything that could end the quote.
    if ($iface.Length -lt 1 -or $iface.Length -gt 256 -or $iface -cmatch '[\x00-\x1f\x7f"]' -or $iface.Trim() -cne $iface -or $iface.EndsWith('\')) { throw 'This Wi-Fi adapter has a name that cannot be used safely' }
    $exe = HNetshPath
    if (![IO.File]::Exists($exe)) { throw 'The Wi-Fi tool is missing from this computer' }
    $enabled = $(if ([int]$v -eq 1) { 'yes' } else { 'no' })
    $code = HRunHidden $exe ('wlan set randomization enabled=' + $enabled + ' interface="' + $iface + '"')
    if ($code -ne 0) { throw "Windows could not change the Wi-Fi address setting (code $code)" }
}
function HSetOutbound($v) {
    Load 'NetSecurity'
    if ([int]$v -eq 1) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $hOutboundRule -DisplayName $hOutboundName -Description 'Added by Secblitz. Stops this computer sending file-sharing traffic to the internet.' -Direction Outbound -Action Block -Protocol TCP -RemotePort 445,139 -RemoteAddress Internet -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    } else {
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $hOutboundRule -ErrorAction Stop
    }
}
function HWlanApi() {
    if ($null -ne ('Secblitz.WlanApi' -as [type])) { return }
    # Reflection.Emit P/Invoke stubs: no csc.exe child process (see MdmRegistration).
    $dll = [IO.Path]::Combine($env:SystemRoot, 'System32\wlanapi.dll')
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly([Reflection.AssemblyName]::new('Secblitz.WlanApi'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('Secblitz.WlanApi')
    $type = $module.DefineType('Secblitz.WlanApi', [Reflection.TypeAttributes]'Public, Abstract, Sealed')
    $defs = @(
        @{ n = 'WlanOpenHandle'; p = [Type[]]@([uint32], [IntPtr], [uint32].MakeByRefType(), [IntPtr].MakeByRefType()) },
        @{ n = 'WlanCloseHandle'; p = [Type[]]@([IntPtr], [IntPtr]) },
        @{ n = 'WlanSetProfile'; p = [Type[]]@([IntPtr], [Guid].MakeByRefType(), [uint32], [string], [string], [bool], [IntPtr], [uint32].MakeByRefType()) }
    )
    foreach ($d in $defs) {
        $m = $type.DefinePInvokeMethod($d.n, $dll, $d.n, [Reflection.MethodAttributes]'Public, Static, PinvokeImpl', [Reflection.CallingConventions]::Standard, [uint32], $d.p, [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $m.SetImplementationFlags($m.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
    }
    $null = $type.CreateType()
}
function HSetWifi($name, $v) {
    $found = @(HWlanProfiles | Where-Object { $_.name -ceq $name })
    if ($found.Count -ne 1) { throw 'Saved Wi-Fi network not found exactly once' }
    $p = $found[0]
    $doc = HLoadXml $p.file
    $node = $doc.SelectSingleNode("//*[local-name()='connectionMode']")
    if ($null -eq $node) { throw 'Wi-Fi profile has no connection mode' }
    $node.InnerText = $(if ([int]$v -eq 1) { 'auto' } else { 'manual' })
    HWlanApi
    $negotiated = [uint32]0; $handle = [IntPtr]::Zero
    $rc = [Secblitz.WlanApi]::WlanOpenHandle([uint32]2, [IntPtr]::Zero, [ref]$negotiated, [ref]$handle)
    if ($rc -ne 0) { throw "Wi-Fi service is not available (code $rc)" }
    try {
        $iface = [Guid]$p.iface; $reason = [uint32]0
        # Flags 0 = all-user profile, overwrite in place; nothing is deleted.
        $rc = [Secblitz.WlanApi]::WlanSetProfile($handle, [ref]$iface, [uint32]0, $doc.OuterXml, $null, $true, [IntPtr]::Zero, [ref]$reason)
        if ($rc -ne 0) { throw "Wi-Fi profile update was refused (code $rc, reason $reason)" }
    } finally { $null = [Secblitz.WlanApi]::WlanCloseHandle($handle, [IntPtr]::Zero) }
}
function HSet([string]$name, $v) {
    $def = HDef $name
    switch -CaseSensitive ($spec.source) {
        'Registry' { HSetRegistry $def $v; HAfterRegistry $def $v }
        'DefenderPref' { HSetDefenderPref $def $v }
        'DefenderAsr' { HSetAsr $def $v }
        'Lockout' { HSetLockout $def $v }
        'BuiltinAdmin' { HSetBuiltinAdmin $def $v }
        'FirewallExposure' { HSetFirewall $name $v }
        'WifiProfiles' { HSetWifi $name $v }
        'NetbiosAdapters' { HSetNetbios $name $v }
        'WifiRandomAddress' { HSetWifiRandom $name $v }
        'FirewallOutbound' { HSetOutbound $v }
        'ExploitMitigations' { HSetMitigation $name $v }
        'PowerShellV2' { HSetPowerShellV2 $v }
        'LegacyServices' { HSetService $name $v }
        'LockOnWake' { HSetLockOnWake $name $v }
        'UpdatePause' { HSetPause $def $v }
        'SmartScreen' { HSetSmartScreen $def $v }
        'DefenderExclusions' { HSetExclusion $name $v }
        'WinlogonAutoLogon' { HSetAutoLogon $name $v }
        'SmbFeature' { HSetSmb1 $name $v }
        'UnquotedServices' { HSetUnquoted $name $v }
        'UserDirFirewall' { HSetUserDirFirewall $name $v }
        'HostsFile' { HSetHosts $name $v }
        'StartupItems' { HSetStartup $name $v }
        'StaleAccounts' { HSetStale $name $v }
        'ShareGrants' { HSetShare $name $v }
        'BrowserExtensions' { HSetExtension $name $v }
        'CfaAllowedApps' { HSetCfaApp $name $v }
        'RecoveryTools' { HSetRecovery $name $v }
        default { throw 'Unknown hardening source' }
    }
}

function HVerified([string]$name, $have, $want) {
    if (HEq $have $want) { return $true }
    # An account or shared folder the person deleted since the fix has nothing
    # left to put back: undo is complete.
    if (($spec.source -ceq 'StaleAccounts' -or $spec.source -ceq 'ShareGrants') -and $null -ne $want -and [int64]$want -eq 1 -and (HItemGone $name)) { return $true }
    # An update pause that already ended cannot be put back: nothing is in force.
    if ($spec.source -ceq 'UpdatePause' -and $null -ne $want -and $null -ne $have -and [int64]$have -eq 0 -and !(HPauseWantedActive)) { return $true }
    return $false
}
function HWantedNames() {
    $v = Get-Variable -Name hWanted -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $v -or $null -eq $v.Value) { return @() }
    return @($v.Value.Keys)
}
# Is anything waiting to print (or can that not be told)? Unreadable counts as busy.
function HPrintBusy() {
    try {
        # Strict mode: a missing value returns nothing, so read the property only when it is there.
        $p = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -Name 'DefaultSpoolDirectory' -ErrorAction SilentlyContinue
        $dir = if ($null -ne $p -and $p.PSObject.Properties['DefaultSpoolDirectory']) { [string]$p.DefaultSpoolDirectory } else { '' }
        if ([string]::IsNullOrWhiteSpace($dir)) { $dir = [IO.Path]::Combine($env:SystemRoot, 'System32\spool\PRINTERS') }
        return (@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop).Count -gt 0)
    } catch { return $true }
}
function HAfterRegistry($def, $v) {
    if ($spec.id -ceq 'printer.spooler_remote') {
        # The setting is read when the Spooler starts: restart it once, only if it runs.
        $svc = Get-Service -Name 'Spooler' -ErrorAction Stop
        # Applying is only offered while nothing is queued (see HPreflight). Putting
        # it back never cuts off a print in progress: with anything queued it takes
        # effect the next time the Spooler starts.
        $applying = HIsSafe $def $v
        if ([string]$svc.Status -ceq 'Running' -and ($applying -or !(HPrintBusy))) { Restart-Service -Name 'Spooler' -Force -ErrorAction Stop }
    }
}

function HMitigationValue($v) {
    switch -CaseSensitive (([string]$v).ToUpperInvariant()) {
        'ON' { return 1 }
        'OFF' { return 0 }
        'NOTSET' { return 2 }
    }
    throw 'Exploit protection state is not readable'
}
function HReadMitigations() {
    Load 'ProcessMitigations'
    $m = Get-ProcessMitigation -System
    return @{
        DEP = (HMitigationValue $m.DEP.Enable)
        SEHOP = (HMitigationValue $m.SEHOP.Enable)
        BottomUp = (HMitigationValue $m.ASLR.BottomUp)
        HighEntropy = (HMitigationValue $m.ASLR.HighEntropy)
        CFG = (HMitigationValue $m.CFG.Enable)
    }
}
function HSetMitigation([string]$name, $v) {
    if (@('DEP', 'SEHOP', 'BottomUp', 'HighEntropy', 'CFG') -cnotcontains $name) { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid exploit protection state' }
    Load 'ProcessMitigations'
    if ([int]$v -eq 1) { Set-ProcessMitigation -System -Enable $name -ErrorAction Stop }
    else { Set-ProcessMitigation -System -Disable $name -ErrorAction Stop }
}

function HFeatureState([string]$name) { return (FeatureState $name) }
function HPackageInstalled([string]$name) {
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications'
    if (!(Test-Path -LiteralPath $root)) { throw 'The installed apps could not be listed' }
    $prefix = $name + '_'
    return (@(Get-ChildItem -LiteralPath $root -Name -ErrorAction Stop | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0)
}
function HV2Value([string]$state) {
    switch -CaseSensitive ($state) {
        'Enabled' { return 1 }
        'EnablePending' { return 1 }
        'Disabled' { return 0 }
        'DisablePending' { return 0 }
        'DisabledWithPayloadRemoved' { return 0 }
        'Missing' { return 0 }
    }
    throw 'The Windows feature state is not readable'
}
function HReadPowerShellV2() {
    $root = HV2Value (HFeatureState 'MicrosoftWindowsPowerShellV2Root')
    $child = HV2Value (HFeatureState 'MicrosoftWindowsPowerShellV2')
    return @{ Enabled = [int]([bool]($root -or $child)) }
}
function HSetPowerShellV2($v) {
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid feature state' }
    # Changing a feature needs DISM (DismHost.exe): the engine runs only this
    # write with a job that allows that one child process.
    Load 'Dism'
    $names = @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')
    foreach ($name in $names) {
        if ([int]$v -eq 0) {
            if ((HV2Value (HFeatureState $name)) -eq 1) { $null = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop }
        } else {
            $null = Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart -ErrorAction Stop
        }
    }
}

# Only the AutoAdminLogon text value is read or written. The saved sign-in
# name, saved password and sign-in count are never opened.
function HReadAutoLogon() {
    $def = @($spec.keys)[0]
    $key = Get-Item -LiteralPath $def.path -ErrorAction Stop
    if ($key.GetValueNames() -notcontains 'AutoAdminLogon') { return @{ AutoAdminLogon = $null } }
    if ($key.GetValueKind('AutoAdminLogon') -ne [Microsoft.Win32.RegistryValueKind]::String) { throw 'AutoAdminLogon is not text' }
    $flag = [string]$key.GetValue('AutoAdminLogon')
    if ($flag -ceq '1') { return @{ AutoAdminLogon = 1 } }
    if ($flag -ceq '0') { return @{ AutoAdminLogon = 0 } }
    throw 'AutoAdminLogon has an unknown setting'
}
function HSetAutoLogon([string]$name, $v) {
    if ($name -cne 'AutoAdminLogon') { throw 'Unknown hardening item' }
    $def = @($spec.keys)[0]
    if ($null -eq $v) { Remove-ItemProperty -LiteralPath $def.path -Name 'AutoAdminLogon' -ErrorAction Stop; return }
    if ([int]$v -ne 0 -and [int]$v -ne 1) { throw 'Invalid automatic sign-in setting' }
    New-ItemProperty -LiteralPath $def.path -Name 'AutoAdminLogon' -PropertyType String -Value ([string][int]$v) -Force -ErrorAction Stop | Out-Null
}

function HRemoteSessionActive() {
    # SM_REMOTESESSION (0x1000) through a Reflection.Emit P/Invoke stub: no
    # Add-Type, so no csc.exe child process. Anything unclear counts as remote.
    if ($env:SESSIONNAME -cmatch '^(RDP|ICA)-') { return $true }
    if ($null -eq ('Secblitz.SessionInfo' -as [type])) {
        $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly([Reflection.AssemblyName]::new('Secblitz.SessionInfo'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $module = $assembly.DefineDynamicModule('Secblitz.SessionInfo')
        $type = $module.DefineType('Secblitz.SessionInfo', [Reflection.TypeAttributes]'Public, Abstract, Sealed')
        $dll = [IO.Path]::Combine($env:SystemRoot, 'System32\user32.dll')
        $method = $type.DefinePInvokeMethod('GetSystemMetrics', $dll, 'GetSystemMetrics', [Reflection.MethodAttributes]'Public, Static, PinvokeImpl', [Reflection.CallingConventions]::Standard, [int], [Type[]]@([int]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags($method.GetMethodImplementationFlags() -bor [Reflection.MethodImplAttributes]::PreserveSig)
        $null = $type.CreateType()
    }
    return ([Secblitz.SessionInfo]::GetSystemMetrics(4096) -ne 0)
}

# Windows reports an optional feature as unchanged until the restart that
# finishes the change. After a successful change that needs a restart, a small
# note (one value per feature) says what was asked for, so the check reads the
# intended state until Windows restarts. The note lives in a volatile registry
# key that Windows deletes at every restart, so it can never outlive the
# pending change and needs no clock comparison.
$hSmbNotePath = 'SOFTWARE\Secblitz\PendingFeatures'
function HSmbNoteGet([string]$name) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($hSmbNotePath)
    if ($null -eq $key) { return $null }
    try {
        if ($key.GetValueNames() -cnotcontains $name) { return $null }
        $text = [string]$key.GetValue($name)
        if ($text -ceq '0') { return 0 }
        if ($text -ceq '1') { return 1 }
        return $null
    } finally { $key.Dispose() }
}
function HSmbNotePut([string]$name, $want) {
    if ($null -eq $want) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($hSmbNotePath, $true)
        if ($null -eq $key) { return }
        try { if ($key.GetValueNames() -ccontains $name) { $key.DeleteValue($name) } } finally { $key.Dispose() }
        return
    }
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($hSmbNotePath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
    try { $key.SetValue($name, [string][int]$want, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
}
function HSmbState([string]$name) {
    $note = HSmbNoteGet $name
    if ($null -ne $note) { return $note }
    return (HV2Value (HFeatureState $name))
}
function HSmbInstallValues() {
    # One query for all the old file-sharing parts (each query can take a while).
    Load 'CimCmdlets'
    $rows = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name LIKE 'SMB1Protocol%'" -OperationTimeoutSec 30)
    if ($rows.Count -eq 0) {
        # Only believe "not present" when the full list is healthy.
        if (@(Get-CimInstance -ClassName Win32_OptionalFeature -OperationTimeoutSec 60).Count -lt 5) { throw 'The Windows feature list is not readable' }
    }
    $out = @{}
    foreach ($row in $rows) {
        $n = [string]$row.Name
        if ($out.ContainsKey($n)) { throw 'The Windows feature list is ambiguous' }
        switch ([int]$row.InstallState) { 1 { $out[$n] = 1 } 2 { $out[$n] = 0 } 3 { $out[$n] = 0 } default { throw 'The Windows feature state is not readable' } }
    }
    return $out
}
function HReadSmb1() {
    $script:hSmb1Unreadable = $false
    $out = @{}
    $found = $null
    try { $found = HSmbInstallValues } catch { $script:hSmb1Unreadable = $true }
    foreach ($def in @($spec.keys)) {
        # A part that cannot be read counts as "on" here so nothing looks safe;
        # the preflight then says the old file sharing could not be checked.
        if ($script:hSmb1Unreadable) { $out[$def.name] = 1; continue }
        try {
            $note = HSmbNoteGet $def.name
            if ($null -ne $note) { $out[$def.name] = $note }
            elseif ($found.ContainsKey($def.name)) { $out[$def.name] = $found[$def.name] }
            else { $out[$def.name] = 0 }
        } catch { $script:hSmb1Unreadable = $true; $out[$def.name] = 1 }
    }
    return $out
}
function HSmb1InUse() {
    # Best effort: a live connection that speaks the old version blocks the change.
    try {
        Load 'SmbShare'
        foreach ($c in @(Get-SmbConnection -ErrorAction Stop)) { if ([string]$c.Dialect -cmatch '^1\.') { return $true } }
    } catch { }
    try {
        foreach ($c in @(Get-SmbSession -ErrorAction Stop)) { if ([string]$c.Dialect -cmatch '^1\.') { return $true } }
    } catch { }
    return $false
}
function HSetSmb1([string]$name, $v) {
    if (@('SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'SMB1Protocol-Deprecation') -cnotcontains $name) { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid feature state' }
    # DISM needs DismHost.exe: the engine runs only this write with a job that allows it.
    Load 'Dism'
    $state = HSmbState $name
    if ($state -eq [int]$v) { return }
    # Never -Remove: the files stay, so undo can turn the same part back on offline.
    # -LimitAccess: never reach out to Windows Update for files that are already here.
    if ([int]$v -eq 0) { $r = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop }
    else { $r = Enable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -LimitAccess -ErrorAction Stop }
    try {
        if ($null -ne $r -and $r.RestartNeeded -eq $true) { HSmbNotePut $name $v } else { HSmbNotePut $name $null }
    } catch {
        $failure = $_
        # The note could not be kept, so the change is not tracked: put the part back.
        try {
            if ([int]$v -eq 0) { $null = Enable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -LimitAccess -ErrorAction Stop }
            else { $null = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop }
        } catch { }
        throw $failure
    }
}

# ---- services.legacy_remote (value = start type 2/3/4, 5 = automatic delayed, +8 when running)
function HServiceNames() { return @('RemoteRegistry', 'WinRM', 'sshd', 'TlntSvr', 'FTPSVC', 'W3SVC', 'SNMP') }
function HServiceKey([string]$name) {
    if ((HServiceNames) -cnotcontains $name) { throw 'Unknown hardening item' }
    return ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $name)
}
function HReadServices() {
    $out = @{}
    foreach ($name in @(HServiceNames)) {
        $path = HServiceKey $name
        if (!(Test-Path -LiteralPath $path)) { continue }
        $key = Get-Item -LiteralPath $path
        $names = @($key.GetValueNames())
        if ($names -notcontains 'ImagePath' -or $names -notcontains 'Start') { continue }
        $start = $key.GetValue('Start')
        if ($start -isnot [int]) { throw 'A service start type is not readable' }
        if ($start -eq 2) {
            if ($names -contains 'DelayedAutostart' -and $key.GetValue('DelayedAutostart') -is [int] -and $key.GetValue('DelayedAutostart') -eq 1) { $start = 5 }
        } elseif ($start -ne 3 -and $start -ne 4) { throw 'A service start type is unexpected' }
        $svc = Get-Service -Name $name -ErrorAction Stop
        $status = [string]$svc.Status
        if ($status -ceq 'Running') { $start += 8 }
        elseif ($status -cne 'Stopped') { throw 'A service is changing state; try again in a moment' }
        $out[$name] = [int]$start
    }
    return $out
}
function HSetService([string]$name, $v) {
    $path = HServiceKey $name
    if ($null -eq $v) { throw 'Invalid service state' }
    $start = [int]$v -band 7
    $run = (([int]$v -band 8) -ne 0)
    $type = switch ($start) { 2 { 'Automatic' } 3 { 'Manual' } 4 { 'Disabled' } 5 { 'Automatic' } default { throw 'Invalid service start type' } }
    $svc = Get-Service -Name $name -ErrorAction Stop
    if (!$run -and [string]$svc.Status -cne 'Stopped') {
        Stop-Service -Name $name -ErrorAction Stop
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Set-Service -Name $name -StartupType $type -ErrorAction Stop
    if ($start -eq 5) {
        New-ItemProperty -LiteralPath $path -Name 'DelayedAutostart' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    } elseif ($start -eq 2) {
        # Plain automatic: only clear a delayed flag that is really set. A value
        # that was never there is not created, so undo puts back exactly what was.
        $flag = Get-ItemProperty -LiteralPath $path -Name 'DelayedAutostart' -ErrorAction SilentlyContinue
        if ($null -ne $flag -and [int]$flag.DelayedAutostart -ne 0) {
            New-ItemProperty -LiteralPath $path -Name 'DelayedAutostart' -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
        }
    }
    $svc.Refresh()
    if ($run -and [string]$svc.Status -cne 'Running') { Start-Service -Name $name -ErrorAction Stop }
}

# ---- session.lock_on_wake (powercfg CONSOLELOCK through the power WMI provider)
function HConsoleLockInstance([string]$mode) {
    Load 'CimCmdlets'
    $plans = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerPlan | Where-Object { $_.IsActive -eq $true })
    if ($plans.Count -ne 1) { throw 'The active power plan is not readable' }
    $m = [regex]::Match([string]$plans[0].InstanceID, '\{([0-9a-fA-F-]{36})\}$')
    if (!$m.Success) { throw 'The active power plan is not readable' }
    $id = 'Microsoft:PowerSettingDataIndex\{' + $m.Groups[1].Value + '}\' + $mode + '\{0e796bdb-100d-47d6-a2d5-f7d2daa51f51}'
    $found = @(Get-CimInstance -Namespace 'root\cimv2\power' -ClassName Win32_PowerSettingDataIndex | Where-Object { [string]$_.InstanceID -ieq $id })
    if ($found.Count -gt 1) { throw 'The sign-in-on-wake setting is ambiguous' }
    $setting = $null
    if ($found.Count -eq 1) { $setting = $found[0] }
    return @{ plan = $plans[0]; setting = $setting }
}
function HReadLockOnWake() {
    $ac = HConsoleLockInstance 'AC'
    if ($null -eq $ac.setting) { throw 'The sign-in-on-wake setting is not readable' }
    $dc = HConsoleLockInstance 'DC'
    $acValue = [int]$ac.setting.SettingIndexValue
    # Desktop PCs may have no battery setting: it then mirrors the plugged-in one.
    $dcValue = $acValue
    if ($null -ne $dc.setting) { $dcValue = [int]$dc.setting.SettingIndexValue }
    foreach ($n in @($acValue, $dcValue)) { if ($n -ne 0 -and $n -ne 1) { throw 'The sign-in-on-wake setting is not readable' } }
    return @{ Ac = $acValue; Dc = $dcValue }
}
function HSetLockOnWake([string]$name, $v) {
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid sign-in-on-wake value' }
    if ($name -ceq 'Ac') { $mode = 'AC' } elseif ($name -ceq 'Dc') { $mode = 'DC' } else { throw 'Unknown hardening item' }
    $i = HConsoleLockInstance $mode
    if ($null -ne $i.setting) {
        $i.setting.SettingIndexValue = [uint32]$v
        Set-CimInstance -InputObject $i.setting -ErrorAction Stop
    } elseif ($mode -ceq 'AC') { throw 'The sign-in-on-wake setting is not available' }
    Invoke-CimMethod -InputObject $i.plan -MethodName Activate -ErrorAction Stop | Out-Null
}

# ---- update.paused (values are minutes since 1970; 0 = nothing to resume)
function HPauseNames() { return @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesStartTime', 'PauseQualityUpdatesStartTime') }
function HPauseEndNames() { return @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime') }
function HPauseMinutes($key, [string]$name) {
    if ($key.GetValueNames() -notcontains $name) { return $null }
    if ($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::String) { throw "$name is not text" }
    $when = [DateTimeOffset]::MinValue
    if (![DateTimeOffset]::TryParse([string]$key.GetValue($name), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$when)) { throw "$name is not a date" }
    $minutes = [int64][Math]::Floor($when.ToUnixTimeSeconds() / 60)
    if ($minutes -lt 1 -or $minutes -gt 2000000000) { throw "$name is out of range" }
    return $minutes
}
function HReadPause() {
    $out = @{}
    foreach ($def in @($spec.keys)) { $out[$def.name] = 0 }
    $path = [string]@($spec.keys)[0].path
    if (!(Test-Path -LiteralPath $path)) { return $out }
    $key = Get-Item -LiteralPath $path
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $active = $false
    foreach ($name in @(HPauseEndNames)) {
        $m = HPauseMinutes $key $name
        if ($null -ne $m -and ($m * 60) -gt $now) { $active = $true }
    }
    if (!$active) { return $out }
    foreach ($name in @(HPauseNames)) {
        $m = HPauseMinutes $key $name
        if ($null -ne $m) { $out[$name] = [int]$m }
    }
    return $out
}
function HPauseWantedActive() {
    $names = @(HWantedNames)
    if ($names.Count -eq 0) { return $true }
    $wanted = (Get-Variable -Name hWanted -Scope Script).Value
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($name in @(HPauseEndNames)) {
        if ($wanted.ContainsKey($name) -and $null -ne $wanted[$name] -and ([int64]$wanted[$name] * 60) -gt $now) { return $true }
    }
    return $false
}
function HSetPause($def, $v) {
    if ($null -eq $v) { throw 'Invalid pause value' }
    $key = $null
    if (Test-Path -LiteralPath $def.path) { $key = Get-Item -LiteralPath $def.path }
    if ([int]$v -eq 0) {
        if ($null -ne $key -and $key.GetValueNames() -contains $def.name) { Remove-ItemProperty -LiteralPath $def.path -Name $def.name -ErrorAction Stop }
        return
    }
    if (!(HPauseWantedActive)) { return }
    $seconds = [int64]$v * 60
    $text = [DateTimeOffset]::FromUnixTimeSeconds($seconds).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    if ($null -eq $key) { $null = New-Item -Path $def.path -Force -ErrorAction Stop }
    New-ItemProperty -LiteralPath $def.path -Name $def.name -PropertyType String -Value $text -Force -ErrorAction Stop | Out-Null
}

# ---- smartscreen.apps (0 Off, 1 Warn, 2 RequireAdmin, 3 Prompt; absent = null)
function HSmartScreenWords() { return @('Off', 'Warn', 'RequireAdmin', 'Prompt') }
function HReadSmartScreen() {
    $out = @{}
    foreach ($def in @($spec.keys)) {
        if ($def.name -cne 'SmartScreenEnabled') { $out[$def.name] = HReadRegistry $def; continue }
        $out[$def.name] = $null
        if (!(Test-Path -LiteralPath $def.path)) { continue }
        $key = Get-Item -LiteralPath $def.path
        if ($key.GetValueNames() -notcontains $def.name) { continue }
        if ($key.GetValueKind($def.name) -ne [Microsoft.Win32.RegistryValueKind]::String) { throw 'The SmartScreen setting is not text' }
        $text = [string]$key.GetValue($def.name)
        $words = HSmartScreenWords
        $index = -1
        for ($n = 0; $n -lt $words.Count; $n++) { if ($words[$n] -ieq $text) { $index = $n } }
        if ($index -lt 0) { throw 'The SmartScreen setting is not recognised' }
        $out[$def.name] = $index
    }
    return $out
}
function HSetSmartScreen($def, $v) {
    if ($def.name -cne 'SmartScreenEnabled') { HSetRegistry $def $v; return }
    $words = HSmartScreenWords
    if ($null -eq $v -or [int]$v -lt 0 -or [int]$v -ge $words.Count) { throw 'Invalid SmartScreen setting' }
    if (!(Test-Path -LiteralPath $def.path)) { $null = New-Item -Path $def.path -Force -ErrorAction Stop }
    New-ItemProperty -LiteralPath $def.path -Name $def.name -PropertyType String -Value $words[[int]$v] -Force -ErrorAction Stop | Out-Null
}

# ---- defender.exclusions_risky (names are "path:...", "ext:..." or "proc:...")
function HRiskyPathPattern() {
    $drive = '([a-z]:|%systemdrive%)'
    $parts = @(
        '(\*|[a-z]:|[a-z]:\\\*|%systemdrive%|%homedrive%)',
        ($drive + '\\(windows|users|programdata|temp|tmp|program files|program files \(x86\))'),
        ($drive + '\\windows\\(system32|syswow64|temp)'),
        ($drive + '\\users\\([^\\]+|public)'),
        ($drive + '\\users\\[^\\]+\\(downloads|desktop|documents|appdata|appdata\\local|appdata\\roaming|appdata\\local\\temp)'),
        '%(windir|systemroot)%(\\(system32|syswow64|temp))?',
        '%(temp|tmp|userprofile|appdata|localappdata|programdata|public|allusersprofile)%',
        '%(userprofile|homepath)%\\(downloads|desktop|documents|appdata|appdata\\local|appdata\\roaming|appdata\\local\\temp)'
    )
    return ('^(' + ($parts -join '|') + ')$')
}
function HExclusionRisky([string]$kind, [string]$value) {
    $v = $value.Trim().ToLowerInvariant()
    if ($v.Length -eq 0) { return $false }
    switch -CaseSensitive ($kind) {
        'ext' { return (@('exe', 'dll', 'ps1', 'bat', 'js', 'vbs', 'scr') -ccontains $v.TrimStart([char]46)) }
        'proc' {
            $leaf = $v.Substring($v.LastIndexOf([char]92) + 1)
            if ($leaf.EndsWith('.exe')) { $leaf = $leaf.Substring(0, $leaf.Length - 4) }
            return (@('powershell', 'pwsh', 'cmd', 'wscript', 'cscript', 'mshta') -ccontains $leaf)
        }
        'path' {
            $p = $v
            if ($p.EndsWith('\*') -or $p.EndsWith('/*')) { $p = $p.Substring(0, $p.Length - 2) }
            $p = $p.TrimEnd([char[]]@([char]92, [char]47))
            if ($p.Length -eq 0) { return $true }
            return ($p -cmatch (HRiskyPathPattern))
        }
    }
    return $false
}
function HExclusionParse([string]$name) {
    if ($name.Length -lt 4 -or $name.Length -gt 300 -or $name -cmatch '[\x00-\x1f\x7f"]' -or $name.Trim() -cne $name) { return $null }
    $m = [regex]::Match($name, '^(path|ext|proc):(.+)$')
    if (!$m.Success) { return $null }
    return @{ kind = $m.Groups[1].Value; value = $m.Groups[2].Value }
}
function HExclusionNameOk([string]$name) {
    $p = HExclusionParse $name
    if ($null -eq $p) { return $false }
    return (HExclusionRisky $p.kind $p.value)
}
function HReadExclusions() {
    Load 'Defender'
    $p = Get-MpPreference
    $out = @{}
    foreach ($pair in @(@('path', 'ExclusionPath'), @('ext', 'ExclusionExtension'), @('proc', 'ExclusionProcess'))) {
        foreach ($entry in @($p.($pair[1]))) {
            if ($null -eq $entry) { continue }
            if ($entry -isnot [string] -or $entry.StartsWith('N/A:')) { throw 'Defender exclusions are not readable' }
            if (!(HExclusionRisky $pair[0] $entry)) { continue }
            $name = $pair[0] + ':' + $entry
            if (!(HExclusionNameOk $name)) { throw 'A risky exclusion cannot be listed safely' }
            $out[$name] = 1
        }
    }
    # A removed exclusion is simply gone from the list: that is the safe state "0".
    foreach ($name in @(HWantedNames)) { if (!$out.ContainsKey($name)) { $out[$name] = 0 } }
    if ($out.Count -gt 256) { throw 'Too many risky exclusions to handle at once' }
    return $out
}
function HSetExclusion([string]$name, $v) {
    $p = HExclusionParse $name
    if ($null -eq $p -or !(HExclusionRisky $p.kind $p.value)) { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid exclusion state' }
    Load 'Defender'
    $add = ([int]$v -eq 1)
    switch -CaseSensitive ($p.kind) {
        'path' { if ($add) { Add-MpPreference -ExclusionPath $p.value } else { Remove-MpPreference -ExclusionPath $p.value } }
        'ext' { if ($add) { Add-MpPreference -ExclusionExtension $p.value } else { Remove-MpPreference -ExclusionExtension $p.value } }
        'proc' { if ($add) { Add-MpPreference -ExclusionProcess $p.value } else { Remove-MpPreference -ExclusionProcess $p.value } }
    }
}

# ---- defender.cfa_*: folder protection mode and the apps it may let through
function HCfaModeNumber($raw) {
    $n = HEnumNumber $raw $hCfa
    if ($n -lt 0 -or $n -gt 4) { throw 'Defender preference is not readable' }
    return $n
}
function HCfaMode() {
    Load 'Defender'
    $prop = (Get-MpPreference).PSObject.Properties['EnableControlledFolderAccess']
    if ($null -eq $prop) { throw 'Defender preference is not readable' }
    return (HCfaModeNumber $prop.Value)
}
function HCfaScriptHosts() { return @('powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe') }
function HCfaAppNameOk([string]$name) {
    if (!$name.StartsWith('app:', [StringComparison]::Ordinal)) { return $false }
    $path = $name.Substring(4)
    if ($path.Length -lt 7 -or $path.Length -gt 260 -or $path.Trim() -cne $path) { return $false }
    if ($path -cnotmatch '^[A-Za-z]:\\') { return $false }
    if ($path -cmatch '[\x00-\x1f\x7f-\x9f"*?<>|%/]' -or $path.IndexOf(':', 2) -ge 0) { return $false }
    $parts = $path.Substring(3).Split([char]92)
    foreach ($part in $parts) {
        if ($part.Length -eq 0 -or $part -ceq '.' -or $part -ceq '..' -or $part.TrimEnd() -cne $part) { return $false }
    }
    $leaf = $parts[$parts.Length - 1].ToLowerInvariant()
    return ($leaf.Length -gt 4 -and $leaf.EndsWith('.exe', [StringComparison]::Ordinal) -and ((HCfaScriptHosts) -cnotcontains $leaf))
}
function HCfaFileExists([string]$path) { return [IO.File]::Exists($path) }
function HCfaAllowedMap() {
    Load 'Defender'
    $map = @{}
    $prop = (Get-MpPreference).PSObject.Properties['ControlledFolderAccessAllowedApplications']
    if ($null -eq $prop) { return $map }
    foreach ($entry in @($prop.Value)) {
        if ($null -eq $entry) { continue }
        if ($entry -isnot [string] -or $entry.StartsWith('N/A:')) { throw 'The allowed apps are not readable' }
        $map[$entry.ToLowerInvariant()] = $entry
    }
    return $map
}
# The program that changed a protected file. The event names it "Process Name"; the position is the fallback.
function HCfaEventPath([string]$xmlText, $props) {
    $path = $null
    try {
        $xml = New-Object Xml.XmlDocument
        $xml.LoadXml($xmlText)
        foreach ($d in @($xml.GetElementsByTagName('Data'))) {
            if ($d.GetAttribute('Name') -ceq 'Process Name') { $path = [string]$d.InnerText }
        }
    } catch { $path = $null }
    if ([string]::IsNullOrWhiteSpace($path)) {
        $list = @($props)
        if ($list.Count -gt 5 -and $null -ne $list[5]) {
            $item = $list[5]
            $path = if ($item.PSObject.Properties['Value']) { [string]$item.Value } else { [string]$item }
        }
    }
    return $path
}
function HCfaAuditedPaths() {
    Load 'Microsoft.PowerShell.Diagnostics'
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1123, 1124; StartTime = (Get-Date).AddDays(-$hCfaEventDays) } -MaxEvents 500 -ErrorAction Stop)
    } catch { return @() }
    $paths = @()
    foreach ($e in $events) {
        $path = HCfaEventPath ([string]$e.ToXml()) @($e.Properties)
        if (![string]::IsNullOrWhiteSpace($path)) { $paths += $path.Trim() }
    }
    return $paths
}
# Apps seen most often first; only ones that pass the name rules, exist and are not allowed yet.
function HCfaPickApps($paths, $allowed) {
    $count = @{}
    $first = @{}
    foreach ($raw in @($paths)) {
        if ($raw -isnot [string]) { continue }
        $path = $raw.Trim()
        if (!(HCfaAppNameOk ('app:' + $path))) { continue }
        $key = $path.ToLowerInvariant()
        if ($allowed.ContainsKey($key)) { continue }
        if (!$count.ContainsKey($key)) { $count[$key] = 0; $first[$key] = $path }
        $count[$key]++
    }
    $keys = @($count.Keys | Where-Object { HCfaFileExists $first[$_] } | Sort-Object @{ Expression = { -$count[$_] } }, @{ Expression = { $_ } })
    return @($keys | Select-Object -First $hCfaMaxApps | ForEach-Object { $first[$_] })
}
# The path with who published the program, so an unknown or unsigned one stands out.
function HCfaSignerNote([string]$path) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        $status = [string]$sig.Status
        if ($status -ceq 'NotSigned') {
            if ($path -match '(?i)\\(temp|downloads|appdata)\\') { return 'not signed, in a temporary or download folder' }
            return 'not signed'
        }
        if ($status -ceq 'Valid' -and $null -ne $sig.SignerCertificate) {
            $who = HClean ([string]$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))
            if ($who.Length -gt 0) { return ('by ' + $who) }
        }
        return 'signature not valid'
    } catch { return '' }
}
function HCfaLabel([string]$path) {
    $note = HCfaSignerNote $path
    if ($note.Length -eq 0) { return $path }
    if ($note.Length -gt 50) { $note = $note.Substring(0, 50) }
    $tail = ' (' + $note + ')'
    $room = 120 - $tail.Length
    $shown = if ($path.Length -gt $room) { $path.Substring(0, $room - 3) + '...' } else { $path }
    return ($shown + $tail)
}
function HReadCfaApps() {
    $allowed = HCfaAllowedMap
    $out = @{}
    $seen = @{}
    $script:hLabels = @{}
    $known = @(HStateNames) + @(HWantedNames)
    foreach ($name in $known) {
        if (!(HCfaAppNameOk $name)) { continue }
        $key = $name.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $out[$name] = if ($allowed.ContainsKey($name.Substring(4).ToLowerInvariant())) { 1 } else { 0 }
    }
    $script:hCfaSeen = @{}
    foreach ($path in @(HCfaPickApps (HCfaAuditedPaths) $allowed)) {
        $script:hCfaSeen[$path.ToLowerInvariant()] = $true
        $name = 'app:' + $path
        if ($seen.ContainsKey($name.ToLowerInvariant())) { continue }
        $seen[$name.ToLowerInvariant()] = $true
        $out[$name] = 0
    }
    foreach ($name in @($out.Keys)) { if ($out[$name] -eq 0) { HLabel $name (HCfaLabel $name.Substring(4)) } }
    if ($out.Count -gt 256) { throw 'Too many apps to handle at once' }
    return $out
}
function HSetCfaApp([string]$name, $v) {
    if (!(HCfaAppNameOk $name)) { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid allowed app state' }
    Load 'Defender'
    $path = $name.Substring(4)
    if ([int]$v -eq 1) {
        # Only an app that was seen changing files in the last week, or one Secblitz allowed before, can be allowed.
        if ($null -eq (HStateGet $name) -and !$script:hCfaSeen.ContainsKey($path.ToLowerInvariant())) { throw 'An app to allow was not seen changing your files' }
        if (!(HCfaFileExists $path)) { throw 'An app to allow could not be found' }
        HStateSet $name @{ path = $path }
        try {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $path
            if (!(HCfaAllowedMap).ContainsKey($path.ToLowerInvariant())) { throw 'Windows did not accept the change. Tamper Protection may be on.' }
        } catch { HStateRemove $name; throw }
    } else {
        # Only an app Secblitz allowed is ever taken off the list.
        if ($null -eq (HStateGet $name)) { throw 'Unknown hardening item' }
        Remove-MpPreference -ControlledFolderAccessAllowedApplications $path
        if ((HCfaAllowedMap).ContainsKey($path.ToLowerInvariant())) { throw 'Windows did not accept the change. Tamper Protection may be on.' }
        HStateRemove $name
    }
}

# ---- accounts.stale_enabled (name = account SID, 1 = switched on, 0 = switched off)
# Only user-created local accounts (RID 1000 and up) that are switched on and
# have not signed in for 180 days. Nothing is ever deleted: the repair is
# Disable-LocalUser and undo is Enable-LocalUser.
function HStaleNameOk([string]$name) {
    $m = [regex]::Match($name, '^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-([1-9][0-9]{3,9})\z')
    if (!$m.Success) { return $false }
    $rid = [int64]$m.Groups[1].Value
    return ($rid -ge 1000 -and $rid -le 4294967295)
}
function HCurrentSid() {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $me) { throw 'The signed-in account cannot be identified' }
    return [string]$me.Value
}
function HSidOfAccount([string]$account) {
    return ([Security.Principal.NTAccount]$account).Translate([Security.Principal.SecurityIdentifier]).Value
}
function HAccountOfSid([string]$sid) {
    return ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value
}
function HAccountsInUse() {
    # SIDs that must not be switched off: the account running this, every
    # account with a live sign-in session, and every account a service runs as.
    # Any doubt throws: the caller then treats the whole control as not offered.
    Load 'CimCmdlets'
    $inUse = @{}
    $inUse[(HCurrentSid)] = $true
    $live = @{}
    foreach ($s in @(Get-CimInstance -ClassName Win32_LogonSession)) { $live[[string]$s.LogonId] = $true }
    foreach ($l in @(Get-CimInstance -ClassName Win32_LoggedOnUser)) {
        if (!$live.ContainsKey([string]$l.Dependent.LogonId)) { continue }
        # Only local accounts can be switched off here; system sessions
        # (SYSTEM, window manager, font driver) belong to other domains.
        if ([string]$l.Antecedent.Domain -ine $env:COMPUTERNAME) { continue }
        $who = ([string]$l.Antecedent.Domain) + '\' + ([string]$l.Antecedent.Name)
        $inUse[(HSidOfAccount $who)] = $true
    }
    $console = [string](Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if ($console) { $inUse[(HSidOfAccount $console)] = $true }
    foreach ($svc in @(Get-CimInstance -ClassName Win32_Service)) {
        $start = [string]$svc.StartName
        if (!$start -or $start -cmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') { continue }
        if ($start.StartsWith('.\')) { $start = $env:COMPUTERNAME + $start.Substring(1) }
        try { $inUse[(HSidOfAccount $start)] = $true } catch { }
    }
    return $inUse
}
function HStaleAccounts() {
    Load 'Microsoft.PowerShell.LocalAccounts'
    $cut = (Get-Date).AddDays(-180)
    $out = @()
    foreach ($u in @(Get-LocalUser)) {
        if ($u.Enabled -ne $true) { continue }
        if (!(HStaleNameOk ([string]$u.SID.Value))) { continue }
        if ($null -eq $u.LastLogon -or $u.LastLogon -ge $cut) { continue }
        $out += $u
    }
    return $out
}
function HEnabledAdminSids() {
    Load 'Microsoft.PowerShell.LocalAccounts'
    $out = @()
    foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
        $sid = [string]$m.SID.Value
        if ([string]$m.ObjectClass -cne 'User' -or $sid -cnotmatch '^S-1-5-21-[0-9-]+$') { continue }
        if ((Get-LocalUser -SID $m.SID -ErrorAction Stop).Enabled -eq $true) { $out += $sid }
    }
    return $out
}
function HAccountState([string]$sid) {
    if (!(HStaleNameOk $sid)) { throw 'Invalid account state' }
    Load 'Microsoft.PowerShell.LocalAccounts'
    try { $user = Get-LocalUser -SID $sid -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return 0 }
        throw
    }
    if ($user.Enabled -eq $true) { return 1 }
    return 0
}
function HReadStale() {
    $out = @{}
    $script:hLabels = @{}
    try { $skip = HAccountsInUse } catch {
        # Unreadable: list nothing the running account could be. The preflight
        # then refuses the repair with a plain reason.
        $skip = @{}
        try { $skip[(HCurrentSid)] = $true } catch { }
    }
    foreach ($u in @(HStaleAccounts)) {
        $sid = [string]$u.SID.Value
        if ($skip.ContainsKey($sid)) { continue }
        $out[$sid] = 1
        HLabel $sid ([string]$u.Name)
    }
    # Every account asked about reports its real state, never a guess from the
    # candidate list: one that is signed in or runs a service is not listed
    # above but is still switched on, and must read 1 so the write can refuse it.
    foreach ($name in @(HWantedNames)) { if (!$out.ContainsKey($name)) { $out[$name] = HAccountState $name } }
    if ($out.Count -gt 256) { throw 'Too many old accounts to handle at once' }
    return $out
}
function HStalePreflight() {
    try { $inUse = HAccountsInUse } catch { throw 'Not offered: Secblitz cannot tell who is signed in' }
    $candidates = @(HStaleAccounts | ForEach-Object { [string]$_.SID.Value } | Where-Object { !$inUse.ContainsKey($_) })
    if ($candidates.Count -eq 0) { return }
    try { $admins = @(HEnabledAdminSids) } catch { throw 'Not offered: no other administrator account could be confirmed' }
    $leaving = @($admins | Where-Object { $candidates -ccontains $_ })
    if ($leaving.Count -gt 0) {
        # Someone who can actually sign in as an administrator must stay (the
        # built-in Administrator account does not count).
        $staying = @($admins | Where-Object { ($candidates -cnotcontains $_) -and ($_ -cnotmatch '-500$') })
        if ($staying.Count -eq 0) { throw 'Not offered: no other administrator account is enabled' }
    }
}
function HSetStale([string]$sid, $v) {
    if (!(HStaleNameOk $sid) -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid account state' }
    Load 'Microsoft.PowerShell.LocalAccounts'
    $user = $null
    try { $user = Get-LocalUser -SID $sid -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
        if ([int]$v -eq 1) { return }
        throw 'The account no longer exists; nothing was changed'
    }
    if ([int]$v -eq 1) { Enable-LocalUser -SID $sid -ErrorAction Stop; return }
    $inUse = HAccountsInUse
    if ($inUse.ContainsKey($sid)) { throw 'This account is in use; nothing was changed' }
    if (@(HStaleAccounts | Where-Object { [string]$_.SID.Value -ceq $sid }).Count -eq 0) { throw 'This account is no longer an old account; nothing was changed' }
    $admins = @(HEnabledAdminSids)
    if (($admins -ccontains $sid) -and @($admins | Where-Object { $_ -cne $sid -and $_ -cnotmatch '-500$' }).Count -eq 0) { throw 'This is the last administrator account; nothing was changed' }
    Disable-LocalUser -SID $sid -ErrorAction Stop
}

# ---- smb.shares_exposed (name = "share|SID|right", 1 = entry present, 0 = removed)
# One name per broad entry (Everyone, Anonymous logon or Guests with Change or
# Full) on a user-created share. The repair removes just that entry with
# Revoke-SmbShareAccess; undo grants the same right back. Other entries,
# administrative shares and the share itself are never touched.
function HShareParts([string]$name) {
    if ($name -cnotmatch '^[^\x00-\x1f\x7f"/\\\[\]:|<>+=;,?*]{1,80}\|(S-1-1-0|S-1-5-7|S-1-5-32-546)\|(Change|Full)\z') { return $null }
    $parts = $name.Split('|')
    if ($parts.Count -ne 3 -or $parts[0].Trim() -cne $parts[0] -or (HBuiltinShare $parts[0])) { return $null }
    return @{ share = $parts[0]; sid = $parts[1]; right = $parts[2] }
}
# Windows' own shares (drive shares, ADMIN$, IPC$, print$) are never touched; a
# hidden share the person made themselves is an ordinary share.
function HBuiltinShare([string]$name) {
    return ($name -imatch '^([A-Za-z]|ADMIN|IPC|print)\$\z')
}
function HFindShare([string]$name) {
    try { return @(Get-SmbShare -Name $name -ErrorAction Stop) }
    catch {
        # Only "no such share" counts as gone; a failed read must not look like a deletion.
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return @() }
        throw
    }
}
function HShareNameOk([string]$name) { return ($null -ne (HShareParts $name)) }
function HBroadAccounts() {
    $map = @{}
    foreach ($sid in @('S-1-1-0', 'S-1-5-7', 'S-1-5-32-546')) {
        $map[$sid] = HAccountOfSid $sid
    }
    return $map
}
function HBroadShareEntries() {
    Load 'SmbShare'
    $broad = HBroadAccounts
    $found = @()
    $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special })
    if ($shares.Count -gt 64) { throw 'Too many shared folders to handle at once' }
    foreach ($share in $shares) {
        $shareName = [string]$share.Name
        if (HBuiltinShare $shareName) { continue }
        $rows = @(Get-SmbShareAccess -Name $shareName -ErrorAction Stop)
        foreach ($access in $rows) {
            if ([string]$access.AccessControlType -cne 'Allow') { continue }
            $right = [string]$access.AccessRight
            if (@('Change', 'Full') -cnotcontains $right) { continue }
            foreach ($sid in @($broad.Keys)) {
                if ([string]$access.AccountName -ine [string]$broad[$sid]) { continue }
                $item = $shareName + '|' + $sid + '|' + $right
                # More than one row for the same account (for example Read and
                # Change) cannot be removed and put back exactly, one right at a time.
                $count = @($rows | Where-Object { [string]$_.AccountName -ieq [string]$broad[$sid] }).Count
                if (HShareNameOk $item) { $found += @{ name = $item; share = $shareName; multi = ($count -ne 1) } }
                else { $found += @{ name = $null; share = $shareName; multi = $false } }
            }
        }
    }
    return $found
}
function HReadShares() {
    $out = @{}
    $script:hLabels = @{}
    foreach ($e in @(HBroadShareEntries)) {
        if ($null -ne $e.name) { $out[$e.name] = 1; HLabel $e.name ([string]$e.share) }
    }
    # A removed entry is simply no longer listed: that is the safe state "0".
    foreach ($name in @(HWantedNames)) { if (!$out.ContainsKey($name)) { $out[$name] = 0 } }
    if ($out.Count -gt 256) { throw 'Too many shared folder entries to handle at once' }
    return $out
}
function HSharesPreflight() {
    Load 'SmbShare'
    $broad = HBroadAccounts
    $entries = @(HBroadShareEntries)
    # Something flagged that cannot be named exactly: leave the whole control alone.
    if (@($entries | Where-Object { $null -eq $_.name }).Count -gt 0) { throw 'Not offered: a shared folder has permissions that could not be put back exactly' }
    if (@($entries | Where-Object { $_.multi }).Count -gt 0) { throw 'Not offered: a shared folder has permissions that could not be put back exactly' }
    $removing = @{}
    foreach ($e in $entries) { $removing[$e.name] = $true }
    $keep = @(@('S-1-5-32-544', 'S-1-5-18') | ForEach-Object { HAccountOfSid $_ })
    foreach ($shareName in @($entries | ForEach-Object { $_.share } | Sort-Object -Unique)) {
        $left = @(Get-SmbShareAccess -Name $shareName -ErrorAction Stop | Where-Object {
            if ([string]$_.AccessControlType -cne 'Allow') { return $false }
            foreach ($sid in @($broad.Keys)) {
                if ([string]$_.AccountName -ieq [string]$broad[$sid] -and $removing.ContainsKey($shareName + '|' + $sid + '|' + [string]$_.AccessRight)) { return $false }
            }
            return $true
        })
        if ($left.Count -eq 0) { throw 'Not offered: a shared folder would be left with no one who can open it' }
        # Only administrators would still be able to open it from other devices.
        $others = @($left | Where-Object { $keep -cnotcontains [string]$_.AccountName })
        if ($others.Count -eq 0) { throw 'Not offered: a shared folder would be left that only administrators can open' }
    }
}
function HSetShare([string]$name, $v) {
    $p = HShareParts $name
    if ($null -eq $p) { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid shared folder state' }
    Load 'SmbShare'
    $share = @(HFindShare $p.share)
    if ($share.Count -eq 0) {
        if ([int]$v -eq 1) { return }
        throw 'The shared folder no longer exists; nothing was changed'
    }
    if ($share[0].Special -eq $true) { throw 'Built-in shares are never changed' }
    $account = [string](HBroadAccounts)[$p.sid]
    $rows = @(Get-SmbShareAccess -Name $p.share -ErrorAction Stop)
    $mine = @($rows | Where-Object { [string]$_.AccountName -ieq $account })
    if ([int]$v -eq 0) {
        # Exactly one row for this account, and it is the recorded one: Revoke
        # removes every row of the account, so anything more could not be put back.
        if ($mine.Count -ne 1 -or [string]$mine[0].AccessControlType -cne 'Allow' -or [string]$mine[0].AccessRight -cne $p.right) { throw 'The shared folder entry changed; nothing was changed' }
        # Never leave a folder that nobody can open.
        $left = @($rows | Where-Object { [string]$_.AccessControlType -ceq 'Allow' -and [string]$_.AccountName -ine $account })
        if ($left.Count -eq 0) { throw 'Not offered: a shared folder would be left with no one who can open it' }
        $null = Revoke-SmbShareAccess -Name $p.share -AccountName $account -Force -ErrorAction Stop
        return
    }
    if ($mine.Count -gt 0) {
        if ($mine.Count -eq 1 -and [string]$mine[0].AccessControlType -ceq 'Allow' -and [string]$mine[0].AccessRight -ceq $p.right) { return }
        throw 'The shared folder entry changed; it was left alone'
    }
    $null = Grant-SmbShareAccess -Name $p.share -AccountName $account -AccessRight $p.right -Force -ErrorAction Stop
}
function HItemGone([string]$name) {
    if ($spec.source -ceq 'StaleAccounts') {
        Load 'Microsoft.PowerShell.LocalAccounts'
        try { $null = Get-LocalUser -SID $name -ErrorAction Stop; return $false }
        catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return $true }; throw }
    }
    $p = HShareParts $name
    if ($null -eq $p) { return $false }
    Load 'SmbShare'
    return (@(HFindShare $p.share).Count -eq 0)
}

# ---- recovery.winre_enabled (1 = the Windows recovery tools are on, 0 = off)
# The state is read from ReAgent.xml, the file in which ReAgentc.exe keeps its
# own settings: InstallState is 1 while the tools are on. Unlike the text that
# ReAgentc /info prints, the file reads the same in every display language,
# and reading it starts no program. Only ReAgentc.exe /enable and /disable
# change anything: partitions, BitLocker and start-up settings are never
# edited here, and Windows moves the recovery image itself.
function HRecoveryDir() { return [IO.Path]::Combine($env:SystemRoot, 'System32\Recovery') }
function HReagentPath() { return [IO.Path]::Combine($env:SystemRoot, 'System32\ReAgentc.exe') }
function HReadRecovery() {
    $file = [IO.Path]::Combine((HRecoveryDir), 'ReAgent.xml')
    if (![IO.File]::Exists($file)) { throw 'The recovery tools setting is not readable' }
    $doc = HLoadXml $file
    $nodes = @($doc.SelectNodes("/*[local-name()='WindowsRE']/*[local-name()='InstallState']"))
    if ($nodes.Count -ne 1) { throw 'The recovery tools setting is not readable' }
    $state = [string]$nodes[0].GetAttribute('state')
    if ($state -ceq '1') { return @{ Enabled = 1 } }
    if ($state -ceq '0') { return @{ Enabled = 0 } }
    throw 'The recovery tools setting is not readable'
}
function HRecoveryImageReady() {
    $image = [IO.FileInfo]::new([IO.Path]::Combine((HRecoveryDir), 'Winre.wim'))
    return ($image.Exists -and $image.Length -gt 0)
}
function HRunHidden([string]$exe, [string]$arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($exe, $arguments)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.WorkingDirectory = [IO.Path]::Combine($env:SystemRoot, 'System32')
    $temp = [IO.Path]::Combine($env:SystemRoot, 'Temp')
    $start.EnvironmentVariables['TEMP'] = $temp
    $start.EnvironmentVariables['TMP'] = $temp
    $drive = [IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd([char]92)
    if ($drive -cmatch '^[A-Za-z]:$') { $start.EnvironmentVariables['SystemDrive'] = $drive }
    $p = [Diagnostics.Process]::Start($start)
    try {
        $p.StandardInput.Close()
        # Both outputs are drained so a full pipe can never stall the tool. The
        # text is in the display language, so it is never parsed: the exit code
        # and a fresh read of the setting decide.
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $null = $out.Result
        $null = $err.Result
        return [int]$p.ExitCode
    } finally { $p.Dispose() }
}
function HRunReagent([string]$verb) {
    if (@('/enable', '/disable') -cnotcontains $verb) { throw 'Unknown recovery tools change' }
    $exe = HReagentPath
    if (![IO.File]::Exists($exe)) { throw 'The recovery tools are missing from this computer' }
    return (HRunHidden $exe $verb)
}
function HSetRecovery([string]$name, $v) {
    if ($name -cne 'Enabled') { throw 'Unknown hardening item' }
    if ($null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid recovery tools state' }
    if ((HReadRecovery).Enabled -eq [int]$v) { return }
    $verb = if ([int]$v -eq 1) { '/enable' } else { '/disable' }
    $code = HRunReagent $verb
    if ($code -ne 0) { throw "Windows could not change the recovery tools (code $code)" }
}

function HParseInput($inputValue) {
    $names = @($inputValue.PSObject.Properties.Name)
    if ($names.Count -ne 1 -or $names[0] -cne 'items') { throw 'Invalid hardening state' }
    $wanted = @{}
    foreach ($p in @($inputValue.items.PSObject.Properties)) {
        if (!(HNameOk $p.Name)) { throw 'Unknown hardening item' }
        $v = $p.Value
        if ($null -ne $v) {
            $def = HDef $p.Name
            if ($def.rule -ceq 'text') {
                if ($v -isnot [string]) { throw 'Invalid hardening value' }
                if ($v.Length -gt [int64]$def.max -or $v -cmatch '[\x00-\x1f\x7f-\x9f]') { throw 'Invalid hardening text' }
            } else {
                if ($v -isnot [int] -and $v -isnot [long]) { throw 'Invalid hardening value' }
                if ($v -lt 0 -or $v -gt [int64]$def.max) { throw 'Hardening value out of range' }
                $v = [int64]$v
            }
        }
        $wanted[$p.Name] = $v
    }
    if (!$spec.dynamic -and $wanted.Count -ne @($spec.keys).Count) { throw 'Hardening state must contain every item' }
    return $wanted
}

function HWrite($inputValue) {
    $wanted = HParseInput $inputValue
    $script:hWanted = $wanted
    HGate
    $current = HRead
    if ($spec.source -ceq 'SmbFeature' -and $script:hSmb1Unreadable) { throw 'Not offered: the old file-sharing version could not be checked' }
    $steps = @()
    $repairing = $false
    foreach ($name in @($wanted.Keys | Sort-Object)) {
        if (!$current.ContainsKey($name)) { throw "Item $name no longer exists; nothing was changed" }
        $cur = $current[$name]; $want = $wanted[$name]
        if (HEq $cur $want) { continue }
        $def = HDef $name
        if (!(HIsSafe $def $cur) -and (HEq (HFixOf $def $cur) $want)) { $repairing = $true }
        elseif (!(HIsSafe $def $want) -and (HEq (HFixOf $def $want) $cur)) { }
        else { throw "Item $name changed before the write; nothing was changed" }
        $steps += @{ name = $name; from = $cur; to = $want }
    }
    if ($repairing) { HPreflight }
    if ($spec.source -ceq 'SmbFeature' -and $repairing) { $steps = @($steps | Sort-Object { $_.name } -Descending) }
    $done = @()
    try {
        foreach ($s in $steps) { HSet $s.name $s.to; $done += $s }
        if ($spec.source -ceq 'SmbFeature' -and !$repairing) {
            # Turning a part back on must not bring back parts that were off. If one now reads on, turn it off again.
            $after = HRead
            foreach ($name in @($wanted.Keys | Sort-Object -Descending)) {
                if ($wanted[$name] -eq 0 -and $after.ContainsKey($name) -and $after[$name] -eq 1) { HSet $name 0; $done += @{ name = $name; from = 1; to = 0 } }
            }
        }
        $verified = $false
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            $now = HRead
            $ok = $true
            foreach ($name in $wanted.Keys) { if (!$now.ContainsKey($name) -or !(HVerified $name $now[$name] $wanted[$name])) { $ok = $false } }
            if ($ok) { $verified = $true; break }
            if ($attempt -lt 9) { Start-Sleep -Milliseconds 500 }
        }
        if (!$verified) {
            if ($spec.id.StartsWith('defender.')) { throw 'Readback did not match; Windows Security may be blocking this change (tamper protection); mutation outcome requires review' }
            throw 'Readback did not match; mutation outcome requires review'
        }
    } catch {
        $failure = $_
        # Best effort: put back what this call changed so undo still matches.
        for ($i = $done.Count - 1; $i -ge 0; $i--) { try { HSet $done[$i].name $done[$i].from } catch { } }
        throw $failure
    }
}

try {
    switch -CaseSensitive ($action) {
        'observe' { Emit (HObserve) }
        'write' { HWrite $value; Emit @{ok=$true} }
        default { throw 'Unknown operation' }
    }
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
