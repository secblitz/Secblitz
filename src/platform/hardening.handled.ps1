# Handled-item controls: services.unquoted_paths, firewall.user_dir_inbound_allow, net.hosts_file,
# persistence.run_and_tasks, browser.extensions_off. Each item reads 1 while flagged and untouched, 0 while exactly as Secblitz
# left it, 2 when Secblitz fixed it and someone changed it since. The exact original lives in
# HKLM\\Software\\Secblitz\\HardeningUndo\\<control id>. Nothing is deleted; no child process is started.
$hUserDirPattern = '\\users\\[^\\]+\\(downloads|desktop|appdata\\local\\temp)\\|\\users\\public\\|\\windows\\temp\\|%userprofile%\\(downloads|desktop)\\|%temp%\\|%public%\\'
$hHostsBroad = '(^|\.)(microsoft|windowsupdate|windows|live|office|office365|msedge|xbox)\.(com|net)\z|defender|kaspersky|avast|avg\.com|norton|symantec|mcafee|malwarebytes|bitdefender|eset\.|sophos|trendmicro|avira|webroot|paypal|bank|chase\.com|wellsfargo|citibank|hsbc|barclays|santander|capitalone|americanexpress|revolut'
$hHostsUpdate = 'windowsupdate\.com\z|(^|\.)update\.microsoft\.com\z|(^|\.)download\.microsoft\.com\z|(^|\.)smartscreen[^.]*\.microsoft\.com\z|(^|\.)wdcp\.microsoft\.com\z|defender|kaspersky|avast|norton|symantec|mcafee|malwarebytes|bitdefender|eset\.|sophos|trendmicro|avira|webroot'
$hHostsNote = '# turned off by Secblitz '
$hHostsMaxBytes = 131072
$hStartupMax = 48
$hLabelLimit = 48
$script:hLabels = @{}
$script:hLeft = @()
$script:hMe = $null
$script:hUnquotedCache = $null
$script:hStartupCache = $null

function HStateSub() { return ('SOFTWARE\Secblitz\HardeningUndo\' + [string]$spec.id) }
function HStateNames() {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HStateSub), $false)
    if ($null -eq $key) { return @() }
    try { return @($key.GetValueNames()) } finally { $key.Dispose() }
}
function HStateGet([string]$name) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HStateSub), $false)
    if ($null -eq $key) { return $null }
    try {
        if ($key.GetValueNames() -cnotcontains $name) { return $null }
        $text = $key.GetValue($name)
        if ($text -isnot [string]) { return $null }
        return (ConvertFrom-Json -InputObject $text)
    } finally { $key.Dispose() }
}
function HStateSet([string]$name, $data) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey((HStateSub))
    try { $key.SetValue($name, (ConvertTo-Json -InputObject $data -Compress), [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
}
function HStateRemove([string]$name) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HStateSub), $true)
    if ($null -eq $key) { return }
    try {
        if ($key.GetValueNames() -ccontains $name) { $key.DeleteValue($name, $false) }
    } finally { $key.Dispose() }
}
function HSha256Hex([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()) } finally { $sha.Dispose() }
}
function HClean([string]$text) {
    $clean = ($text -replace '[\x00-\x1f\x7f]', ' ').Trim()
    if ($clean.Length -gt 120) { $clean = $clean.Substring(0, 120) }
    return $clean
}
function HLabel([string]$name, [string]$text) { $script:hLabels[$name] = (HClean $text) }
function HLabelKind([string]$name) {
    switch -CaseSensitive ([string]$spec.source) {
        'UnquotedServices' { return 'service' }
        'UserDirFirewall' { return 'rule' }
        'HostsFile' { return 'hosts' }
        'StartupItems' { if ($name.StartsWith('task:')) { return 'task' } else { return 'startup' } }
        'StaleAccounts' { return 'account' }
        'ShareGrants' { return 'share' }
        'BrowserExtensions' { return 'addon' }
        'CfaAllowedApps' { return 'app' }
    }
    return ''
}
function HLabelList($slice) {
    $out = @()
    $more = 0
    $flagged = if ([string]$spec.source -ceq 'CfaAllowedApps') { 0 } else { 1 }
    foreach ($name in @($slice.Keys | Sort-Object)) {
        if (!$script:hLabels.ContainsKey($name) -or $null -eq $slice[$name] -or $slice[$name] -is [string] -or [int64]$slice[$name] -ne $flagged) { continue }
        $kind = HLabelKind $name
        if ($kind -eq '') { continue }
        foreach ($text in @($script:hLabels[$name])) {
            if ($out.Count -lt $hLabelLimit) {
                $entry = @{ kind = $kind; name = [string]$text }
                if ($kind -ceq 'addon') { $entry.key = $name; $entry.why = (@($script:hAddonInfo[$name]) -join ',') }
                $out += $entry
            } else { $more++ }
        }
    }
    foreach ($left in @($script:hLeft | Select-Object -First 8)) { $out += $left }
    if ($more -gt 0) { $out += @{ kind = 'more'; name = [string]$more } }
    return $out
}

function HServicesRoot() { return 'SYSTEM\CurrentControlSet\Services' }
function HBroadWriters() { return @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') }
function HDirWritable([string]$dir, $cache) {
    if ($cache.ContainsKey($dir)) { return [bool]$cache[$dir] }
    $result = $false
    try {
        if ([IO.Directory]::Exists($dir)) {
            $acl = (New-Object IO.DirectoryInfo $dir).GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
                if ((HBroadWriters) -cnotcontains $rule.IdentityReference.Value) { continue }
                if (([int]$rule.PropagationFlags -band 2) -ne 0) { continue }
                if ((([int]$rule.FileSystemRights) -band (2 -bor 262144 -bor 524288)) -ne 0) { $result = $true }
            }
        }
    } catch { $result = $false }
    $cache[$dir] = $result
    return $result
}
function HUnquotedSplit([string]$raw) {
    # The program part of an unquoted path that has spaces, or $null. Leading and
    # trailing blanks would not survive a quote-and-unquote round trip, so those are left alone.
    if ($raw -cne $raw.Trim() -or $raw.StartsWith('"') -or $raw -notmatch '^(?<exe>[A-Za-z]:\\.*?\.exe)(\s|$)') { return $null }
    $exe = $Matches['exe']
    if (!$exe.Contains(' ') -or $exe.Contains('"')) { return $null }
    return $exe
}
function HUnquotedProblem([string]$exe) {
    # $null when quoting is safe, otherwise the reason it is not offered.
    if (![IO.File]::Exists($exe)) { return 'A background program file could not be found' }
    $at = $exe.IndexOf(' ')
    while ($at -ge 0) {
        $candidate = $exe.Substring(0, $at)
        foreach ($path in @(($candidate + '.exe'), $candidate)) {
            if ($path -cne $exe -and [IO.File]::Exists($path)) { return 'Another program could be started first' }
        }
        $at = $exe.IndexOf(' ', $at + 1)
    }
    return $null
}
function HUnquotedEntries() {
    $out = @()
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HServicesRoot), $false)
    if ($null -eq $root) { throw 'The list of background programs is not readable' }
    $cache = @{}
    try {
        $names = @($root.GetSubKeyNames())
        if ($names.Count -gt 4096) { throw 'Too many background programs to check' }
        foreach ($name in $names) {
            $key = $root.OpenSubKey($name, $false)
            if ($null -eq $key) { continue }
            try {
                $type = $key.GetValue('Type', $null)
                if ($type -isnot [int] -or ($type -band 0x30) -eq 0) { continue }
                if ($key.GetValueNames() -cnotcontains 'ImagePath') { continue }
                $kind = $key.GetValueKind('ImagePath')
                if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String -and $kind -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) { continue }
                $raw = $key.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($raw -isnot [string]) { continue }
                $exe = HUnquotedSplit $raw
                if ($null -eq $exe) { continue }
                $hit = $false
                $at = $exe.IndexOf(' ')
                while ($at -ge 0) {
                    $dir = [IO.Path]::GetDirectoryName($exe.Substring(0, $at))
                    if ($null -ne $dir -and (HDirWritable $dir $cache)) { $hit = $true }
                    $at = $exe.IndexOf(' ', $at + 1)
                }
                if (!$hit -or !(HNameOk $name)) { continue }
                $out += @{ name = $name; raw = $raw; exe = $exe; fixed = ('"' + $exe + '"' + $raw.Substring($exe.Length)); kind = $kind; problem = (HUnquotedProblem $exe) }
            } finally { $key.Dispose() }
        }
    } finally { $root.Dispose() }
    return $out
}
function HUnquotedEntriesOnce() {
    if ($null -eq $script:hUnquotedCache) { $script:hUnquotedCache = @(HUnquotedEntries) }
    return $script:hUnquotedCache
}
function HReadUnquoted() {
    $out = @{}
    $script:hLabels = @{}
    $script:hLeft = @()
    $script:hUnquotedCache = $null
    foreach ($e in @(HUnquotedEntries)) {
        # A service whose file is missing, or that could be shadowed by another
        # file, is left alone and named in the details; the others are still fixed.
        if ($null -ne $e.problem) {
            $kind = $(if ($e.problem -like '*could not be found*') { 'skip_missing' } else { 'skip_shadow' })
            $script:hLeft += @{ kind = $kind; name = (HClean $e.name) }
            continue
        }
        $out[$e.name] = 1
        HLabel $e.name ($e.name + ' (' + $e.exe + ')')
    }
    foreach ($name in @(HStateNames)) {
        if ($out.ContainsKey($name) -or !(HNameOk $name)) { continue }
        $st = HStateGet $name
        if ($null -eq $st) { continue }
        $current = $null
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HServicesRoot) + '\' + $name, $false)
        if ($null -ne $key) {
            try { if ($key.GetValueNames() -ccontains 'ImagePath') { $current = $key.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } } finally { $key.Dispose() }
        }
        $out[$name] = $(if ($current -is [string] -and $current -ceq [string]$st.f) { 0 } else { 2 })
    }
    if ($out.Count -gt 256) { throw 'Too many background programs to handle at once' }
    return $out
}
function HSetUnquoted([string]$name, $v) {
    if (!(HNameOk $name) -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid background program state' }
    $path = (HServicesRoot) + '\' + $name
    if ([int]$v -eq 0) {
        $entry = @(HUnquotedEntriesOnce | Where-Object { $_.name -ceq $name })
        if ($entry.Count -ne 1) { throw 'The background program no longer needs a change' }
        $e = $entry[0]
        if ($null -ne $e.problem) { throw $e.problem }
        HStateSet $name @{ o = [string]$e.raw; f = [string]$e.fixed }
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $true)
            if ($null -eq $key) { throw 'The background program was not found' }
            try { $key.SetValue('ImagePath', [string]$e.fixed, $e.kind) } finally { $key.Dispose() }
        } catch { HStateRemove $name; throw }
        return
    }
    $st = HStateGet $name
    if ($null -eq $st) { throw 'Secblitz no longer has the saved original for this background program' }
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $true)
    if ($null -eq $key) { throw 'The background program was not found' }
    try {
        $current = $key.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($current -isnot [string] -or $current -cne [string]$st.f) { throw 'The background program changed again; it was left alone' }
        $key.SetValue('ImagePath', [string]$st.o, $key.GetValueKind('ImagePath'))
    } finally { $key.Dispose() }
    HStateRemove $name
}

function HFirewallProgramOf($rule, $programs) {
    # The program filters are read once for all rules (one call per rule is very
    # slow with hundreds of rules). A rule missing from that list is asked directly.
    foreach ($key in @([string]$rule.InstanceID, [string]$rule.Name)) {
        if ($key -ne '' -and $programs.ContainsKey($key)) { return [string]$programs[$key] }
    }
    return ([string]@($rule | Get-NetFirewallApplicationFilter)[0].Program)
}
function HFirewallPrograms() {
    $map = @{}
    foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore PersistentStore -ErrorAction Stop)) { $map[[string]$f.InstanceID] = [string]$f.Program }
    return $map
}
function HReadUserDirFirewall() {
    Load 'NetSecurity'
    $out = @{}
    $script:hLabels = @{}
    $seen = @{}
    try { $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $rules = @() }
    if ($rules.Count -gt 2048) { throw 'Too many firewall rules to check' }
    $programs = $(if ($rules.Count -gt 0) { HFirewallPrograms } else { @{} })
    foreach ($rule in $rules) {
        $name = [string]$rule.Name
        $program = HFirewallProgramOf $rule $programs
        if ($program -eq '' -or $program -ceq 'Any') { continue }
        if ($program.ToLowerInvariant() -cnotmatch $hUserDirPattern) { continue }
        if (!(HNameOk $name)) { continue }
        # Two rules with one name are ambiguous: leave them alone.
        if ($seen.ContainsKey($name)) { $out.Remove($name); continue }
        $seen[$name] = $true
        $out[$name] = 1
        $display = [string]$rule.DisplayName
        if ($display -eq '' -or $display.StartsWith('@')) { $display = $name }
        HLabel $name ($display + ' (' + $program + ')')
    }
    foreach ($name in @(HStateNames)) {
        if ($out.ContainsKey($name) -or !(HNameOk $name)) { continue }
        $found = @()
        try { $found = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop) }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
        $out[$name] = $(if ($found.Count -eq 1 -and [string]$found[0].Enabled -ceq 'False') { 0 } else { 2 })
    }
    if ($out.Count -gt 256) { throw 'Too many firewall rules to handle at once' }
    return $out
}
function HSetUserDirFirewall([string]$name, $v) {
    if (!(HNameOk $name) -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid firewall rule state' }
    Load 'NetSecurity'
    $found = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop)
    if ($found.Count -ne 1) { throw 'The firewall rule was not found exactly once' }
    if ([int]$v -eq 0) {
        # Only this one rule is checked: it must still be an enabled inbound allow rule for a program in a personal folder.
        $rule = $found[0]
        $program = ([string]@($rule | Get-NetFirewallApplicationFilter)[0].Program)
        $flagged = ([string]$rule.Enabled -ceq 'True' -and [string]$rule.Direction -ceq 'Inbound' -and [string]$rule.Action -ceq 'Allow' -and $program -ne '' -and $program -cne 'Any' -and $program.ToLowerInvariant() -cmatch $hUserDirPattern)
        if (!$flagged) { throw 'The firewall rule no longer needs a change' }
        HStateSet $name @{ was = 'enabled' }
        try { Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled False -ErrorAction Stop }
        catch { HStateRemove $name; throw }
        return
    }
    if ($null -eq (HStateGet $name)) { throw 'Secblitz no longer has the saved state for this firewall rule' }
    if ([string]$found[0].Enabled -cne 'False') { throw 'The firewall rule changed again; it was left alone' }
    Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled True -ErrorAction Stop
    HStateRemove $name
}

function HHostsPath() { return [IO.Path]::Combine($env:SystemRoot, 'System32\drivers\etc\hosts') }
function HHostsBytes() {
    $p = HHostsPath
    if (![IO.File]::Exists($p)) { return $null }
    if ((New-Object IO.FileInfo $p).Length -gt 4194304) { throw 'The hosts file is too large to read' }
    return ,[byte[]][IO.File]::ReadAllBytes($p)
}
function HHostsPlain([byte[]]$bytes) {
    # ASCII-compatible text with Windows or Unix line ends only (UTF-8 included):
    # changing it keeps every other byte as it was. UTF-16, NUL bytes and a lone
    # carriage return (which the Tools check reads as a line end) are not kept exactly.
    if ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) { return $false }
    if ([Array]::IndexOf($bytes, [byte]0) -ge 0) { return $false }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13 -and ($i + 1 -ge $bytes.Length -or $bytes[$i + 1] -ne 10)) { return $false }
    }
    return $true
}
function HHostsLineFlag([string]$line) {
    # Same test as the Tools security check (probes.ps1, HostsFile).
    $text = $line
    $hash = $text.IndexOf('#')
    if ($hash -ge 0) { $text = $text.Substring(0, $hash) }
    $parts = @($text.Trim() -split '\s+' | Where-Object { $_ -ne '' })
    if ($parts.Count -lt 2) { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address)) { return $false }
    $loop = $parts[0] -cin @('127.0.0.1', '::1', '0.0.0.0', '::')
    $broad = $false; $update = $false
    foreach ($h in @($parts[1..($parts.Count - 1)] | ForEach-Object { $_.ToLowerInvariant() })) {
        if ($h -match $hHostsBroad) { $broad = $true }
        if ($h -match $hHostsUpdate) { $update = $true }
    }
    if ($loop) { return $update }
    return $broad
}
function HHostsText([byte[]]$bytes) { return [Text.Encoding]::GetEncoding(28591).GetString($bytes) }
function HHostsBom() { return ([string][char]0xEF + [char]0xBB + [char]0xBF) }
function HHostsFlaggedLines([byte[]]$bytes) {
    $out = @()
    $bom = HHostsBom
    $first = $true
    foreach ($raw in @((HHostsText $bytes) -split "`n")) {
        $line = $raw.TrimEnd([char]13)
        # A byte order mark can only sit at the very start of the file.
        if ($first -and $line.StartsWith($bom, [StringComparison]::Ordinal)) { $line = $line.Substring(3) }
        $first = $false
        if (HHostsLineFlag $line) { $out += $line }
    }
    return $out
}
function HHostsFlaggedOther() {
    # Same decoding as the Tools check, for files we cannot rewrite exactly (UTF-16, lone CR).
    $out = @()
    foreach ($line in @([IO.File]::ReadAllLines((HHostsPath)))) { if (HHostsLineFlag $line) { $out += $line } }
    return $out
}
function HHostsFix([byte[]]$bytes) {
    # Comment out only the flagged lines; every other byte stays exactly as it was.
    $bom = HHostsBom
    $lines = @((HHostsText $bytes) -split "`n")
    $done = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $raw = $lines[$i]
        $cr = ''
        if ($raw.Length -gt 0 -and $raw[$raw.Length - 1] -eq [char]13) { $cr = [string][char]13; $raw = $raw.Substring(0, $raw.Length - 1) }
        $head = ''
        if ($i -eq 0 -and $raw.StartsWith($bom, [StringComparison]::Ordinal)) { $head = $bom; $raw = $raw.Substring(3) }
        if (HHostsLineFlag $raw) { $raw = $hHostsNote + $raw }
        $done += ($head + $raw + $cr)
    }
    return ,[byte[]][Text.Encoding]::GetEncoding(28591).GetBytes(($done -join "`n"))
}
function HHostsReadOnly() { return (([int][IO.File]::GetAttributes((HHostsPath)) -band 1) -ne 0) }
function HReadHosts() {
    $out = @{}
    $script:hLabels = @{}
    $bytes = HHostsBytes
    if ($null -eq $bytes) { return $out }
    $plain = HHostsPlain $bytes
    $flagged = @(if ($plain) { HHostsFlaggedLines $bytes } else { HHostsFlaggedOther })
    if ($flagged.Count -gt 0) {
        # Not offered (by the preflight) when the file is in a format we cannot keep exactly.
        $out['hosts'] = 1
        $script:hLabels['hosts'] = @($flagged | ForEach-Object { HClean $_ } | Where-Object { $_ -ne '' })
        return $out
    }
    $st = HStateGet 'hosts'
    if ($null -ne $st) { $out['hosts'] = $(if ((HSha256Hex $bytes) -ceq [string]$st.f -and !(HHostsReadOnly)) { 0 } else { 2 }) }
    return $out
}
function HHostsWrite([byte[]]$bytes) {
    $fs = New-Object IO.FileStream((HHostsPath), [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        # Overwrite in place, then cut to length: the file is never empty part-way.
        $fs.Position = 0
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.SetLength($bytes.Length)
        $fs.Flush($true)
    } finally { $fs.Dispose() }
}
function HHostsSetReadOnly([bool]$on) {
    $p = HHostsPath
    $attrs = [int][IO.File]::GetAttributes($p)
    $attrs = $(if ($on) { $attrs -bor 1 } else { $attrs -band (-bnot 1) })
    [IO.File]::SetAttributes($p, [IO.FileAttributes]$attrs)
}
function HFlushDns() {
    try { Load 'DnsClient'; Clear-DnsClientCache -ErrorAction Stop } catch { }
}
function HSetHosts([string]$name, $v) {
    if ($name -cne 'hosts' -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid hosts file state' }
    $current = HHostsBytes
    if ($null -eq $current) { throw 'The hosts file was not found' }
    if ([int]$v -eq 0) {
        if (!(HHostsPlain $current) -or @(HHostsFlaggedLines $current).Count -eq 0) { throw 'The hosts file no longer needs a change' }
        $fixed = HHostsFix $current
        $ro = HHostsReadOnly
        HStateSet 'hosts' @{ o = [Convert]::ToBase64String($current); f = (HSha256Hex $fixed); ro = $ro }
        try {
            # A read-only mark is cleared for the change and put back by undo.
            if ($ro) { HHostsSetReadOnly $false }
            HHostsWrite $fixed
        } catch {
            try { HHostsWrite $current } catch { }
            try { if ($ro) { HHostsSetReadOnly $true } } catch { }
            HStateRemove 'hosts'
            throw
        }
        HFlushDns
        return
    }
    $st = HStateGet 'hosts'
    if ($null -eq $st) { throw 'Secblitz no longer has the saved original of the hosts file' }
    if ((HSha256Hex $current) -cne [string]$st.f -or (HHostsReadOnly)) { throw 'The hosts file changed again; it was left alone' }
    HHostsWrite ([Convert]::FromBase64String([string]$st.o))
    if ($st.ro -eq $true) { HHostsSetReadOnly $true }
    HStateRemove 'hosts'
    HFlushDns
}
function HHostsPreflight() {
    $bytes = HHostsBytes
    if ($null -eq $bytes) { throw 'Not offered: the hosts file could not be found' }
    if ($bytes.Length -gt $hHostsMaxBytes) { throw 'Not offered: the hosts file is too large to change safely' }
    if (!(HHostsPlain $bytes)) { throw 'Not offered: the hosts file uses a format we cannot keep exactly' }
}

function HStartupRoot([string]$kind) {
    # Where each kind of entry lives and where Windows keeps its on/off switch.
    $explorer = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\'
    $run = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    switch -CaseSensitive ($kind) {
        'run-machine' { return @{ hive = [Microsoft.Win32.Registry]::LocalMachine; run = $run; approved = ($explorer + 'Run') } }
        'run-machine32' { return @{ hive = [Microsoft.Win32.Registry]::LocalMachine; run = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; approved = ($explorer + 'Run32') } }
        'run-user' { return @{ hive = [Microsoft.Win32.Registry]::CurrentUser; run = $run; approved = ($explorer + 'Run') } }
        'folder-machine' { return @{ hive = [Microsoft.Win32.Registry]::LocalMachine; dir = [Environment]::GetFolderPath('CommonStartup'); approved = ($explorer + 'StartupFolder') } }
        'folder-user' { return @{ hive = [Microsoft.Win32.Registry]::CurrentUser; dir = [Environment]::GetFolderPath('Startup'); approved = ($explorer + 'StartupFolder') } }
    }
    throw 'Unknown start-up entry kind'
}
function HStartupExpand([string]$text) {
    $t = $text.Trim()
    $appData = [Environment]::GetFolderPath('ApplicationData')
    $localData = [Environment]::GetFolderPath('LocalApplicationData')
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $commonData = [Environment]::GetFolderPath('CommonApplicationData')
    $publicDir = $null
    try { $publicDir = [IO.Path]::GetDirectoryName([Environment]::GetFolderPath('CommonDocuments')) } catch { }
    foreach ($pair in @(@('%appdata%', $appData), @('%localappdata%', $localData), @('%temp%', "$localData\Temp"), @('%tmp%', "$localData\Temp"), @('%userprofile%', $userProfile), @('%programdata%', $commonData), @('%public%', $publicDir))) {
        if ($null -ne $pair[1]) { $t = $t -ireplace [regex]::Escape($pair[0]), $pair[1].Replace('$', '$$') }
    }
    return [Environment]::ExpandEnvironmentVariables($t)
}
function HStartupTarget([string]$command) {
    $c = (HStartupExpand $command).Trim()
    if ($c -match '^"(?<p>[^"]+)"') { return $Matches['p'] }
    if ($c -match '^(?<p>[A-Za-z]:\\.*?\.(exe|dll|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|scr|com|lnk|msi|cpl))(\s|$)') { return $Matches['p'] }
    return $null
}
function HStartupRisky([string]$command, [string]$exePath, [bool]$startupFolder) {
    # Same test as the Tools security check (probes.ps1, Autostart).
    $lower = $command.ToLowerInvariant()
    if ($lower -match '(powershell|pwsh)(\.exe)?["\s].*\s-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{40,}' -or $lower -match '(mshta|regsvr32|certutil|bitsadmin|rundll32)\b.*https?://' -or $lower -match '(powershell|pwsh)\b.*(downloadstring|downloadfile|net\.webclient|\biwr\b|\biex\b)') { return $true }
    $path = $null
    if ($exePath -ne '') { $path = (HStartupExpand $exePath).Trim().Trim('"') } else { $path = HStartupTarget $command }
    if ($null -eq $path -or $path -cnotmatch '^[A-Za-z]:\\') { return $false }
    $p = $path.ToLowerInvariant()
    $riskyPath = '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\downloads\\|\\appdata\\roaming\\[^\\]+\z'
    $scripts = '\.(bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1)\z'
    $here = ($p -match $riskyPath) -or ($startupFolder -and $p -match $scripts)
    if (-not $here) { return $false }
    if (-not [IO.File]::Exists($path)) { return $false }
    try { $status = [string](Get-AuthenticodeSignature -LiteralPath $path).Status } catch { return $false }
    return ($status -cne 'Valid')
}
function HApprovedBytes($root, [string]$name) {
    # $null when the entry has no on/off record; the text 'odd' when the record is
    # not binary (such an entry is left alone); otherwise the exact bytes.
    $key = $root.hive.OpenSubKey($root.approved, $false)
    if ($null -eq $key) { return $null }
    try {
        if ($key.GetValueNames() -cnotcontains $name) { return $null }
        if ($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::Binary) { return 'odd' }
        return ,[byte[]]$key.GetValue($name)
    } finally { $key.Dispose() }
}
function HInteractiveIsMe() {
    # The per-user start-up lists are only touched when this elevated process runs
    # as the person signed in at the screen; otherwise it would be another profile.
    if ($null -ne $script:hMe) { return [bool]$script:hMe }
    $script:hMe = $false
    try {
        Load 'CimCmdlets'
        $who = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($who -ne '') {
            $sid = (New-Object Security.Principal.NTAccount($who)).Translate([Security.Principal.SecurityIdentifier]).Value
            $script:hMe = ($sid -ceq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        }
    } catch { $script:hMe = $false }
    return [bool]$script:hMe
}
function HIsUserKind([string]$kind) { return ($kind -ceq 'run-user' -or $kind -ceq 'folder-user') }
function HApprovedEnabled($bytes) {
    # Task Manager marks an entry off with an odd first byte (3); anything else runs.
    if ($null -eq $bytes) { return $true }
    if ($bytes.Length -lt 4) { return $false }
    return (($bytes[0] -band 1) -eq 0)
}
function HStartupEntriesOnce() {
    if ($null -eq $script:hStartupCache) { $script:hStartupCache = @(HStartupEntries) }
    return $script:hStartupCache
}
function HStartupEntries() {
    $out = @()
    foreach ($kind in @('run-machine', 'run-machine32', 'run-user')) {
        if ((HIsUserKind $kind) -and !(HInteractiveIsMe)) { continue }
        $root = HStartupRoot $kind
        $key = $root.hive.OpenSubKey($root.run, $false)
        if ($null -eq $key) { continue }
        try {
            $names = @($key.GetValueNames())
            if ($names.Count -gt 256) { throw 'Too many start-up entries to check' }
            foreach ($valueName in $names) {
                $value = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($value -isnot [string] -or $value.Length -ge 2048 -or $valueName -eq '') { continue }
                $name = $kind + ':' + $valueName
                if (!(HNameOk $name) -or !(HStartupRisky $value '' $false)) { continue }
                $approved = HApprovedBytes $root $valueName
                if ($approved -is [string] -or !(HApprovedEnabled $approved)) { continue }
                $out += @{ name = $name; kind = $kind; item = $valueName; label = ($valueName + ' (' + $value + ')') }
            }
        } finally { $key.Dispose() }
    }
    foreach ($kind in @('folder-machine', 'folder-user')) {
        if ((HIsUserKind $kind) -and !(HInteractiveIsMe)) { continue }
        $root = HStartupRoot $kind
        $dir = [string]$root.dir
        if ([string]::IsNullOrEmpty($dir) -or -not [IO.Directory]::Exists($dir)) { continue }
        $files = @([IO.Directory]::GetFiles($dir))
        if ($files.Count -gt 256) { throw 'Too many start-up entries to check' }
        foreach ($file in $files) {
            $leaf = [IO.Path]::GetFileName($file)
            if ($leaf -ceq 'desktop.ini') { continue }
            if ($file.EndsWith('.lnk', [StringComparison]::OrdinalIgnoreCase)) {
                $shell = New-Object -ComObject WScript.Shell
                $link = $shell.CreateShortcut($file)
                $risky = HStartupRisky ('"' + $link.TargetPath + '" ' + $link.Arguments) '' $true
            } else { $risky = HStartupRisky $file $file $true }
            $name = $kind + ':' + $leaf
            if (!$risky -or !(HNameOk $name)) { continue }
            $approved = HApprovedBytes $root $leaf
            if ($approved -is [string] -or !(HApprovedEnabled $approved)) { continue }
            $out += @{ name = $name; kind = $kind; item = $leaf; label = $leaf }
        }
    }
    Load 'ScheduledTasks'
    $tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -notlike 'Secblitz*' -and [string]$_.State -cne 'Disabled' } | Select-Object -First 2049)
    if ($tasks.Count -gt 2048) { throw 'Too many scheduled tasks to check' }
    foreach ($task in $tasks) {
        $risky = $false
        foreach ($action in @($task.Actions)) {
            if ($null -eq $action.PSObject.Properties['Execute'] -or [string]::IsNullOrWhiteSpace([string]$action.Execute)) { continue }
            if (HStartupRisky (([string]$action.Execute) + ' ' + ([string]$action.Arguments)) ([string]$action.Execute) $false) { $risky = $true }
        }
        $name = 'task:' + [string]$task.TaskPath + [string]$task.TaskName
        if (!$risky -or !(HNameOk $name)) { continue }
        $out += @{ name = $name; kind = 'task'; item = [string]$task.TaskName; label = ([string]$task.TaskPath + [string]$task.TaskName) }
    }
    return $out
}
function HTaskParts([string]$name) {
    $m = [regex]::Match($name, '^task:(?<path>\\(?:.*\\)?)(?<leaf>[^\\]+)\z')
    if (!$m.Success) { throw 'Invalid scheduled task name' }
    return @{ path = $m.Groups['path'].Value; leaf = $m.Groups['leaf'].Value }
}
function HStartupTaskState([string]$name) {
    $parts = HTaskParts $name
    Load 'ScheduledTasks'
    $found = @(Get-ScheduledTask -TaskPath $parts.path -TaskName $parts.leaf -ErrorAction SilentlyContinue)
    if ($found.Count -ne 1) { return $null }
    return [string]$found[0].State
}
function HReadStartup() {
    $out = @{}
    $script:hLabels = @{}
    $script:hStartupCache = $null
    foreach ($e in @(HStartupEntries)) { $out[$e.name] = 1; HLabel $e.name $e.label }
    foreach ($name in @(HStateNames)) {
        if ($out.ContainsKey($name) -or !(HNameOk $name)) { continue }
        $st = HStateGet $name
        if ($null -eq $st) { continue }
        if ($name.StartsWith('task:')) { $out[$name] = $(if ((HStartupTaskState $name) -ceq 'Disabled') { 0 } else { 2 }); continue }
        $kind = $name.Substring(0, $name.IndexOf(':'))
        # Another account's lists are never read as if they were this person's.
        if ((HIsUserKind $kind) -and !(HInteractiveIsMe)) { $out[$name] = 2; continue }
        $current = HApprovedBytes (HStartupRoot $kind) $name.Substring($kind.Length + 1)
        $out[$name] = $(if ($current -is [byte[]] -and [Convert]::ToBase64String($current) -ceq [string]$st.d) { 0 } else { 2 })
    }
    if ($out.Count -gt 256) { throw 'Too many start-up items to handle at once' }
    return $out
}
function HSetApproved($root, [string]$item, [byte[]]$bytes) {
    $key = $root.hive.CreateSubKey($root.approved)
    try { $key.SetValue($item, $bytes, [Microsoft.Win32.RegistryValueKind]::Binary) } finally { $key.Dispose() }
}
function HSetStartup([string]$name, $v) {
    if (!(HNameOk $name) -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid start-up item state' }
    if ($name.StartsWith('task:')) {
        $parts = HTaskParts $name
        Load 'ScheduledTasks'
        if ([int]$v -eq 0) {
            if (@(HStartupEntriesOnce | Where-Object { $_.name -ceq $name }).Count -ne 1) { throw 'The scheduled task no longer needs a change' }
            HStateSet $name @{ was = 'enabled' }
            try { $null = Disable-ScheduledTask -TaskPath $parts.path -TaskName $parts.leaf -ErrorAction Stop }
            catch { HStateRemove $name; throw }
            return
        }
        if ($null -eq (HStateGet $name)) { throw 'Secblitz no longer has the saved state for this scheduled task' }
        if ((HStartupTaskState $name) -cne 'Disabled') { throw 'The scheduled task changed again; it was left alone' }
        $null = Enable-ScheduledTask -TaskPath $parts.path -TaskName $parts.leaf -ErrorAction Stop
        HStateRemove $name
        return
    }
    $kind = $name.Substring(0, $name.IndexOf(':'))
    $item = $name.Substring($kind.Length + 1)
    if ((HIsUserKind $kind) -and !(HInteractiveIsMe)) { throw 'The start-up entry belongs to another account; it was left alone' }
    $root = HStartupRoot $kind
    $original = HApprovedBytes $root $item
    if ($original -is [string]) { throw 'The start-up entry has an unusual on/off record; it was left alone' }
    if ([int]$v -eq 0) {
        if (@(HStartupEntriesOnce | Where-Object { $_.name -ceq $name }).Count -ne 1) { throw 'The start-up entry no longer needs a change' }
        [byte[]]$off = @(3, 0, 0, 0) + [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())
        HStateSet $name @{ o = $(if ($null -eq $original) { $null } else { [Convert]::ToBase64String($original) }); d = [Convert]::ToBase64String($off) }
        try { HSetApproved $root $item $off }
        catch { HStateRemove $name; throw }
        return
    }
    $st = HStateGet $name
    if ($null -eq $st) { throw 'Secblitz no longer has the saved state for this start-up entry' }
    if ($null -eq $original -or [Convert]::ToBase64String($original) -cne [string]$st.d) { throw 'The start-up entry changed again; it was left alone' }
    if ($null -eq $st.o) {
        $key = $root.hive.OpenSubKey($root.approved, $true)
        try { $key.DeleteValue($item, $false) } finally { $key.Dispose() }
    } else { HSetApproved $root $item ([Convert]::FromBase64String([string]$st.o)) }
    HStateRemove $name
}
function HStartupPreflight() {
    if (@(HStartupEntries).Count -gt $hStartupMax) { throw 'Not offered: too many items to switch off safely at once' }
}

# ---- browser.extensions_off (names are "chromium:<chrome|edge>:<extension id>")
# Secblitz adds the id to the browser's ExtensionInstallBlocklist at the next free number and keeps
# that number in its own state. Undo removes only that value. Other entries are never renumbered.
$script:hAddonInfo = @{}
$script:hAddonCache = $null
function HAddonParts([string]$name) {
    $m = [regex]::Match($name, '^chromium:(?<b>chrome|edge):(?<id>[a-p]{32})\z')
    if (!$m.Success) { return $null }
    return @{ browser = $m.Groups['b'].Value; id = $m.Groups['id'].Value }
}
function HAddonNameOk([string]$name) { return ($null -ne (HAddonParts $name)) }
function HAddonPolicyKey([string]$browser) {
    if ($browser -ceq 'chrome') { return 'SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist' }
    return 'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
}
function HAddonList([string]$browser) {
    $out = @{}
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((HAddonPolicyKey $browser), $false)
    if ($null -eq $key) { return $out }
    try {
        foreach ($n in @($key.GetValueNames())) {
            if ($key.GetValueKind($n) -eq [Microsoft.Win32.RegistryValueKind]::String) { $out[$n] = [string]$key.GetValue($n) }
            else { $out[$n] = $null }
        }
    } finally { $key.Dispose() }
    return $out
}
function HAddonPut([string]$browser, [string]$number, [string]$id) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey((HAddonPolicyKey $browser))
    try { $key.SetValue($number, $id, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
}
function HAddonDrop([string]$browser, [string]$number) {
    $subKey = HAddonPolicyKey $browser
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKey, $true)
    if ($null -eq $key) { return }
    try {
        $key.DeleteValue($number, $false)
        $empty = ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0)
    } finally { $key.Dispose() }
    if (!$empty) { return }
    $leafAt = $subKey.LastIndexOf('\')
    $parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKey.Substring(0, $leafAt), $true)
    if ($null -eq $parent) { return }
    try { $parent.DeleteSubKey($subKey.Substring($leafAt + 1), $false) } finally { $parent.Dispose() }
}
function HAddonNextNumber($list) {
    $max = [int64]0
    foreach ($n in @($list.Keys)) {
        if ($n -cmatch '^[0-9]{1,9}$' -and [int64]$n -gt $max) { $max = [int64]$n }
    }
    return ($max + 1)
}
function HAddonLocalData() { return [Environment]::GetFolderPath('LocalApplicationData') }
function HAddonPathPlain([string]$path) {
    # Profile folders belong to the person: a link anywhere on the way is never followed.
    $full = [IO.Path]::GetFullPath($path)
    if ($full -cnotmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { return $false }
    $part = [IO.Path]::GetPathRoot($full)
    foreach ($leaf in $full.Substring($part.Length).Split('\')) {
        if (!$leaf -or $leaf -eq '.' -or $leaf -eq '..' -or $leaf.EndsWith(' ') -or $leaf.EndsWith('.')) { return $false }
        $part = [IO.Path]::Combine($part, $leaf)
        try { $attr = [IO.File]::GetAttributes($part) } catch { return $false }
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    }
    return $true
}
function HAddonJson([string]$path) {
    try {
        if (!(HAddonPathPlain $path)) { return $null }
        $info = New-Object IO.FileInfo $path
        if (!$info.Exists -or $info.Length -gt 1048576) { return $null }
        $text = [Text.UTF8Encoding]::new($false, $false).GetString([IO.File]::ReadAllBytes($path)).TrimStart([char]0xFEFF)
        return (ConvertFrom-Json -InputObject $text)
    } catch { return $null }
}
function HAddonProp($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function HAddonTitle([string]$versionDir, $manifest, [string]$id) {
    $raw = HAddonProp $manifest 'name'
    if ($raw -isnot [string]) { $raw = '' }
    $m = [regex]::Match($raw, '^__MSG_(?<k>[A-Za-z0-9_@]{1,64})__\z')
    if ($m.Success) {
        $raw = ''
        $locales = @()
        $default = HAddonProp $manifest 'default_locale'
        if ($default -is [string] -and $default -cmatch '^[A-Za-z0-9_-]{1,20}$') { $locales += $default }
        foreach ($fallback in @('en', 'en_US')) { if ($locales -cnotcontains $fallback) { $locales += $fallback } }
        foreach ($locale in $locales) {
            $messages = HAddonJson ([IO.Path]::Combine($versionDir, '_locales', $locale, 'messages.json'))
            if ($null -eq $messages) { continue }
            $hit = @($messages.PSObject.Properties | Where-Object { $_.Name -ieq $m.Groups['k'].Value } | Select-Object -First 1)
            if ($hit.Count -eq 1) {
                $entry = $hit[0].Value
                $text = HAddonProp $entry 'message'
                if ($text -is [string] -and $text.Trim() -ne '') { $raw = $text; break }
            }
        }
    }
    $clean = HClean $raw
    if ($clean -eq '') { return $id }
    return $clean
}
function HAddonWhy($manifest) {
    $permissions = @()
    foreach ($field in @('permissions', 'host_permissions')) {
        # Read in place: a one-entry list returned from a function arrives unrolled to a string.
        $p = $manifest.PSObject.Properties[$field]
        if ($null -eq $p -or $null -eq $p.Value) { continue }
        $value = $p.Value
        if ($value -isnot [array]) { return @() }
        $permissions += $value
    }
    $why = @()
    if (($permissions -contains '<all_urls>') -or ($permissions -contains '*://*/*') -or ($permissions -contains 'https://*/*') -or ($permissions -contains 'http://*/*')) { $why += 'sites' }
    if ($permissions -contains 'nativeMessaging') { $why += 'programs' }
    return $why
}
function HAddonInventory() {
    if ($null -ne $script:hAddonCache) { return $script:hAddonCache }
    $found = @{}
    $local = HAddonLocalData
    foreach ($b in @(@{ browser = 'chrome'; root = @('Google', 'Chrome', 'User Data') }, @{ browser = 'edge'; root = @('Microsoft', 'Edge', 'User Data') })) {
        $root = [IO.Path]::Combine($local, $b.root[0], $b.root[1], $b.root[2])
        try {
            if (!(HAddonPathPlain $root)) { continue }
            $profiles = @([IO.Directory]::EnumerateDirectories($root) | Where-Object { [IO.Path]::GetFileName($_) -cmatch '^(Default|Profile [0-9]+)$' } | Select-Object -First 16)
            foreach ($profile in $profiles) {
                $extensions = [IO.Path]::Combine($profile, 'Extensions')
                if (!(HAddonPathPlain $extensions)) { continue }
                foreach ($dir in @([IO.Directory]::EnumerateDirectories($extensions) | Select-Object -First 256)) {
                    $id = [IO.Path]::GetFileName($dir)
                    $name = 'chromium:' + $b.browser + ':' + $id
                    if (!(HAddonNameOk $name) -or $found.ContainsKey($name) -or !(HAddonPathPlain $dir)) { continue }
                    $newest = @(@([IO.Directory]::EnumerateDirectories($dir) | Select-Object -First 8) | ForEach-Object { New-Object IO.DirectoryInfo $_ } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
                    if ($newest.Count -ne 1) { continue }
                    $manifest = HAddonJson ([IO.Path]::Combine($newest[0].FullName, 'manifest.json'))
                    if ($null -eq $manifest) { continue }
                    $why = @(HAddonWhy $manifest)
                    if ($why.Count -eq 0) { continue }
                    $found[$name] = @{ name = $name; browser = $b.browser; id = $id; title = (HAddonTitle $newest[0].FullName $manifest $id); why = $why }
                }
            }
        } catch { }
    }
    $script:hAddonCache = @($found.Values | Sort-Object { $_.title }, { $_.name })
    return $script:hAddonCache
}
function HReadExtensions() {
    $script:hAddonCache = $null
    $script:hAddonInfo = @{}
    $out = @{}
    $lists = @{ chrome = (HAddonList 'chrome'); edge = (HAddonList 'edge') }
    foreach ($name in @(HStateNames)) {
        $parts = HAddonParts $name
        if ($null -eq $parts) { continue }
        $st = HStateGet $name
        if ($null -eq $st) { continue }
        $list = $lists[$parts.browser]
        $number = [string]$st.v
        $out[$name] = $(if ($list.ContainsKey($number) -and $null -ne $list[$number] -and $list[$number] -ceq $parts.id) { 0 } else { 2 })
    }
    if (HInteractiveIsMe) {
        foreach ($a in @(HAddonInventory)) {
            if ($out.ContainsKey($a.name) -or @($lists[$a.browser].Values) -ccontains $a.id) { continue }
            $out[$a.name] = 1
            HLabel $a.name $a.title
            $script:hAddonInfo[$a.name] = $a.why
        }
    }
    return $out
}
function HSetExtension([string]$name, $v) {
    $parts = HAddonParts $name
    if ($null -eq $parts -or $null -eq $v -or ([int]$v -ne 0 -and [int]$v -ne 1)) { throw 'Invalid browser add-on state' }
    $list = HAddonList $parts.browser
    if ([int]$v -eq 0) {
        if (!(HInteractiveIsMe)) { throw 'The add-on belongs to another account; it was left alone' }
        $script:hAddonCache = $null
        if (@(HAddonInventory | Where-Object { $_.name -ceq $name }).Count -ne 1) { throw 'The add-on no longer needs a change' }
        if (@($list.Values) -ccontains $parts.id) { throw 'The add-on is already turned off; it was left alone' }
        if (@($list.Values | Where-Object { $null -eq $_ -or $_ -ceq '*' }).Count -gt 0) { throw 'The browser add-on rules changed; nothing was changed' }
        $number = [string](HAddonNextNumber $list)
        HStateSet $name @{ v = $number; id = $parts.id }
        try { HAddonPut $parts.browser $number $parts.id }
        catch { HStateRemove $name; throw }
        return
    }
    $st = HStateGet $name
    if ($null -eq $st) { throw 'Secblitz no longer has the saved state for this add-on' }
    $number = [string]$st.v
    if ($list.ContainsKey($number)) {
        if ($null -eq $list[$number] -or $list[$number] -cne $parts.id) { throw 'The add-on rule changed again; it was left alone' }
        HAddonDrop $parts.browser $number
    }
    HStateRemove $name
}
function HAddonPreflight() {
    foreach ($browser in @('chrome', 'edge')) {
        foreach ($text in @((HAddonList $browser).Values)) {
            if ($null -eq $text) { throw 'Not offered: the browser add-on rules on this computer could not be read' }
            if ($text -ceq '*') { throw 'Not offered: a browser rule already turns off every add-on' }
        }
    }
}
