# Non-mutating fixtures for the extended hardening controls (hardening.ps1): every registry, Defender,
# firewall, account and Wi-Fi touchpoint is an in-memory double. Runs on PowerShell 5.1 and 7.
# Optional: SECBLITZ_PARITY points at the file the Rust test `export_rule_parity_fixture_for_powershell` writes.
param(
    [string]$BackendPath = (Join-Path $PSScriptRoot 'backend.ps1'),
    [string]$HardeningPath = (Join-Path $PSScriptRoot 'hardening.ps1'),
    [string]$HandledPath = (Join-Path $PSScriptRoot 'hardening.handled.ps1')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
foreach ($path in @($BackendPath, $HandledPath, $HardeningPath)) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    foreach ($node in $ast.EndBlock.Statements) {
        if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
        elseif ($path -ne $BackendPath -and $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -cmatch '^h[A-Z]' -and
                $node.Right.Extent.Text -notmatch '\$(?!true|false|null)') { . ([scriptblock]::Create($node.Extent.Text)) }
    }
}
$script:checks = 0
# backend.tests.ps1 runs this file as a child script, so its doubles for these
# cmdlets are visible here; start from the real ones so this suite is hermetic.
function Get-ChildItem { Microsoft.PowerShell.Management\Get-ChildItem @args }
function Test-Path { Microsoft.PowerShell.Management\Test-Path @args }
function Get-Item { Microsoft.PowerShell.Management\Get-Item @args }
function Get-ItemProperty { Microsoft.PowerShell.Management\Get-ItemProperty @args }
# The script Rust actually runs is the backend definitions plus hardening.ps1:
# it must parse as one unit and must not redefine (shadow) any backend function.
$backendText = [IO.File]::ReadAllText($BackendPath)
$delimiter = "`ntry {`n    switch -CaseSensitive (`$action) {"
$cut = $backendText.IndexOf($delimiter)
if ($cut -lt 0) { throw 'Backend dispatcher boundary changed' }
$combined = $backendText.Substring(0, $cut) + "`n" + [IO.File]::ReadAllText($HandledPath) + "`n" + [IO.File]::ReadAllText($HardeningPath)
$tokens = $null; $errors = $null
$combinedAst = [Management.Automation.Language.Parser]::ParseInput($combined, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$names = @($combinedAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name.ToLowerInvariant() })
if (@($names | Group-Object | Where-Object { $_.Count -gt 1 }).Count -gt 0) { throw 'Duplicate function definition across backend.ps1, hardening.handled.ps1 and hardening.ps1' }
$realHRead = ${function:HRead}
$realHSet = ${function:HSet}
$realHPreflight = ${function:HPreflight}
function Assert($ok, [string]$message) { if (!$ok) { throw $message }; $script:checks++ }
function Reject([scriptblock]$operation, [string]$message) {
    $caught = $null
    try { & $operation } catch { $caught = $_.Exception.Message }
    Assert ($null -ne $caught -and $caught -like "*$message*") "Expected '$message', received '$caught'"
}
function Load($name) {}
function Start-Sleep($Milliseconds) {}
$hMaps = @('Disabled','Basic','Advanced')
$hPua = @('Disabled','Enabled','AuditMode')
function MakeSpec([string]$json) { $script:spec = ConvertFrom-Json -InputObject $json }

if ($env:SECBLITZ_PARITY -and (Test-Path -LiteralPath $env:SECBLITZ_PARITY)) {
    $entries = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($env:SECBLITZ_PARITY))
    Assert (@($entries).Count -ge 20) 'Parity fixture is incomplete'
    foreach ($entry in @($entries)) {
        $script:spec = $entry.spec
        foreach ($case in @($entry.cases)) {
            $def = HDef $case.key
            Assert ((HIsSafe $def $case.value) -eq [bool]$case.safe) "Parity: safe($($entry.id) $($case.key)=$($case.value))"
            $fix = HFixOf $def $case.value
            Assert (HEq $fix $case.fix) "Parity: fix($($entry.id) $($case.key)=$($case.value)) got '$fix' expected '$($case.fix)'"
        }
    }
}

$pplJson = '{"id":"lsa.run_as_ppl","source":"Registry","dynamic":false,"reboot":true,"keys":[{"name":"RunAsPPL","path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","rule":"set","safe":[1,2],"absentSafe":false,"fix":2,"max":2}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$pnpJson = '{"id":"printer.point_and_print","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"RestrictDriverInstallationToAdministrators","path":"HKLM:\\P","rule":"set","safe":[1],"absentSafe":true,"fix":null,"max":1},{"name":"NoWarningNoElevationOnInstall","path":"HKLM:\\P","rule":"set","safe":[0],"absentSafe":true,"fix":null,"max":1},{"name":"UpdatePromptSettings","path":"HKLM:\\P","rule":"set","safe":[0,1],"absentSafe":true,"fix":null,"max":2}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$fwJson = '{"id":"net.public_sharing_exposure","source":"FirewallExposure","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"exposure","safe":[],"absentSafe":false,"fix":null,"max":15}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$wifiJson = '{"id":"wifi.risky_profiles","source":"WifiProfiles","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$asrJson = '{"id":"defender.asr.standard","source":"DefenderAsr","dynamic":false,"reboot":false,"keys":[{"name":"56a863a9-875e-4185-98a7-b882c64b5ce5","path":"","rule":"set","safe":[1,6],"absentSafe":false,"fix":1,"max":6},{"name":"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","path":"","rule":"set","safe":[1,6],"absentSafe":false,"fix":1,"max":6}],"gate":{"areas":[],"pattern":".","tamperExempt":true,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'

MakeSpec $pplJson
$def = HDef 'RunAsPPL'
Assert (!(HIsSafe $def $null) -and !(HIsSafe $def 0) -and (HIsSafe $def 1) -and (HIsSafe $def 2)) 'PPL safety'
Assert ((HFixOf $def $null) -eq 2 -and (HFixOf $def 0) -eq 2 -and (HFixOf $def 1) -eq 1) 'PPL fix keeps the firmware lock'
Reject { HDef 'Other' } 'Unknown hardening item'
MakeSpec $pnpJson
Assert (HIsSafe (HDef 'UpdatePromptSettings') $null) 'Absent policy value is the safe default'
Assert ($null -eq (HFixOf (HDef 'UpdatePromptSettings') 2)) 'Unsafe policy value is removed'
Assert ((HFixOf (HDef 'UpdatePromptSettings') 1) -eq 1) 'Safe value kept'
MakeSpec $fwJson
$exp = HDef 'FPS-X'
Assert ((HFixOf $exp 15) -eq 11 -and (HFixOf $exp 12) -eq 4 -and (HFixOf $exp 7) -eq 7 -and (HFixOf $exp 3) -eq 3) 'Exposure fixes'
foreach ($ok in @('FPS-SMB-In-TCP','NETDIS-LLMNR-In-UDP')) { Assert (HNameOk $ok) "name $ok" }
foreach ($bad in @('RemoteDesktop-In','FPS-','fps-x',"FPS-x'; calc",'FPS-a b','')) { Assert (!(HNameOk $bad)) "name $bad accepted" }
MakeSpec $wifiJson
foreach ($ok in @('Cafe Guest',"John's Home",'Kaffee Straße')) { Assert (HNameOk $ok) "wifi $ok" }
foreach ($bad in @('','a"b'," padded","tab`there",('x' * 65))) { Assert (!(HNameOk $bad)) "wifi name accepted: $bad" }

MakeSpec $pplJson
function Parse($json) { HParseInput (ConvertFrom-Json -InputObject $json) }
Assert ((Parse '{"items":{"RunAsPPL":2}}')['RunAsPPL'] -eq 2) 'parse'
Assert ($null -eq (Parse '{"items":{"RunAsPPL":null}}')['RunAsPPL']) 'parse null'
foreach ($bad in @('{"items":{"RunAsPPL":3}}','{"items":{"RunAsPPL":-1}}','{"items":{"RunAsPPL":"1"}}','{"items":{"RunAsPPL":1.5}}','{"items":{"X":1}}','{"items":{}}','{"items":{"RunAsPPL":1},"extra":1}','{"present":true,"value":1}')) {
    $caught = $false; try { $null = Parse $bad } catch { $caught = $true }
    Assert $caught "accepted $bad"
}

function HRead { return $script:state.Clone() }
function HGate { $script:gates++; if ($script:blocked) { throw 'management gate' } }
function HPreflight { $script:preflights++; if ($script:preflightFails) { throw 'Not offered: fixture' } }
function HSet([string]$name, $v) {
    $script:sets += ,@($name, $v)
    if ($script:failOn -ceq $name) { throw 'fixture write failure' }
    if (!$script:ignoreWrites) { $script:state[$name] = $v }
}
function Reset([string]$json, $state) {
    MakeSpec $json
    $script:state = $state; $script:sets = @(); $script:blocked = $false; $script:gates = 0
    $script:preflights = 0; $script:preflightFails = $false; $script:failOn = ''; $script:ignoreWrites = $false
}
function Input($json) { ConvertFrom-Json -InputObject $json }

Reset $pplJson @{ RunAsPPL = $null }
HWrite (Input '{"items":{"RunAsPPL":2}}')
Assert ($script:sets.Count -eq 1 -and $script:state['RunAsPPL'] -eq 2 -and $script:preflights -eq 1 -and $script:gates -ge 1) 'repair'
# Undo is gated but never preflighted (a failing preflight must not trap the person).
$script:preflightFails = $true
HWrite (Input '{"items":{"RunAsPPL":null}}')
Assert ($null -eq $script:state['RunAsPPL'] -and $script:preflights -eq 1) 'undo skips preflight'
Reset $pplJson @{ RunAsPPL = $null }; $script:preflightFails = $true
Reject { HWrite (Input '{"items":{"RunAsPPL":2}}') } 'Not offered'
Assert ($script:sets.Count -eq 0) 'preflight failure wrote'
Reset $pplJson @{ RunAsPPL = $null }; $script:blocked = $true
Reject { HWrite (Input '{"items":{"RunAsPPL":2}}') } 'management gate'
Assert ($script:sets.Count -eq 0) 'gate bypassed'
# Drift: any state that is neither the recorded original nor its fix stops the write.
foreach ($drift in @(0, 1)) {
    Reset $pplJson @{ RunAsPPL = $drift }
    Reject { HWrite (Input '{"items":{"RunAsPPL":null}}') } 'changed before the write'
    Assert ($script:sets.Count -eq 0) "undo overwrote drift $drift"
}
Reset $pplJson @{ RunAsPPL = 1 }
Reject { HWrite (Input '{"items":{"RunAsPPL":2}}') } 'changed before the write'
Assert ($script:sets.Count -eq 0) 'repair overwrote the firmware lock'
Reset $pplJson @{ RunAsPPL = $null }; $script:ignoreWrites = $true
Reject { HWrite (Input '{"items":{"RunAsPPL":2}}') } 'Readback did not match'

# Partial progress is rolled back so the journal still matches the machine.
Reset $pnpJson @{ RestrictDriverInstallationToAdministrators = 0; NoWarningNoElevationOnInstall = 1; UpdatePromptSettings = 2 }
$script:failOn = 'UpdatePromptSettings'
Reject { HWrite (Input '{"items":{"RestrictDriverInstallationToAdministrators":null,"NoWarningNoElevationOnInstall":null,"UpdatePromptSettings":null}}') } 'fixture write failure'
$script:failOn = ''
Assert ($script:state['RestrictDriverInstallationToAdministrators'] -eq 0 -and $script:state['NoWarningNoElevationOnInstall'] -eq 1 -and $script:state['UpdatePromptSettings'] -eq 2) 'rollback restored the originals'
Reset $pnpJson @{ RestrictDriverInstallationToAdministrators = 1; NoWarningNoElevationOnInstall = 1; UpdatePromptSettings = 1 }
HWrite (Input '{"items":{"RestrictDriverInstallationToAdministrators":1,"NoWarningNoElevationOnInstall":null,"UpdatePromptSettings":1}}')
Assert ($script:sets.Count -eq 1 -and $script:sets[0][0] -ceq 'NoWarningNoElevationOnInstall') 'only unsafe keys move'

$gateTail = '"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}'
$gateExempt = $gateTail.Replace('"tamperExempt":false', '"tamperExempt":true')
$textJson = '{"id":"browser.dns_bypass","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"EdgeMode","path":"HKLM:\\E","valueName":"DnsOverHttpsMode","rule":"text","safe":["off"],"absentSafe":false,"fix":"off","max":256},{"name":"Optional","path":"HKLM:\\E","rule":"text","safe":["a"],"absentSafe":true,"fix":null,"max":256},{"name":"Locked","path":"HKLM:\\F","valueName":"Locked","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $gateTail + '}'
MakeSpec $textJson
$tm = HDef 'EdgeMode'
Assert ((HIsSafe $tm 'off') -and !(HIsSafe $tm 'OFF') -and !(HIsSafe $tm 'automatic') -and !(HIsSafe $tm '') -and !(HIsSafe $tm $null)) 'a text is safe only when it matches exactly'
Assert (!(HIsSafe $tm 0) -and !(HIsSafe $tm 1)) 'a number is never a safe text'
Assert (!(HIsSafe (HDef 'Locked') 'on')) 'a text is never a safe number'
Assert ((HFixOf $tm 'automatic') -ceq 'off' -and (HFixOf $tm $null) -ceq 'off' -and (HFixOf $tm 'off') -ceq 'off' -and (HFixOf $tm 'OFF') -ceq 'off') 'text repair'
Assert ((HIsSafe (HDef 'Optional') $null) -and $null -eq (HFixOf (HDef 'Optional') 'zzz') -and (HFixOf (HDef 'Optional') 'a') -ceq 'a') 'an unsafe optional text is removed'
Assert ((HEq 'off' 'off') -and !(HEq 'off' 'OFF') -and !(HEq 'off' $null) -and !(HEq 'off' 1) -and !(HEq 1 'off') -and (HEq $null $null)) 'HEq compares texts exactly'
function ParseText($json) { HParseInput (ConvertFrom-Json -InputObject $json) }
Assert ((ParseText '{"items":{"EdgeMode":"off","Optional":null,"Locked":1}}')['EdgeMode'] -ceq 'off') 'text parse'
Assert ($null -eq (ParseText '{"items":{"EdgeMode":null,"Optional":"a","Locked":1}}')['EdgeMode']) 'text parse null'
Assert ((ParseText '{"items":{"EdgeMode":"https://dns.example/dns-query{?dns}","Optional":null,"Locked":1}}')['EdgeMode'] -ceq 'https://dns.example/dns-query{?dns}') 'any plain text is accepted'
foreach ($bad in @(
    '{"items":{"EdgeMode":0,"Optional":null,"Locked":1}}',
    '{"items":{"EdgeMode":true,"Optional":null,"Locked":1}}',
    '{"items":{"EdgeMode":["off"],"Optional":null,"Locked":1}}',
    '{"items":{"EdgeMode":"off","Optional":null,"Locked":"1"}}',
    '{"items":{"EdgeMode":"o\nff","Optional":null,"Locked":1}}',
    '{"items":{"EdgeMode":"o\u0000ff","Optional":null,"Locked":1}}',
    '{"items":{"EdgeMode":"o\u007fff","Optional":null,"Locked":1}}',
    ('{"items":{"EdgeMode":"' + ('x' * 257) + '","Optional":null,"Locked":1}}')
)) {
    $caught = $false; try { $null = ParseText $bad } catch { $caught = $true }
    Assert $caught "accepted $bad"
}
Reset $textJson @{ EdgeMode = 'automatic'; Optional = 'zzz'; Locked = 0 }
HWrite (Input '{"items":{"EdgeMode":"off","Optional":null,"Locked":1}}')
Assert ($script:sets.Count -eq 3 -and $script:state['EdgeMode'] -ceq 'off' -and $null -eq $script:state['Optional'] -and $script:state['Locked'] -eq 1 -and $script:preflights -eq 1) 'text repair writes the fixed texts'
$script:preflightFails = $true
HWrite (Input '{"items":{"EdgeMode":"automatic","Optional":"zzz","Locked":0}}')
Assert ($script:state['EdgeMode'] -ceq 'automatic' -and $script:state['Optional'] -ceq 'zzz' -and $script:state['Locked'] -eq 0 -and $script:preflights -eq 1) 'text undo puts the exact original back without a preflight'
Reset $textJson @{ EdgeMode = 'OFF'; Optional = $null; Locked = 1 }
HWrite (Input '{"items":{"EdgeMode":"off","Optional":null,"Locked":1}}')
Assert ($script:sets.Count -eq 1 -and $script:state['EdgeMode'] -ceq 'off') 'a text that differs only by case is repaired'
Reset $textJson @{ EdgeMode = 'secure'; Optional = $null; Locked = 1 }
Reject { HWrite (Input '{"items":{"EdgeMode":"automatic","Optional":null,"Locked":1}}') } 'changed before the write'
Assert ($script:sets.Count -eq 0) 'undo overwrote a text changed after the fix'
Reset $textJson @{ EdgeMode = 'automatic'; Optional = $null; Locked = 1 }; $script:ignoreWrites = $true
Reject { HWrite (Input '{"items":{"EdgeMode":"off","Optional":null,"Locked":1}}') } 'Readback did not match'
Reset $textJson @{ EdgeMode = 'automatic'; Optional = $null; Locked = 1 }
Reject { HWrite (Input '{"items":{"EdgeMode":0,"Optional":null,"Locked":1}}') } 'Invalid hardening value'
Assert ($script:sets.Count -eq 0) 'a number was written to a text setting'
$script:hLabels = @{ EdgeMode = 'x' }; $script:hLeft = @()
Assert (@(HLabelList @{ EdgeMode = 'automatic'; Locked = 1 }).Count -eq 0) 'text items are never listed as handled items'
$script:hLabels = @{}

# Dynamic items must still exist; new ones are left alone.
Reset $fwJson @{ 'FPS-A' = 15; 'FPS-B' = 12; 'NETDIS-New' = 15 }
HWrite (Input '{"items":{"FPS-A":11,"FPS-B":4}}')
Assert ($script:state['FPS-A'] -eq 11 -and $script:state['FPS-B'] -eq 4 -and $script:state['NETDIS-New'] -eq 15) 'dynamic repair'
HWrite (Input '{"items":{"FPS-A":15,"FPS-B":12}}')
Assert ($script:state['FPS-A'] -eq 15 -and $script:state['FPS-B'] -eq 12) 'dynamic undo'
Reset $fwJson @{ 'FPS-A' = 15 }
Reject { HWrite (Input '{"items":{"FPS-GONE":11}}') } 'no longer exists'
Reject { HWrite (Input '{"items":{"RemoteDesktop-In":11}}') } 'Unknown hardening item'
Reset $wifiJson @{ 'Cafe' = 1; 'Home' = 0 }
HWrite (Input '{"items":{"Cafe":0}}')
Assert ($script:state['Cafe'] -eq 0 -and $script:state['Home'] -eq 0 -and $script:sets.Count -eq 1) 'wifi repair'
HWrite (Input '{"items":{"Cafe":1}}')
Assert ($script:state['Cafe'] -eq 1) 'wifi undo'

$tlsJson = '{"id":"tls.legacy_protocols","source":"Registry","dynamic":false,"reboot":true,"keys":[{"name":"ssl3.client.enabled","path":"HKLM:\\T","valueName":"Enabled","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":4294967295},{"name":"ssl3.client.default_off","path":"HKLM:\\T","valueName":"DisabledByDefault","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $gateTail + '}'
$stackJson = '{"id":"net.stack_hardening","source":"Registry","dynamic":false,"reboot":true,"keys":[{"name":"DisableIPSourceRouting","path":"HKLM:\\T4","valueName":"DisableIPSourceRouting","rule":"set","safe":[2],"absentSafe":false,"fix":2,"max":2},{"name":"DisableIPSourceRouting6","path":"HKLM:\\T6","valueName":"DisableIPSourceRouting","rule":"set","safe":[2],"absentSafe":false,"fix":2,"max":2}],' + $gateTail + '}'
$nbJson = '{"id":"net.netbios","source":"NetbiosAdapters","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","valueName":"*","rule":"set","safe":[2],"absentSafe":false,"fix":2,"max":2}],' + $gateTail + '}'
$obJson = '{"id":"firewall.outbound_smb_internet","source":"FirewallOutbound","dynamic":false,"reboot":false,"keys":[{"name":"RulePresent","path":"","valueName":"RulePresent","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $gateTail + '}'
$npJson = '{"id":"defender.network_protection","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"EnableNetworkProtection","path":"","valueName":"EnableNetworkProtection","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":2}],' + $gateExempt + '}'
$cblJson = '{"id":"defender.cloud_block_level","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"CloudBlockLevel","path":"","valueName":"CloudBlockLevel","rule":"set","safe":[2,4,6],"absentSafe":false,"fix":2,"max":6},{"name":"CloudExtendedTimeout","path":"","valueName":"CloudExtendedTimeout","rule":"set","safe":[20,25,50],"absentSafe":false,"fix":20,"max":50}],' + $gateExempt + '}'
$officeJson = '{"id":"defender.asr.office","source":"DefenderAsr","dynamic":false,"reboot":false,"keys":[{"name":"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84","path":"","valueName":"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":6}],' + $gateExempt + '}'

# DWORD 0xFFFFFFFF ("enabled" in many guides) is a legal original and is restored exactly.
MakeSpec $tlsJson
Assert (!(HIsSafe (HDef 'ssl3.client.enabled') 4294967295) -and !(HIsSafe (HDef 'ssl3.client.enabled') $null) -and (HIsSafe (HDef 'ssl3.client.enabled') 0)) 'tls enabled safety'
Assert ((HFixOf (HDef 'ssl3.client.enabled') 4294967295) -eq 0 -and (HFixOf (HDef 'ssl3.client.default_off') $null) -eq 1) 'tls fixes'
Assert ((Parse '{"items":{"ssl3.client.enabled":4294967295,"ssl3.client.default_off":1}}')['ssl3.client.enabled'] -eq 4294967295) 'parse 0xFFFFFFFF'
Reject { $null = Parse '{"items":{"ssl3.client.enabled":4294967296,"ssl3.client.default_off":1}}' } 'out of range'
Reset $tlsJson @{ 'ssl3.client.enabled' = 4294967295; 'ssl3.client.default_off' = $null }
HWrite (Input '{"items":{"ssl3.client.enabled":0,"ssl3.client.default_off":1}}')
Assert ($script:sets.Count -eq 2 -and $script:state['ssl3.client.enabled'] -eq 0 -and $script:state['ssl3.client.default_off'] -eq 1 -and $script:preflights -eq 1) 'tls repair'
HWrite (Input '{"items":{"ssl3.client.enabled":4294967295,"ssl3.client.default_off":null}}')
Assert ($script:state['ssl3.client.enabled'] -eq 4294967295 -and $null -eq $script:state['ssl3.client.default_off'] -and $script:preflights -eq 1) 'tls undo restores the exact original'
Reset $tlsJson @{ 'ssl3.client.enabled' = 1; 'ssl3.client.default_off' = 1 }
Reject { HWrite (Input '{"items":{"ssl3.client.enabled":4294967295,"ssl3.client.default_off":1}}') } 'changed before the write'
Assert ($script:sets.Count -eq 0) 'tls drift'

# NetBIOS is restored adapter by adapter; adapters that appear later are left alone.
Reset $nbJson @{ '{11111111-1111-1111-1111-111111111111}' = 0; '{22222222-2222-2222-2222-222222222222}' = 1; '{33333333-3333-3333-3333-333333333333}' = 2 }
HWrite (Input '{"items":{"{11111111-1111-1111-1111-111111111111}":2,"{22222222-2222-2222-2222-222222222222}":2,"{33333333-3333-3333-3333-333333333333}":2}}')
Assert ($script:sets.Count -eq 2 -and $script:preflights -eq 1) 'netbios repair only moves unsafe adapters'
HWrite (Input '{"items":{"{11111111-1111-1111-1111-111111111111}":0,"{22222222-2222-2222-2222-222222222222}":1,"{33333333-3333-3333-3333-333333333333}":2}}')
Assert ($script:state['{11111111-1111-1111-1111-111111111111}'] -eq 0 -and $script:state['{22222222-2222-2222-2222-222222222222}'] -eq 1 -and $script:state['{33333333-3333-3333-3333-333333333333}'] -eq 2) 'netbios undo per adapter'
Reject { HWrite (Input '{"items":{"{99999999-9999-9999-9999-999999999999}":2}}') } 'no longer exists'
Reject { HWrite (Input '{"items":{"Ethernet":2}}') } 'Unknown hardening item'

# The firewall rule is present (1) or absent (0); undo removes it.
Reset $obJson @{ RulePresent = 0 }
HWrite (Input '{"items":{"RulePresent":1}}')
Assert ($script:state['RulePresent'] -eq 1 -and $script:preflights -eq 1) 'outbound rule added'
HWrite (Input '{"items":{"RulePresent":0}}')
Assert ($script:state['RulePresent'] -eq 0) 'outbound rule removed on undo'

# Defender failures mention tamper protection.
Reset $npJson @{ EnableNetworkProtection = 0 }; $script:ignoreWrites = $true
Reject { HWrite (Input '{"items":{"EnableNetworkProtection":1}}') } 'tamper protection'

Reset $pplJson @{ RunAsPPL = $null }
$o = HObserve
Assert ($o.eligible -and $o.value.items['RunAsPPL'] -eq $null -and $script:preflights -eq 1) 'observe unsafe'
Reset $pplJson @{ RunAsPPL = 2 }; $script:preflightFails = $true
$o = HObserve
Assert ($o.eligible -and $script:preflights -eq 0) 'safe state is never gated by preflight'
Reset $pplJson @{ RunAsPPL = $null }; $script:preflightFails = $true
$o = HObserve
Assert (!$o.eligible -and $o.reason -ceq 'Not offered: fixture') 'preflight reason surfaces'
Reset $pplJson @{ RunAsPPL = $null }; $script:blocked = $true
$o = HObserve
Assert (!$o.eligible -and $o.reason -ceq 'management gate' -and $o.value.items['RunAsPPL'] -eq $null) 'managed device is observed but not eligible'
Assert ((ConvertTo-Json -InputObject $o -Depth 8 -Compress) -like '*"RunAsPPL":null*') 'absent serializes as null'

${function:HRead} = $realHRead
function Get-MpPreference { return $script:mp }
MakeSpec '{"id":"defender.cloud_protection","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"MAPSReporting","path":"","rule":"set","safe":[1,2],"absentSafe":false,"fix":2,"max":2},{"name":"DisableBlockAtFirstSeen","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$script:mp = [pscustomobject]@{ MAPSReporting = 'Advanced'; DisableBlockAtFirstSeen = $false }
$r = HRead
Assert ($r['MAPSReporting'] -eq 2 -and $r['DisableBlockAtFirstSeen'] -eq 0) 'defender enum names'
$script:mp = [pscustomobject]@{ MAPSReporting = [byte]0; DisableBlockAtFirstSeen = $true }
$r = HRead
Assert ($r['MAPSReporting'] -eq 0 -and $r['DisableBlockAtFirstSeen'] -eq 1) 'defender numeric'
$script:mp = [pscustomobject]@{ MAPSReporting = $null; DisableBlockAtFirstSeen = $false }
Reject { HRead } 'not readable'
MakeSpec '{"id":"defender.script_nis","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"DisableScriptScanning","path":"","rule":"set","safe":[0],"absentSafe":true,"fix":0,"max":1},{"name":"DisableIntrusionPreventionSystem","path":"","rule":"set","safe":[0],"absentSafe":true,"fix":0,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":true,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
$script:mp = [pscustomobject]@{ DisableScriptScanning = $false; DisableIntrusionPreventionSystem = $null }
$r = HRead
Assert ($r['DisableIntrusionPreventionSystem'] -eq 0 -and !(HAnyUnsafe $r)) 'unset prevention preference means on'
$script:mp = [pscustomobject]@{ DisableScriptScanning = $false }
$r = HRead
Assert ($r['DisableIntrusionPreventionSystem'] -eq 0 -and !(HAnyUnsafe $r)) 'retired prevention preference (missing property) means on'
$script:mp = [pscustomobject]@{ DisableScriptScanning = 'yes'; DisableIntrusionPreventionSystem = $false }
Reject { HRead } 'readable boolean'

MakeSpec $asrJson
$script:mp = [pscustomobject]@{
    AttackSurfaceReductionRules_Ids = @('56A863A9-875E-4185-98A7-B882C64B5CE5', 'aaaaaaaa-0000-0000-0000-000000000000')
    AttackSurfaceReductionRules_Actions = @([byte]2, [byte]1)
}
$r = HRead
Assert ($r['56a863a9-875e-4185-98a7-b882c64b5ce5'] -eq 2 -and $null -eq $r['9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'] -and $r.Count -eq 2) 'asr read (case-insensitive, other rules ignored)'
Assert (HAnyUnsafe $r) 'audit mode and unconfigured rules are not protection'
$script:mp = [pscustomobject]@{ AttackSurfaceReductionRules_Ids = $null; AttackSurfaceReductionRules_Actions = $null }
Assert ($null -eq (HRead)['56a863a9-875e-4185-98a7-b882c64b5ce5']) 'empty asr lists'
$script:mp = [pscustomobject]@{ AttackSurfaceReductionRules_Ids = @('a', 'b'); AttackSurfaceReductionRules_Actions = @([byte]1) }
Reject { HRead } 'inconsistent'

$script:calls = @()
function Add-MpPreference { param($AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions); $script:calls += ,@('add', $AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions) }
function Remove-MpPreference { param($AttackSurfaceReductionRules_Ids); $script:calls += ,@('remove', $AttackSurfaceReductionRules_Ids) }
function Set-MpPreference { param($MAPSReporting, $PUAProtection, $DisableBlockAtFirstSeen, $DisableScriptScanning, $DisableIntrusionPreventionSystem); $script:calls += ,@('set', $MAPSReporting, $PUAProtection, $DisableBlockAtFirstSeen, $DisableScriptScanning, $DisableIntrusionPreventionSystem) }
$asrDef = HDef '56a863a9-875e-4185-98a7-b882c64b5ce5'
HSetAsr $asrDef 1; HSetAsr $asrDef 6; HSetAsr $asrDef 2; HSetAsr $asrDef 0; HSetAsr $asrDef $null
Assert (($script:calls | ForEach-Object { $_[0] + ':' + $_[2] }) -join ',' -ceq 'add:Enabled,add:Warn,add:AuditMode,add:Disabled,remove:') 'asr setter arguments'
Reject { HSetAsr $asrDef 3 } 'Invalid attack surface rule action'
$script:calls = @()
MakeSpec '{"id":"defender.cloud_protection","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"MAPSReporting","path":"","rule":"set","safe":[1,2],"absentSafe":false,"fix":2,"max":2},{"name":"DisableBlockAtFirstSeen","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}}'
HSetDefenderPref (HDef 'MAPSReporting') 2; HSetDefenderPref (HDef 'DisableBlockAtFirstSeen') 0; HSetDefenderPref (HDef 'MAPSReporting') 0
Assert ($script:calls[0][1] -ceq 'Advanced' -and $script:calls[1][3] -eq $false -and $script:calls[2][1] -ceq 'Disabled') 'defender setter arguments'

MakeSpec $fwJson
function Get-NetFirewallRule {
    param($PolicyStore, $Name, $ErrorAction)
    $all = @(
        [pscustomobject]@{ Name = 'FPS-SMB-In-TCP'; Direction = 'Inbound'; Action = 'Allow'; Profile = 7; Enabled = 'True' }
        [pscustomobject]@{ Name = 'FPS-Any'; Direction = 'Inbound'; Action = 'Allow'; Profile = 0; Enabled = 'True' }
        [pscustomobject]@{ Name = 'FPS-PublicOnly'; Direction = 'Inbound'; Action = 'Allow'; Profile = 4; Enabled = 'False' }
        [pscustomobject]@{ Name = 'FPS-Out'; Direction = 'Outbound'; Action = 'Allow'; Profile = 7; Enabled = 'True' }
        [pscustomobject]@{ Name = 'FPS-Block'; Direction = 'Inbound'; Action = 'Block'; Profile = 7; Enabled = 'True' }
        [pscustomobject]@{ Name = 'NETDIS-LLMNR-In-UDP'; Direction = 'Inbound'; Action = 'Allow'; Profile = 3; Enabled = 'True' }
        [pscustomobject]@{ Name = 'FPS-Odd Name'; Direction = 'Inbound'; Action = 'Allow'; Profile = 7; Enabled = 'True' }
    )
    $hits = @($all | Where-Object { $_.Name -like $Name })
    if ($hits.Count -eq 0) {
        $e = [Management.Automation.ErrorRecord]::new([Exception]::new('none'), 'none', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name)
        throw $e
    }
    return $hits
}
$r = HReadFirewall
Assert ($r.Count -eq 4 -and $r['FPS-SMB-In-TCP'] -eq 15 -and $r['FPS-Any'] -eq 15 -and $r['FPS-PublicOnly'] -eq 4 -and $r['NETDIS-LLMNR-In-UDP'] -eq 11) 'firewall slice'
$script:calls = @()
function Set-NetFirewallRule { param($PolicyStore, $Name, $Profile, $Enabled, $ErrorAction); $script:calls += ,@($Name, ($Profile -join '+'), $Enabled) }
HSetFirewall 'FPS-A' 11; HSetFirewall 'FPS-B' 4; HSetFirewall 'FPS-C' 15; HSetFirewall 'FPS-D' 12
Assert (($script:calls | ForEach-Object { $_ -join '/' }) -join ',' -ceq 'FPS-A/Domain+Private/True,FPS-B/Public/False,FPS-C/Any/True,FPS-D/Public/True') 'firewall setter arguments'

$script:fakeFs = $false; $script:fakePaths = @(); $script:fakeKey = $null
function Test-Path { param($LiteralPath, $ErrorAction); if ($script:fakeFs) { return ($script:fakePaths -contains $LiteralPath) }; return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath) }
function Get-Item { param($LiteralPath, $ErrorAction); if ($script:fakeFs) { return $script:fakeKey }; return (Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath) }
function FakeKey($names, [int]$subkeys = 0) {
    $k = [pscustomobject]@{ SubKeyCount = $subkeys; Names = @($names) }
    $k | Add-Member ScriptMethod GetValueNames { return @($this.Names) }
    return $k
}
$own = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$gateJson = '{"id":"printer.point_and_print","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"UpdatePromptSettings","path":"' + $own.Replace('\', '\\') + '","rule":"set","safe":[0,1],"absentSafe":true,"fix":null,"max":2}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":true,"ownPolicyKey":"' + $own.Replace('\', '\\') + '","policyValues":[{"path":"HKLM:\\SOFTWARE\\Policies\\Other","name":"Managed"}]}}'
MakeSpec $gateJson
$script:fakeFs = $true
$script:fakePaths = @($own); $script:fakeKey = FakeKey @('UpdatePromptSettings')
HGatePolicy
Assert $true 'only our own value in the policy key is acceptable'
$script:fakeKey = FakeKey @('UpdatePromptSettings', 'TrustedServers')
Reject { HGatePolicy } 'Relevant policy is configured'
$script:fakeKey = FakeKey @('UpdatePromptSettings') 1
Reject { HGatePolicy } 'Relevant policy is configured'
$script:fakePaths = @($own, 'HKLM:\SOFTWARE\Policies\Other'); $script:fakeKey = FakeKey @('Managed')
Reject { HGatePolicy } 'Relevant policy is configured'
$script:fakeKey = FakeKey @('UpdatePromptSettings')
$script:fakePaths = @($own, [IO.Path]::Combine($env:SystemRoot, 'System32\GroupPolicy\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'))
Reject { HGatePolicy } 'Local computer policy artifacts'
$script:fakePaths = @($own, [IO.Path]::Combine($env:SystemRoot, 'System32\GroupPolicy\Machine\Registry.pol'))
Reject { HGatePolicy } 'Local computer policy artifacts'
$script:fakePaths = @(); $script:fakeFs = $false
function Get-CimInstance { param($ClassName, $Namespace); switch ($ClassName) { 'RSOP_GPO' { return $script:gpos } 'RSOP_RegistryPolicySetting' { return $script:rsopSettings } default { throw "Unexpected probe $ClassName" } } }
$script:gpos = @(@{ id = 'LocalGPO'; enabled = $true; accessDenied = $false; filterAllowed = $true })
$script:rsopSettings = @(@{ registryKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; valueName = 'Other' })
HRsop
$script:rsopSettings = @(@{ registryKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; valueName = 'UpdatePromptSettings' })
Reject { HRsop } 'Relevant resultant Group Policy'
$script:rsopSettings = @()
$script:gpos = @(@{ id = '{31B2F340-016D-11D2-945F-00C04FB984F9}'; enabled = $true; accessDenied = $false; filterAllowed = $true })
Reject { HRsop } 'Applied computer Group Policy'
$script:gpos = @(@{ id = 'x'; enabled = 'yes'; accessDenied = $false; filterAllowed = $true })
Reject { HRsop } 'authority is unknown'

$root = Join-Path ([IO.Path]::GetTempPath()) ('secblitz-wlan-' + [Guid]::NewGuid().ToString('N'))
$iface = '{' + [Guid]::NewGuid().ToString() + '}'
$null = New-Item -ItemType Directory -Path (Join-Path $root $iface) -Force
function HWlanRoot { return $root }
function Profile([string]$name, [string]$mode, [string]$auth, [string]$enc, [string]$extra = '') {
    "<?xml version=`"1.0`"?><WLANProfile xmlns=`"http://www.microsoft.com/networking/WLAN/profile/v1`"><name>$name</name><connectionType>ESS</connectionType><connectionMode>$mode</connectionMode><MSM><security><authEncryption><authentication>$auth</authentication><encryption>$enc</encryption><useOneX>false</useOneX></authEncryption>$extra</security></MSM></WLANProfile>"
}
try {
    $i = 0
    foreach ($p in @(
        (Profile 'OpenCafe' 'auto' 'open' 'none'), (Profile 'WepOld' 'manual' 'open' 'WEP'), (Profile 'TkipBox' 'auto' 'WPAPSK' 'TKIP'),
        (Profile 'Good2' 'auto' 'WPA2PSK' 'AES'), (Profile 'Good3' 'auto' 'WPA3SAE' 'AES'), (Profile 'Odd"Name' 'auto' 'open' 'none'),
        (Profile 'Bad Mode' 'weird' 'open' 'none')
    )) { [IO.File]::WriteAllText((Join-Path (Join-Path $root $iface) ("p$i.xml")), $p); $i++ }
    [IO.File]::WriteAllText((Join-Path (Join-Path $root $iface) 'enterprise.xml'), ((Profile 'Corp' 'auto' 'open' 'none') -replace '<useOneX>false', '<useOneX>true'))
    MakeSpec $wifiJson
    $r = HReadWifi
    Assert ($r.Count -eq 3 -and $r['OpenCafe'] -eq 1 -and $r['WepOld'] -eq 0 -and $r['TkipBox'] -eq 1) "wifi slice: $($r.Keys -join ',')"
    # A duplicate name (two adapters) is ambiguous and therefore left alone.
    [IO.File]::WriteAllText((Join-Path (Join-Path $root $iface) 'dupe.xml'), (Profile 'OpenCafe' 'auto' 'open' 'none'))
    Assert ((HReadWifi).Count -eq 2) 'duplicate names excluded'
    # DTDs are refused rather than resolved.
    [IO.File]::WriteAllText((Join-Path (Join-Path $root $iface) 'xxe.xml'), '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><WLANProfile><name>&e;</name></WLANProfile>')
    Reject { HReadWifi } 'DTD'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }


${function:HPreflight} = $realHPreflight
function FakeDwordKey([hashtable]$values) {
    $k = [pscustomobject]@{ Values = $values; SubKeyCount = 0 }
    $k | Add-Member ScriptMethod GetValueNames { return @($this.Values.Keys) }
    $k | Add-Member ScriptMethod GetValueKind { param($n) return [Microsoft.Win32.RegistryValueKind]::DWord }
    $k | Add-Member ScriptMethod GetValue { param($n) return $this.Values[$n] }
    return $k
}
MakeSpec $tlsJson
$script:fakeFs = $true; $script:fakePaths = @('HKLM:\T'); $script:fakeKey = FakeDwordKey @{ Enabled = [int]-1 }
Assert ((HReadRegistry (HDef 'ssl3.client.enabled')) -eq 4294967295) '0xFFFFFFFF reads back unsigned'
Assert ($null -eq (HReadRegistry (HDef 'ssl3.client.default_off'))) 'absent value reads as null'
$script:fakeKey = FakeDwordKey @{ Enabled = 0; DisabledByDefault = 1 }
Assert ((HReadRegistry (HDef 'ssl3.client.enabled')) -eq 0 -and (HReadRegistry (HDef 'ssl3.client.default_off')) -eq 1) 'tls read'
$script:calls = @()
function New-ItemProperty { param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force, $ErrorAction); $script:calls += ,@($Name, $Value) }
function Remove-ItemProperty { param($LiteralPath, $Name, $ErrorAction); $script:calls += ,@($Name, 'removed') }
HSetRegistry (HDef 'ssl3.client.enabled') 4294967295
HSetRegistry (HDef 'ssl3.client.enabled') 0
HSetRegistry (HDef 'ssl3.client.default_off') $null
Assert (($script:calls | ForEach-Object { "$($_[0])=$($_[1])" }) -join ',' -ceq 'Enabled=-1,Enabled=0,DisabledByDefault=removed') 'registry setter keeps the unsigned bits and value name'
function FakeTextKey([hashtable]$values, [hashtable]$kinds) {
    $k = [pscustomobject]@{ Values = $values; Kinds = $kinds; SubKeyCount = 0 }
    $k | Add-Member ScriptMethod GetValueNames { return @($this.Values.Keys) }
    $k | Add-Member ScriptMethod GetValueKind { param($n) return [Microsoft.Win32.RegistryValueKind]$this.Kinds[$n] }
    $k | Add-Member ScriptMethod GetValue { param($n) return $this.Values[$n] }
    return $k
}
MakeSpec $textJson
$script:fakeFs = $true; $script:fakePaths = @('HKLM:\E')
$script:fakeKey = FakeTextKey @{ DnsOverHttpsMode = 'automatic' } @{ DnsOverHttpsMode = 'String' }
Assert ((HReadRegistry (HDef 'EdgeMode')) -ceq 'automatic') 'a text value reads back exactly'
$script:fakeKey = FakeTextKey @{ DnsOverHttpsMode = '' } @{ DnsOverHttpsMode = 'String' }
$emptyText = HReadRegistry (HDef 'EdgeMode')
Assert ($emptyText -is [string] -and $emptyText.Length -eq 0) 'an empty text is not the same as an absent value'
$script:fakeKey = FakeTextKey @{} @{}
Assert ($null -eq (HReadRegistry (HDef 'EdgeMode'))) 'an absent text value reads as null'
foreach ($kind in @('DWord', 'ExpandString', 'MultiString', 'Binary', 'QWord')) {
    $script:fakeKey = FakeTextKey @{ DnsOverHttpsMode = 'off' } @{ DnsOverHttpsMode = $kind }
    Reject { HReadRegistry (HDef 'EdgeMode') } 'is not text'
}
$script:calls = @()
$script:fakeKey = FakeTextKey @{ DnsOverHttpsMode = 'automatic' } @{ DnsOverHttpsMode = 'String' }
HSetRegistry (HDef 'EdgeMode') 'off'
HSetRegistry (HDef 'EdgeMode') 'https://dns.example/dns-query{?dns}'
HSetRegistry (HDef 'EdgeMode') $null
Assert (($script:calls | ForEach-Object { "$($_[0])=$($_[1])" }) -join ',' -ceq 'DnsOverHttpsMode=off,DnsOverHttpsMode=https://dns.example/dns-query{?dns},DnsOverHttpsMode=removed') 'the text setter keeps the value name and the exact text'
$script:calls = @()
$script:fakeKey = FakeTextKey @{ DnsOverHttpsMode = 0 } @{ DnsOverHttpsMode = 'DWord' }
Reject { HSetRegistry (HDef 'EdgeMode') 'off' } 'is not text'
Reject { HSetRegistry (HDef 'EdgeMode') 5 } 'Invalid text setting'
Assert ($script:calls.Count -eq 0) 'a value of another kind was replaced'
$watch = @(HRegistryPaths)
Assert (@($watch | Where-Object { $_.path -ceq 'HKLM:\E' -and $_.name -ceq 'DnsOverHttpsMode' }).Count -eq 1) 'policy checks watch the real value name'
MakeSpec $stackJson
Assert ((HValueName (HDef 'DisableIPSourceRouting6')) -ceq 'DisableIPSourceRouting' -and (HDef 'DisableIPSourceRouting6').path -ceq 'HKLM:\T6') 'same value name under another key'
$script:fakePaths = @(); $script:fakeFs = $false

MakeSpec $nbJson
foreach ($ok in @('{11111111-1111-1111-1111-111111111111}', '{abcdefAB-1111-2222-3333-444444444444}')) { Assert (HNameOk $ok) "adapter $ok" }
foreach ($bad in @('', 'Ethernet', '{1111}', '11111111-1111-1111-1111-111111111111', "{11111111-1111-1111-1111-111111111111}'; calc", '{1111111g-1111-1111-1111-111111111111}')) { Assert (!(HNameOk $bad)) "adapter name accepted: $bad" }
function Get-CimInstance {
    param($ClassName, $Namespace, $Filter)
    switch ($ClassName) {
        'Win32_NetworkAdapterConfiguration' {
            if ($Filter -match "SettingID = '(.+)'") { $id = $Matches[1]; return @($script:nics | Where-Object { $_.SettingID -ceq $id }) }
            return $script:nics
        }
        'Win32_OperatingSystem' { return [pscustomobject]@{ OperatingSystemSKU = $script:sku } }
        default { throw "Unexpected probe $ClassName" }
    }
}
$script:nics = @(
    [pscustomobject]@{ SettingID = '{11111111-1111-1111-1111-111111111111}'; TcpipNetbiosOptions = [uint32]0 }
    [pscustomobject]@{ SettingID = '{22222222-2222-2222-2222-222222222222}'; TcpipNetbiosOptions = [uint32]2 }
    [pscustomobject]@{ SettingID = '{33333333-3333-3333-3333-333333333333}'; TcpipNetbiosOptions = $null }
    [pscustomobject]@{ SettingID = 'not-a-guid'; TcpipNetbiosOptions = [uint32]1 }
    [pscustomobject]@{ SettingID = '{44444444-4444-4444-4444-444444444444}'; TcpipNetbiosOptions = [uint32]1 }
    [pscustomobject]@{ SettingID = '{44444444-4444-4444-4444-444444444444}'; TcpipNetbiosOptions = [uint32]2 }
)
$r = HReadNetbios
Assert ($r.Count -eq 2 -and $r['{11111111-1111-1111-1111-111111111111}'] -eq 0 -and $r['{22222222-2222-2222-2222-222222222222}'] -eq 2) 'netbios slice skips unreadable, invalid and duplicate adapters'
$script:calls = @(); $script:rv = 0
function Invoke-CimMethod { param($InputObject, $MethodName, $Arguments); $script:calls += ,@($InputObject.SettingID, $MethodName, $Arguments.TcpipNetbiosOptions); return [pscustomobject]@{ ReturnValue = $script:rv } }
HSetNetbios '{11111111-1111-1111-1111-111111111111}' 2
HSetNetbios '{22222222-2222-2222-2222-222222222222}' 0
Assert (($script:calls | ForEach-Object { $_ -join '/' }) -join ',' -ceq '{11111111-1111-1111-1111-111111111111}/SetTcpipNetbios/2,{22222222-2222-2222-2222-222222222222}/SetTcpipNetbios/0') 'netbios setter arguments'
$script:rv = 1; HSetNetbios '{11111111-1111-1111-1111-111111111111}' 2
$script:rv = 84
Reject { HSetNetbios '{11111111-1111-1111-1111-111111111111}' 2 } 'refused'
Reject { HSetNetbios '{44444444-4444-4444-4444-444444444444}' 2 } 'exactly once'
Reject { HSetNetbios '{11111111-1111-1111-1111-111111111111}' 3 } 'Invalid NetBIOS'
Reject { HSetNetbios "x'; calc" 2 } 'Invalid NetBIOS'

# NetBIOS gate: SMB1 off and no bare-name shares.
Assert ((HRemoteHost '\\NAS\media') -ceq 'NAS' -and (HRemoteHost '\\nas.local\x') -ceq 'nas.local' -and (HRemoteHost 'C:\x') -ceq '') 'remote host parsing'
Assert ((HBareName 'NAS') -and !(HBareName 'nas.local') -and !(HBareName '192.168.1.5') -and !(HBareName 'fe80::1') -and !(HBareName '')) 'bare name detection'
$script:smb = [pscustomobject]@{ EnableSMB1Protocol = $false }
$script:maps = @(); $script:conns = @(); $script:hives = @(); $script:drivePath = ''
function Get-SmbServerConfiguration { return $script:smb }
function Get-SmbMapping { param($ErrorAction); return $script:maps }
function Get-SmbConnection { param($ErrorAction); return $script:conns }
function Get-ChildItem { param($LiteralPath); if ($LiteralPath -ceq 'Registry::HKEY_USERS') { return $script:hives }; return @([pscustomobject]@{ PSPath = 'drive' }) }
function Get-ItemProperty { param($LiteralPath); return [pscustomobject]@{ RemotePath = $script:drivePath } }
$script:fakeFs = $true; $script:fakePaths = @(); $script:fakeKey = $null
MakeSpec $nbJson
HNetbiosPreflight
Assert $true 'clean machine passes the NetBIOS gate'
$script:smb = [pscustomobject]@{ EnableSMB1Protocol = $true }
Reject { HNetbiosPreflight } 'SMB1'
$script:smb = [pscustomobject]@{ EnableSMB1Protocol = $null }
Reject { HNetbiosPreflight } 'could not be checked'
$script:smb = [pscustomobject]@{ EnableSMB1Protocol = $false }
$script:fakePaths = @('HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'); $script:fakeKey = FakeDwordKey @{ Start = 3 }
Reject { HNetbiosPreflight } 'SMB1'
$script:fakeKey = FakeDwordKey @{ Start = 4 }
HNetbiosPreflight
$script:fakePaths = @(); $script:fakeKey = $null
$script:maps = @([pscustomobject]@{ RemotePath = '\\NAS\media' })
Reject { HNetbiosPreflight } 'old name service'
$script:maps = @([pscustomobject]@{ RemotePath = '\\nas.local\media' }, [pscustomobject]@{ RemotePath = '\\192.168.1.9\share' })
HNetbiosPreflight
$script:maps = @(); $script:conns = @([pscustomobject]@{ ServerName = 'FILESRV' })
Reject { HNetbiosPreflight } 'old name service'
$script:conns = @()
$script:hives = @([pscustomobject]@{ PSChildName = 'S-1-5-21-1-2-3-1001' }, [pscustomobject]@{ PSChildName = 'S-1-5-21-1-2-3-1001_Classes' })
$script:fakePaths = @('Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Network'); $script:drivePath = '\\OLDBOX\data'
Reject { HNetbiosPreflight } 'old name service'
$script:drivePath = '\\box.example.com\data'
HNetbiosPreflight
$script:fakePaths = @(); $script:fakeFs = $false

MakeSpec $obJson
Assert ((HReadOutbound)['RulePresent'] -eq 0) 'rule absent reads as 0 (ObjectNotFound is not an error)'
$script:rule = [pscustomobject]@{ Name = 'Secblitz-Block-Outbound-SMB-Internet'; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True' }
$script:portFilter = [pscustomobject]@{ Protocol = 'TCP'; RemotePort = @('445', '139') }
$script:addrFilter = [pscustomobject]@{ RemoteAddress = 'Internet' }
function Get-NetFirewallRule { param($PolicyStore, $Name, $ErrorAction); if ($Name -cne 'Secblitz-Block-Outbound-SMB-Internet') { throw 'wrong name' }; return $script:rules }
function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline = $true)]$InputObject); process { $script:portFilter } }
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline = $true)]$InputObject); process { $script:addrFilter } }
$script:rules = @($script:rule)
Assert ((HReadOutbound)['RulePresent'] -eq 1) 'exact rule reads as 1'
$script:rules = @($script:rule, $script:rule)
Reject { HReadOutbound } 'more than once'
foreach ($variant in @(
    { $script:rule = [pscustomobject]@{ Name = 'x'; Direction = 'Outbound'; Action = 'Allow'; Enabled = 'True' } },
    { $script:rule = [pscustomobject]@{ Name = 'x'; Direction = 'Outbound'; Action = 'Block'; Enabled = 'False' } },
    { $script:portFilter = [pscustomobject]@{ Protocol = 'TCP'; RemotePort = @('445') } },
    { $script:portFilter = [pscustomobject]@{ Protocol = 'UDP'; RemotePort = @('445', '139') } },
    { $script:addrFilter = [pscustomobject]@{ RemoteAddress = 'Any' } }
)) {
    $script:rule = [pscustomobject]@{ Name = 'x'; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True' }
    $script:portFilter = [pscustomobject]@{ Protocol = 'TCP'; RemotePort = @('445', '139') }
    $script:addrFilter = [pscustomobject]@{ RemoteAddress = 'Internet' }
    & $variant
    $script:rules = @($script:rule)
    Reject { HReadOutbound } 'exists but is different'
}
$script:calls = @()
function New-NetFirewallRule { param($PolicyStore, $Name, $DisplayName, $Description, $Direction, $Action, $Protocol, $RemotePort, $RemoteAddress, $Profile, $Enabled, $ErrorAction); $script:calls += ,@('new', $PolicyStore, $Name, $DisplayName, $Direction, $Action, $Protocol, ($RemotePort -join '+'), $RemoteAddress, $Profile, $Enabled) }
function Remove-NetFirewallRule { param($PolicyStore, $Name, $ErrorAction); $script:calls += ,@('remove', $PolicyStore, $Name) }
HSetOutbound 1; HSetOutbound 0
Assert (($script:calls | ForEach-Object { $_ -join '/' }) -join ',' -ceq 'new/PersistentStore/Secblitz-Block-Outbound-SMB-Internet/Secblitz: block outbound file sharing to the internet/Outbound/Block/TCP/445+139/Internet/Any/True,remove/PersistentStore/Secblitz-Block-Outbound-SMB-Internet') 'outbound rule setter arguments'

MakeSpec $npJson
$script:mp = [pscustomobject]@{ EnableNetworkProtection = $null }
Assert ((HRead)['EnableNetworkProtection'] -eq 0) 'unreported network protection counts as off'
$script:mp = [pscustomobject]@{ EnableNetworkProtection = 'Enabled' }
Assert ((HRead)['EnableNetworkProtection'] -eq 1) 'network protection name'
$script:mp = [pscustomobject]@{ EnableNetworkProtection = [byte]2 }
Assert ((HRead)['EnableNetworkProtection'] -eq 2 -and (HAnyUnsafe (HRead))) 'audit mode is not protection'
$script:mp = [pscustomobject]@{ EnableNetworkProtection = 'Bogus' }
Reject { HRead } 'not readable'
MakeSpec $cblJson
$script:mp = [pscustomobject]@{ CloudBlockLevel = 'High'; CloudExtendedTimeout = [uint32]20 }
$r = HRead
Assert ($r['CloudBlockLevel'] -eq 2 -and $r['CloudExtendedTimeout'] -eq 20 -and !(HAnyUnsafe $r)) 'cloud block level names'
$script:mp = [pscustomobject]@{ CloudBlockLevel = [byte]6; CloudExtendedTimeout = [uint32]25 }
$r = HRead
Assert ($r['CloudBlockLevel'] -eq 6 -and !(HAnyUnsafe $r)) 'zero tolerance is preserved, never written'
Assert ((HFixOf (HDef 'CloudBlockLevel') 0) -eq 2 -and (HFixOf (HDef 'CloudBlockLevel') 1) -eq 2 -and (HFixOf (HDef 'CloudExtendedTimeout') 0) -eq 20) 'cloud block fixes are High and 20 seconds'
$script:mp = [pscustomobject]@{ CloudBlockLevel = 'Default'; CloudExtendedTimeout = [uint32]0 }
$r = HRead
Assert ($r['CloudBlockLevel'] -eq 0 -and $r['CloudExtendedTimeout'] -eq 0 -and (HAnyUnsafe $r)) 'defaults are not protected'
$script:mp = [pscustomobject]@{ CloudBlockLevel = [byte]3; CloudExtendedTimeout = [uint32]0 }
Reject { HRead } 'not readable'
$script:mp = [pscustomobject]@{ CloudBlockLevel = 'High'; CloudExtendedTimeout = $null }
Reject { HRead } 'not readable'
$script:calls = @()
function Set-MpPreference { param($EnableNetworkProtection, $CloudBlockLevel, $CloudExtendedTimeout); $script:calls += ,@($EnableNetworkProtection, $CloudBlockLevel, $CloudExtendedTimeout) }
HSetDefenderPref (HDef 'CloudBlockLevel') 2; HSetDefenderPref (HDef 'CloudBlockLevel') 0; HSetDefenderPref (HDef 'CloudBlockLevel') 4; HSetDefenderPref (HDef 'CloudExtendedTimeout') 20
Reject { HSetDefenderPref (HDef 'CloudBlockLevel') 3 } 'Invalid cloud block level'
MakeSpec $npJson
HSetDefenderPref (HDef 'EnableNetworkProtection') 1; HSetDefenderPref (HDef 'EnableNetworkProtection') 0; HSetDefenderPref (HDef 'EnableNetworkProtection') 2
Assert (($script:calls | ForEach-Object { "$($_[0])|$($_[1])|$($_[2])" }) -join ',' -ceq '|High|,|Default|,|HighPlus|,||20,Enabled||,Disabled||,AuditMode||') 'new Defender setter arguments'

$script:fakeFs = $true; $script:fakePaths = @(); $script:fakeKey = $null
$script:status = [pscustomobject]@{ RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true }
function Get-MpComputerStatus { return $script:status }
$script:mp = [pscustomobject]@{ MAPSReporting = 'Advanced' }
$script:sku = 48
MakeSpec $npJson
HPreflight
$script:sku = 101
Reject { HPreflight } 'does not include it'
$script:sku = 0
Reject { HPreflight } 'does not include it'
$script:sku = 48
$script:status = [pscustomobject]@{ RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $false }
Reject { HPreflight } 'behavior monitoring'
$script:status = [pscustomobject]@{ RealTimeProtectionEnabled = $false; BehaviorMonitorEnabled = $true }
Reject { HPreflight } 'real-time protection is off'
$script:status = [pscustomobject]@{ RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true }
$script:mp = [pscustomobject]@{ MAPSReporting = 'Disabled' }
Reject { HPreflight } 'cloud protection is off'
$script:mp = [pscustomobject]@{ MAPSReporting = 'Advanced' }
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\CCM')
Reject { HPreflight } 'Configuration Manager'
$script:fakePaths = @()
MakeSpec $cblJson
HPreflight
$script:mp = [pscustomobject]@{ MAPSReporting = 'Disabled' }
Reject { HPreflight } 'cloud protection is off'
$script:mp = [pscustomobject]@{ MAPSReporting = 'Advanced' }
MakeSpec $officeJson
Assert (!(HOfficeInstalled)) 'no Office on a clean machine'
Reject { HPreflight } 'Office was not found'
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration')
Assert (HOfficeInstalled) 'Click-to-Run Office detected'
HPreflight
if ($env:ProgramFiles) {
    $script:fakePaths = @([IO.Path]::Combine($env:ProgramFiles, 'Microsoft Office\root\Office16\WINWORD.EXE'))
    Assert (HOfficeInstalled) 'Office found by program file'
}
$script:fakePaths = @(); $script:fakeFs = $false
$script:sku = 48; Assert (HEditionHasNetworkProtection) 'Pro supports network protection'
foreach ($homeSku in @(98, 99, 100, 101, 0, 999)) { $script:sku = $homeSku; Assert (!(HEditionHasNetworkProtection)) "sku $homeSku must not be offered" }
$noGate = '"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}'
$exclJson = '{"id":"defender.exclusions_risky","source":"DefenderExclusions","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],' + $noGate + '}'
$svcJson = '{"id":"services.legacy_remote","source":"LegacyServices","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[3,4],"absentSafe":false,"fix":4,"max":13}],' + $noGate + '}'
$pauseKeys = @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesStartTime', 'PauseQualityUpdatesStartTime') | ForEach-Object {
    '{"name":"' + $_ + '","path":"HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":2000000000}'
}
$pauseJson = '{"id":"update.paused","source":"UpdatePause","dynamic":false,"reboot":false,"keys":[' + ($pauseKeys -join ',') + '],' + $noGate + '}'
$ssJson = '{"id":"smartscreen.apps","source":"SmartScreen","dynamic":false,"reboot":false,"keys":[{"name":"SmartScreenEnabled","path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer","rule":"set","safe":[1,2,3],"absentSafe":true,"fix":1,"max":3},{"name":"EnableSmartScreen","path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","rule":"set","safe":[1],"absentSafe":true,"fix":null,"max":1}],' + $noGate + '}'
function ValueKey($map) {
    $k = [pscustomobject]@{ Map = $map }
    $k | Add-Member ScriptMethod GetValueNames { return @($this.Map.Keys) }
    $k | Add-Member ScriptMethod GetValueKind {
        param($n)
        if ($this.Map[$n] -is [string]) { return [Microsoft.Win32.RegistryValueKind]::String }
        else { return [Microsoft.Win32.RegistryValueKind]::DWord }
    }
    $k | Add-Member ScriptMethod GetValue { param($n) return $this.Map[$n] }
    return $k
}
function CallLog() { return (($script:calls | ForEach-Object { $_ -join ':' }) -join ',') }

foreach ($risky in @('C:\', 'c:', 'C:\Windows', 'C:\Windows\', 'C:\Windows\Temp', 'C:\Users', 'C:\Users\Bob', 'C:\Users\Bob\Downloads', 'C:\Users\*\Downloads', '%USERPROFILE%\Downloads', '%TEMP%', 'D:\*', 'C:\Users\Bob\AppData\Local\Temp', 'C:\Program Files')) {
    Assert (HExclusionRisky 'path' $risky) "risky path: $risky"
}
foreach ($fine in @('C:\Games\Steam', 'D:\Projects\app', 'C:\Program Files\Foo', 'C:\Users\Bob\Documents\Work', 'C:\Users\Bob\Downloads\keep')) {
    Assert (!(HExclusionRisky 'path' $fine)) "ordinary path left alone: $fine"
}
foreach ($risky in @('exe', '.DLL', 'ps1', 'bat', 'js', 'vbs', 'scr')) { Assert (HExclusionRisky 'ext' $risky) "risky extension: $risky" }
foreach ($fine in @('log', 'txt', 'iso', 'pdf')) { Assert (!(HExclusionRisky 'ext' $fine)) "ordinary extension left alone: $fine" }
foreach ($risky in @('powershell.exe', 'C:\Windows\System32\cmd.exe', 'mshta', 'wscript.exe', 'pwsh.exe')) { Assert (HExclusionRisky 'proc' $risky) "risky process: $risky" }
foreach ($fine in @('steam.exe', 'C:\Games\game.exe')) { Assert (!(HExclusionRisky 'proc' $fine)) "ordinary process left alone: $fine" }
Assert (!(HExclusionRisky 'path' '') -and !(HExclusionRisky 'other' 'exe')) 'empty and unknown kinds are never risky'
MakeSpec $exclJson
foreach ($ok in @('path:C:\Users\Bob\Downloads', 'ext:exe', 'proc:cmd')) { Assert (HNameOk $ok) "exclusion name $ok" }
foreach ($bad in @('path:D:\Games', 'ext:log', 'file:C:\x', 'ext:', 'PATH:C:\Windows', ' path:C:\Windows', "ext:ex`te", 'path:C:\"x', '')) { Assert (!(HNameOk $bad)) "exclusion name accepted: $bad" }

function Load($name) {}
$script:hWanted = @{}
$script:mp = [pscustomobject]@{ ExclusionPath = @('C:\Users\Bob\Downloads', 'D:\Games'); ExclusionExtension = @('exe', 'log'); ExclusionProcess = $null }
function Get-MpPreference { return $script:mp }
$r = HReadExclusions
Assert ($r.Count -eq 2 -and $r['path:C:\Users\Bob\Downloads'] -eq 1 -and $r['ext:exe'] -eq 1) 'only risky exclusions are listed'
$script:hWanted = @{ 'ext:dll' = 1; 'ext:exe' = 0 }
$r = HReadExclusions
Assert ($r['ext:dll'] -eq 0 -and $r['ext:exe'] -eq 1) 'a removed exclusion reads as 0'
$script:mp = [pscustomobject]@{ ExclusionPath = 'N/A: Must be an administrator to view exclusions'; ExclusionExtension = $null; ExclusionProcess = $null }
Reject { HReadExclusions } 'not readable'
$script:hWanted = @{}
$script:exPaths = @('C:\Users\Bob\Downloads', 'D:\Games')
function Add-MpPreference { param($ExclusionPath, $ExclusionExtension, $ExclusionProcess); if ($ExclusionPath) { $script:exPaths = @($script:exPaths) + @($ExclusionPath) } }
function Remove-MpPreference { param($ExclusionPath, $ExclusionExtension, $ExclusionProcess); if ($ExclusionPath) { $script:exPaths = @($script:exPaths | Where-Object { $_ -ne $ExclusionPath }) } }
HSetExclusion 'path:C:\Users\Bob\Downloads' 0
Assert (@($script:exPaths).Count -eq 1 -and $script:exPaths[0] -ceq 'D:\Games') 'risky exclusion removed, the other one untouched'
HSetExclusion 'path:C:\Users\Bob\Downloads' 1
Assert (@($script:exPaths) -contains 'C:\Users\Bob\Downloads') 'undo adds the exclusion back'
Reject { HSetExclusion 'path:D:\Games' 0 } 'Unknown hardening item'
Reject { HSetExclusion 'path:C:\Windows' $null } 'Invalid exclusion state'
# Full write: remove then undo, through the real reader (hint keeps removed names visible).
${function:HRead} = $realHRead
function HSet([string]$name, $v) { HSetExclusion $name $v }
$script:preflightFails = $false; $script:blocked = $false
$script:mp = $null
function Get-MpPreference { return [pscustomobject]@{ ExclusionPath = $script:exPaths; ExclusionExtension = $null; ExclusionProcess = $null } }
$script:exPaths = @('C:\Users\Bob\Downloads', 'D:\Games')
HWrite (Input '{"items":{"path:C:\\Users\\Bob\\Downloads":0}}')
Assert (@($script:exPaths).Count -eq 1 -and $script:exPaths[0] -ceq 'D:\Games') 'exclusion fix verified through the reader'
HWrite (Input '{"items":{"path:C:\\Users\\Bob\\Downloads":1}}')
Assert (@($script:exPaths) -contains 'C:\Users\Bob\Downloads' -and @($script:exPaths).Count -eq 2) 'exclusion undo verified through the reader'
Reject { HWrite (Input '{"items":{"path:D:\\Games":0}}') } 'Unknown hardening item'

# Folder protection: the mode, the app names that may be allowed and the allow list.
& {
function HSet([string]$name, $v) { & $realHSet $name $v }
$cfaWatchJson = '{"id":"defender.cfa_watch","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"EnableControlledFolderAccess","path":"","rule":"set","safe":[1,2,3,4],"absentSafe":false,"fix":2,"max":4}],' + $noGate + '}'
$cfaBlockJson = '{"id":"defender.cfa_block","source":"DefenderPref","dynamic":false,"reboot":false,"keys":[{"name":"EnableControlledFolderAccess","path":"","rule":"set","safe":[1,3],"absentSafe":false,"fix":1,"max":4}],' + $noGate + '}'
$cfaAppsJson = '{"id":"defender.cfa_allowed_apps","source":"CfaAllowedApps","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $noGate + '}'
$script:hCfaPrefs = @{}
function Get-MpPreference { return [pscustomobject]$script:hCfaPrefs }
$script:cfaSet = @{}
function Set-MpPreference { param($EnableControlledFolderAccess); $script:cfaSet['mode'] = $EnableControlledFolderAccess; $script:hCfaPrefs['EnableControlledFolderAccess'] = $EnableControlledFolderAccess }
MakeSpec $cfaWatchJson
foreach ($pair in @(@('Disabled', 0), @('Enabled', 1), @('AuditMode', 2), @('BlockDiskModificationsOnly', 3), @('AuditDiskModificationsOnly', 4), @(2, 2))) {
    $script:hCfaPrefs = @{ EnableControlledFolderAccess = $pair[0] }
    Assert ((HReadDefenderPref)['EnableControlledFolderAccess'] -eq $pair[1]) "folder protection mode $($pair[0])"
    Assert ((HCfaMode) -eq $pair[1]) "folder protection preflight mode $($pair[0])"
}
foreach ($bad in @('Other', 5, $null)) {
    $script:hCfaPrefs = @{ EnableControlledFolderAccess = $bad }
    Reject { HReadDefenderPref } 'not readable'
}
$script:hCfaPrefs = @{}
Reject { HCfaMode } 'not readable'
$def = HDef 'EnableControlledFolderAccess'
foreach ($mode in 0..4) {
    Assert ((HIsSafe $def $mode) -eq ($mode -ne 0)) "watch safe at $mode"
    Assert ((HFixOf $def $mode) -eq $(if ($mode -eq 0) { 2 } else { $mode })) "watch fix at $mode"
}
MakeSpec $cfaBlockJson
$def = HDef 'EnableControlledFolderAccess'
foreach ($mode in 0..4) {
    Assert ((HIsSafe $def $mode) -eq ($mode -eq 1 -or $mode -eq 3)) "block safe at $mode"
    Assert ((HFixOf $def $mode) -eq $(if ($mode -eq 1 -or $mode -eq 3) { $mode } else { 1 })) "block fix at $mode"
}
$script:hCfaPrefs = @{ EnableControlledFolderAccess = 'AuditMode' }
HSetDefenderPref $def 1
Assert ($script:cfaSet['mode'] -ceq 'Enabled') 'full protection is Enabled'
MakeSpec $cfaWatchJson
HSetDefenderPref (HDef 'EnableControlledFolderAccess') 2
Assert ($script:cfaSet['mode'] -ceq 'AuditMode') 'watching is AuditMode'
HSetDefenderPref (HDef 'EnableControlledFolderAccess') 0
Assert ($script:cfaSet['mode'] -ceq 'Disabled') 'undo of watching is Disabled'

# The preflight offers each step only at the right moment.
$script:cfaStatusOn = $true
function Get-MpComputerStatus { return [pscustomobject]@{ RealTimeProtectionEnabled = $script:cfaStatusOn } }
$script:fakePaths = @()
function Test-Path { param($LiteralPath, $Path); return (@($script:fakePaths) -contains $(if ($LiteralPath) { $LiteralPath } else { $Path })) }
foreach ($case in @(
    @($cfaWatchJson, 0, $true, ''),
    @($cfaWatchJson, 2, $true, ''),
    @($cfaBlockJson, 0, $true, ''),
    @($cfaBlockJson, 1, $true, ''),
    @($cfaBlockJson, 2, $true, ''),
    @($cfaBlockJson, 4, $true, ''),
    @($cfaAppsJson, 0, $false, 'folder protection is off'),
    @($cfaAppsJson, 1, $true, ''),
    @($cfaAppsJson, 2, $true, '')
)) {
    MakeSpec $case[0]
    $script:hCfaPrefs = @{ EnableControlledFolderAccess = $case[1] }
    if ($case[2]) { & $realHPreflight }
    else { Reject { & $realHPreflight } $case[3] }
}
MakeSpec $cfaWatchJson
$script:hCfaPrefs = @{ EnableControlledFolderAccess = 0 }
$script:cfaStatusOn = $false
Reject { & $realHPreflight } 'real-time protection is off'
$script:cfaStatusOn = $true
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\CCM')
Reject { & $realHPreflight } 'Configuration Manager'
$script:fakePaths = @()

# App names: one drive-letter path to one .exe, never a script tool.
MakeSpec $cfaAppsJson
foreach ($ok in @('app:C:\Tools\PhotoTool.exe', 'app:D:\Games\Save Helper\helper.EXE', 'app:C:\Program Files (x86)\V\a.exe')) { Assert (HNameOk $ok) "app name $ok" }
foreach ($bad in @('', 'app:', 'C:\Tools\a.exe', 'App:C:\a.exe', 'app:Tools\a.exe', 'app:\\server\share\a.exe', 'app:C:a.exe', 'app:C:\', 'app:C:\a.exe\',
        'app:C:\Tools\a.dll', 'app:C:\Tools\.exe', 'app:C:\Tools\*.exe', 'app:C:\*\a.exe', 'app:C:\Tools\a?.exe', 'app:C:\Tools\..\a.exe', 'app:C:\Tools\.\a.exe',
        'app:C:\Tools\\a.exe', 'app:%ProgramFiles%\a.exe', 'app:C:/Tools/a.exe', 'app:C:\Tools\a.exe:s', 'app:C:\Tools\a".exe', "app:C:\Tools\a`n.exe",
        'app: C:\Tools\a.exe', 'app:C:\Tools\a.exe ', 'app:C:\Tools \a.exe', 'app:C:\Tools\a|b.exe', ('app:C:\' + ('a' * 260) + '.exe'),
        'app:C:\Windows\System32\cmd.exe', 'app:C:\Windows\System32\WindowsPowerShell\v1.0\POWERSHELL.EXE', 'app:C:\Program Files\PowerShell\7\pwsh.exe',
        'app:C:\Windows\System32\wscript.exe', 'app:C:\Windows\System32\cscript.exe', 'app:C:\Windows\System32\mshta.exe', 'app:C:\Windows\System32\rundll32.exe')) {
    Assert (!(HNameOk $bad)) "app name accepted: $bad"
}

# Events become app paths: the "Process Name" field first, the position as the fallback.
$eventXml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1124</EventID></System><EventData><Data Name="Product Name">Microsoft Defender Antivirus</Data><Data Name="Path">C:\Users\Bob\Documents\a.docx</Data><Data Name="Process Name">C:\Tools\PhotoTool.exe</Data></EventData></Event>'
Assert ((HCfaEventPath $eventXml @()) -ceq 'C:\Tools\PhotoTool.exe') 'event process name by field name'
$positional = '<Event><EventData><Data>x</Data></EventData></Event>'
$props = @(1..5 | ForEach-Object { [pscustomobject]@{ Value = "p$_" } }) + @([pscustomobject]@{ Value = 'D:\Apps\sync.exe' })
Assert ((HCfaEventPath $positional $props) -ceq 'D:\Apps\sync.exe') 'event process name by position'
Assert ([string]::IsNullOrEmpty((HCfaEventPath 'not xml' @()))) 'an unreadable event names no app'

$script:cfaFiles = @('C:\Tools\PhotoTool.exe', 'C:\Tools\Edit.exe', 'D:\Apps\sync.exe', 'C:\Windows\System32\cmd.exe')
function HCfaFileExists([string]$path) { return (@($script:cfaFiles) -contains $path) }
$allowedMap = @{ 'd:\apps\sync.exe' = 'D:\Apps\sync.exe' }
$seenPaths = @('C:\Tools\PhotoTool.exe', 'C:\Tools\Edit.exe', 'c:\tools\edit.exe', 'C:\Tools\Edit.exe', 'D:\Apps\sync.exe', 'C:\Windows\System32\cmd.exe', 'C:\Gone\missing.exe', 'C:\Tools\*.exe', 'relative.exe', $null, 5)
$picked = @(HCfaPickApps $seenPaths $allowedMap)
Assert ($picked.Count -eq 2 -and $picked[0] -ceq 'C:\Tools\Edit.exe' -and $picked[1] -ceq 'C:\Tools\PhotoTool.exe') "most seen first; allowed, missing, odd and script tools left out: $($picked -join ',')"
Assert (@(HCfaPickApps @() @{}).Count -eq 0) 'no events, no apps'
$many = @(1..40 | ForEach-Object { "C:\Tools\app$_.exe" })
$script:cfaFiles = $many
Assert (@(HCfaPickApps $many @{}).Count -eq 24) 'at most 24 apps are offered'
$script:cfaFiles = @('C:\Tools\PhotoTool.exe', 'C:\Tools\Edit.exe', 'D:\Apps\sync.exe')

# Reading: candidates read 0, allowed apps Secblitz added read 1, other allowed apps are not listed.
$script:cfaState = @{}
function HStateNames() { return @($script:cfaState.Keys) }
function HStateGet([string]$name) { if ($script:cfaState.ContainsKey($name)) { return $script:cfaState[$name] }; return $null }
function HStateSet([string]$name, $data) { $script:cfaState[$name] = $data }
function HStateRemove([string]$name) { $null = $script:cfaState.Remove($name) }
$script:hCfaAllowed = @('D:\Apps\sync.exe')
$script:hCfaEvents = @('C:\Tools\PhotoTool.exe', 'C:\Tools\PhotoTool.exe', 'C:\Tools\Edit.exe', 'D:\Apps\sync.exe')
function Get-MpPreference { return [pscustomobject]@{ ControlledFolderAccessAllowedApplications = $script:hCfaAllowed; EnableControlledFolderAccess = 2 } }
function Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction); $script:cfaQuery = $FilterHashtable; return @($script:hCfaEvents | ForEach-Object { $e = [pscustomobject]@{ Path = $_ }; $e | Add-Member ScriptMethod ToXml { return ('<Event><EventData><Data Name="Process Name">' + $this.Path + '</Data></EventData></Event>') }; $e | Add-Member NoteProperty Properties @(); $e }) }
$script:hWanted = @{}
$r = HReadCfaApps
Assert ($r.Count -eq 2 -and $r['app:C:\Tools\PhotoTool.exe'] -eq 0 -and $r['app:C:\Tools\Edit.exe'] -eq 0) "candidates read 0, an app that is already allowed is not listed: $($r.Keys -join ',')"
Assert ($script:cfaQuery.LogName -ceq 'Microsoft-Windows-Windows Defender/Operational' -and @($script:cfaQuery.Id) -contains 1123 -and @($script:cfaQuery.Id) -contains 1124) 'both the audited and the blocked events are read'
Assert (([datetime]::Now - $script:cfaQuery.StartTime).TotalDays -lt 7.1 -and ([datetime]::Now - $script:cfaQuery.StartTime).TotalDays -gt 6.9) 'the last seven days are read'
Assert ($script:hLabels.Count -eq 2 -and $script:hLabels['app:C:\Tools\Edit.exe'] -ceq 'C:\Tools\Edit.exe') 'each flagged app is named by its path'
$labels = @(HLabelList $r)
Assert ($labels.Count -eq 2 -and $labels[0].kind -ceq 'app' -and $labels[0].name -ceq 'C:\Tools\Edit.exe') 'flagged apps are shown as apps'
# Each app is shown with who published it; an unsigned one in a download folder is called out.
function Get-AuthenticodeSignature { param($LiteralPath); $script:cfaSig[$LiteralPath] }
$script:cfaSig = @{
    'C:\Users\a\Downloads\x.exe' = [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }
    'C:\Tools\Edit.exe' = [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }
    'C:\Tools\Bad.exe' = [pscustomobject]@{ Status = 'HashMismatch'; SignerCertificate = $null }
}
Assert ((HCfaLabel 'C:\Users\a\Downloads\x.exe') -ceq 'C:\Users\a\Downloads\x.exe (not signed, in a temporary or download folder)') 'unsigned download is called out'
Assert ((HCfaLabel 'C:\Tools\Edit.exe') -ceq 'C:\Tools\Edit.exe (not signed)') 'unsigned app is named'
Assert ((HCfaLabel 'C:\Tools\Bad.exe') -ceq 'C:\Tools\Bad.exe (signature not valid)') 'broken signature is named'
Remove-Item function:Get-AuthenticodeSignature
$script:hCfaEvents = @()
Assert ((HReadCfaApps).Count -eq 0) 'no events, nothing to offer'
$script:hCfaAllowed = @('N/A: Must be an administrator to view exclusions')
Reject { HReadCfaApps } 'not readable'
$script:hCfaAllowed = @('D:\Apps\sync.exe')

# Allowing one app records it, undo removes exactly that one and nothing the person added.
$script:cfaAdded = @()
function Add-MpPreference { param($ControlledFolderAccessAllowedApplications); $script:cfaAdded += @($ControlledFolderAccessAllowedApplications); $script:hCfaAllowed = @($script:hCfaAllowed) + @($ControlledFolderAccessAllowedApplications) }
function Remove-MpPreference { param($ControlledFolderAccessAllowedApplications); $script:hCfaAllowed = @($script:hCfaAllowed | Where-Object { $_ -ne $ControlledFolderAccessAllowedApplications }) }
function HRead { & $realHRead }
function HGate { }
function HPreflight { }
$script:hCfaEvents = @('C:\Tools\PhotoTool.exe', 'C:\Tools\Edit.exe')
HWrite (Input '{"items":{"app:C:\\Tools\\PhotoTool.exe":1,"app:C:\\Tools\\Edit.exe":1}}')
Assert (@($script:cfaAdded).Count -eq 2 -and @($script:hCfaAllowed).Count -eq 3) 'both apps were allowed'
Assert ($script:cfaState.ContainsKey('app:C:\Tools\PhotoTool.exe') -and $script:cfaState.ContainsKey('app:C:\Tools\Edit.exe') -and $script:cfaState.Count -eq 2) 'each allowed app is recorded'
$r = HReadCfaApps
Assert ($r['app:C:\Tools\PhotoTool.exe'] -eq 1 -and $r['app:C:\Tools\Edit.exe'] -eq 1 -and $r.Count -eq 2) 'allowed apps read 1'
HWrite (Input '{"items":{"app:C:\\Tools\\PhotoTool.exe":0,"app:C:\\Tools\\Edit.exe":0}}')
Assert (@($script:hCfaAllowed).Count -eq 1 -and $script:hCfaAllowed[0] -ceq 'D:\Apps\sync.exe' -and $script:cfaState.Count -eq 0) 'undo removes exactly the apps Secblitz added'
# Windows can ignore the change without an error (Tamper Protection): nothing is recorded as done.
function Add-MpPreference { param($ControlledFolderAccessAllowedApplications) }
$script:hCfaSeen['c:\tools\phototool.exe'] = $true
Reject { HSetCfaApp 'app:C:\Tools\PhotoTool.exe' 1 } 'Tamper Protection'
Assert (!$script:cfaState.ContainsKey('app:C:\Tools\PhotoTool.exe')) 'a refused allow is not recorded'
function Add-MpPreference { param($ControlledFolderAccessAllowedApplications); $script:hCfaAllowed = @($script:hCfaAllowed) + @($ControlledFolderAccessAllowedApplications) }
HSetCfaApp 'app:C:\Tools\PhotoTool.exe' 1
Assert ($script:cfaState.ContainsKey('app:C:\Tools\PhotoTool.exe')) 'an accepted allow is recorded'
function Remove-MpPreference { param($ControlledFolderAccessAllowedApplications) }
Reject { HSetCfaApp 'app:C:\Tools\PhotoTool.exe' 0 } 'Tamper Protection'
Assert ($script:cfaState.ContainsKey('app:C:\Tools\PhotoTool.exe')) 'a refused removal keeps the record'
function Remove-MpPreference { param($ControlledFolderAccessAllowedApplications); $script:hCfaAllowed = @($script:hCfaAllowed | Where-Object { $_ -ne $ControlledFolderAccessAllowedApplications }) }
HSetCfaApp 'app:C:\Tools\PhotoTool.exe' 0
Assert (!$script:cfaState.ContainsKey('app:C:\Tools\PhotoTool.exe')) 'an accepted removal clears the record'
Reject { HSetCfaApp 'app:D:\Apps\sync.exe' 0 } 'Unknown hardening item'
Reject { HSetCfaApp 'app:C:\Windows\System32\cmd.exe' 1 } 'Unknown hardening item'
Reject { HSetCfaApp 'app:C:\Tools\*.exe' 1 } 'Unknown hardening item'
Reject { HSetCfaApp 'app:C:\Missing\gone.exe' 1 } 'was not seen changing your files'
$script:hCfaSeen['c:\missing\gone.exe'] = $true
Reject { HSetCfaApp 'app:C:\Missing\gone.exe' 1 } 'could not be found'
Reject { HSetCfaApp 'app:C:\Tools\Edit.exe' 2 } 'Invalid allowed app state'
Reject { HSetCfaApp 'app:C:\Tools\Edit.exe' $null } 'Invalid allowed app state'
Assert (@($script:hCfaAllowed).Count -eq 1) 'refused requests change nothing'
Reject { HWrite (Input '{"items":{"app:C:\\Tools\\Gone.exe":1}}') } 'was not seen changing your files'
Assert (@($script:hCfaAllowed).Count -eq 1 -and $script:cfaState.Count -eq 0) 'an app that was never seen is not allowed'
Reject { HWrite (Input '{"items":{"cmd.exe":1}}') } 'Unknown hardening item'
function Add-MpPreference { param($ControlledFolderAccessAllowedApplications); throw 'fixture add failure' }
Reject { HSetCfaApp 'app:C:\Tools\Edit.exe' 1 } 'fixture add failure'
Assert ($script:cfaState.Count -eq 0) 'a failed allow leaves no record behind'
$script:hWanted = @{}
}

MakeSpec $svcJson
foreach ($ok in @('RemoteRegistry', 'WinRM', 'sshd', 'TlntSvr', 'FTPSVC', 'W3SVC', 'SNMP')) { Assert (HNameOk $ok) "service $ok" }
foreach ($bad in @('Spooler', 'winrm', 'WinRM ', "WinRM'; calc", '')) { Assert (!(HNameOk $bad)) "service name accepted: $bad" }
Reject { HServiceKey 'Spooler' } 'Unknown hardening item'
$script:calls = @(); $script:svcStatus = 'Running'
function Get-Service { param($Name, $ErrorAction); $o = [pscustomobject]@{ Status = $script:svcStatus }; $o | Add-Member ScriptMethod WaitForStatus { param($s, $t) }; $o | Add-Member ScriptMethod Refresh { }; return $o }
function Stop-Service { param($Name, $ErrorAction); $script:calls += ,@('stop', $Name); $script:svcStatus = 'Stopped' }
function Start-Service { param($Name, $ErrorAction); $script:calls += ,@('start', $Name); $script:svcStatus = 'Running' }
function Set-Service { param($Name, $StartupType, $ErrorAction); $script:calls += ,@('type', $Name, $StartupType) }
function New-ItemProperty { param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force, $ErrorAction); $script:calls += ,@('reg', $Name, $Value) }
HSetService 'WinRM' 4
Assert ((CallLog) -ceq 'stop:WinRM,type:WinRM:Disabled') "service stop and disable: $(CallLog)"
$script:calls = @(); $script:svcStatus = 'Stopped'
# No delayed flag was ever there: restoring plain automatic must not create one.
$script:delayedFlag = $null
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction); if ($null -eq $script:delayedFlag) { return $null }; return [pscustomobject]@{ DelayedAutostart = $script:delayedFlag } }
HSetService 'WinRM' 10
Assert ((CallLog) -ceq 'type:WinRM:Automatic,start:WinRM') "service restore automatic running leaves an absent flag absent: $(CallLog)"
$script:calls = @(); $script:svcStatus = 'Stopped'; $script:delayedFlag = 1
HSetService 'WinRM' 10
Assert ((CallLog) -ceq 'type:WinRM:Automatic,reg:DelayedAutostart:0,start:WinRM') "service restore automatic running clears a set flag: $(CallLog)"
Remove-Item -LiteralPath function:Get-ItemProperty
$script:calls = @(); $script:svcStatus = 'Stopped'
HSetService 'sshd' 13
Assert ((CallLog) -ceq 'type:sshd:Automatic,reg:DelayedAutostart:1,start:sshd') "service restore delayed running: $(CallLog)"
$script:calls = @(); $script:svcStatus = 'Stopped'
HSetService 'SNMP' 3
Assert ((CallLog) -ceq 'type:SNMP:Manual') "service restore manual stopped: $(CallLog)"
Reject { HSetService 'Spooler' 4 } 'Unknown hardening item'
Reject { HSetService 'WinRM' 1 } 'Invalid service start type'

Assert ((HMitigationValue 'ON') -eq 1 -and (HMitigationValue 'off') -eq 0 -and (HMitigationValue 'NOTSET') -eq 2) 'mitigation words'
Reject { HMitigationValue 'maybe' } 'not readable'
function Get-ProcessMitigation { param([switch]$System); return [pscustomobject]@{ DEP = [pscustomobject]@{ Enable = 'ON' }; SEHOP = [pscustomobject]@{ Enable = 'NOTSET' }; ASLR = [pscustomobject]@{ BottomUp = 'OFF'; HighEntropy = 'ON' }; CFG = [pscustomobject]@{ Enable = 'ON' } } }
$r = HReadMitigations
Assert ($r['DEP'] -eq 1 -and $r['SEHOP'] -eq 2 -and $r['BottomUp'] -eq 0 -and $r['HighEntropy'] -eq 1 -and $r['CFG'] -eq 1) 'mitigation slice'
$script:calls = @()
function Set-ProcessMitigation { param([switch]$System, $Enable, $Disable, $ErrorAction); if ($Enable) { $script:calls += ,@('on', $Enable) } else { $script:calls += ,@('off', $Disable) } }
HSetMitigation 'BottomUp' 1; HSetMitigation 'CFG' 0
Assert ((CallLog) -ceq 'on:BottomUp,off:CFG') "mitigation setters: $(CallLog)"
Reject { HSetMitigation 'ForceRelocateImages' 1 } 'Unknown hardening item'
Reject { HSetMitigation 'DEP' 2 } 'Invalid exploit protection state'

Assert ((HV2Value 'Enabled') -eq 1 -and (HV2Value 'EnablePending') -eq 1 -and (HV2Value 'Disabled') -eq 0 -and (HV2Value 'DisabledWithPayloadRemoved') -eq 0 -and (HV2Value 'Missing') -eq 0) 'feature state words'
Reject { HV2Value 'Weird' } 'not readable'
$script:features = @(1..6 | ForEach-Object { [pscustomobject]@{ FeatureName = "Filler$_"; State = 'Enabled' } }) + @([pscustomobject]@{ FeatureName = 'MicrosoftWindowsPowerShellV2Root'; State = 'Enabled' })
function Get-CimInstance {
    param($ClassName, $Filter, $OperationTimeoutSec)
    if ($ClassName -cne 'Win32_OptionalFeature') { throw "Unexpected probe $ClassName" }
    $rows = @($script:features | ForEach-Object { [pscustomobject]@{ Name = $_.FeatureName; InstallState = [uint32]$(switch ($_.State) { 'Enabled' { 1 } 'Disabled' { 2 } default { 3 } }) } })
    if (!$Filter) { return $rows }
    if ($Filter -cnotmatch "^Name='([A-Za-z0-9-]+)'$") { throw 'Unexpected feature filter' }
    $name = $Matches[1]
    return @($rows | Where-Object { $_.Name -ceq $name })
}
Assert ((HFeatureState 'MicrosoftWindowsPowerShellV2Root') -ceq 'Enabled') 'feature state'
Assert ((HFeatureState 'Recall') -ceq 'Missing') 'unknown feature in a healthy list is missing'
Assert ((HReadPowerShellV2)['Enabled'] -eq 1) 'root enabled'
$script:features = @(1..6 | ForEach-Object { [pscustomobject]@{ FeatureName = "Filler$_"; State = 'Enabled' } })
Assert ((HReadPowerShellV2)['Enabled'] -eq 0) 'missing feature is protected'
$script:features = @()
Reject { HReadPowerShellV2 } 'not readable'
$script:features = @(1..6 | ForEach-Object { [pscustomobject]@{ FeatureName = "Filler$_"; State = 'Enabled' } }) + @([pscustomobject]@{ FeatureName = 'MicrosoftWindowsPowerShellV2Root'; State = 'Disabled' })
Assert ((HReadPowerShellV2)['Enabled'] -eq 0) 'disabled root'
Reject { HFeatureState "x' or Name like '%" } 'Invalid feature name'
$script:features = @(1..6 | ForEach-Object { [pscustomobject]@{ FeatureName = "Filler$_"; State = 'Enabled' } }) + @([pscustomobject]@{ FeatureName = 'MicrosoftWindowsPowerShellV2Root'; State = 'DisabledWithPayloadRemoved' })
Assert ((HReadPowerShellV2)['Enabled'] -eq 0) 'payload removed is off'
$script:features = @(1..6 | ForEach-Object { [pscustomobject]@{ FeatureName = "Filler$_"; State = 'Enabled' } }) + @([pscustomobject]@{ FeatureName = 'MicrosoftWindowsPowerShellV2Root'; State = 'Disabled' })
$script:calls = @()
function Disable-WindowsOptionalFeature { param([switch]$Online, $FeatureName, [switch]$NoRestart, $ErrorAction); $script:calls += ,@('disable', $FeatureName) }
function Enable-WindowsOptionalFeature { param([switch]$Online, $FeatureName, [switch]$All, [switch]$NoRestart, $ErrorAction); $script:calls += ,@('enable', $FeatureName) }
HSetPowerShellV2 0
Assert ((CallLog) -ceq '') 'nothing to disable when already disabled'
HSetPowerShellV2 1
Assert ((CallLog) -ceq 'enable:MicrosoftWindowsPowerShellV2Root,enable:MicrosoftWindowsPowerShellV2') "feature undo: $(CallLog)"

$planId = '381b4222-f694-41f0-9685-ff5bb260df2e'
$script:power = @{ ac = 0; dc = 0; hasDc = $true }
function Get-CimInstance {
    param($ClassName, $Namespace)
    switch ($ClassName) {
        'Win32_PowerPlan' { return @([pscustomobject]@{ IsActive = $false; InstanceID = 'Microsoft:PowerPlan\{aaaaaaaa-0000-0000-0000-000000000000}' }, [pscustomobject]@{ IsActive = $true; InstanceID = "Microsoft:PowerPlan\{$planId}" }) }
        'Win32_PowerSettingDataIndex' {
            $list = @([pscustomobject]@{ InstanceID = "Microsoft:PowerSettingDataIndex\{$planId}\AC\{11111111-1111-1111-1111-111111111111}"; SettingIndexValue = [uint32]7 })
            $list += [pscustomobject]@{ InstanceID = "Microsoft:PowerSettingDataIndex\{$planId}\AC\{0e796bdb-100d-47d6-a2d5-f7d2daa51f51}"; SettingIndexValue = [uint32]$script:power.ac }
            if ($script:power.hasDc) { $list += [pscustomobject]@{ InstanceID = "Microsoft:PowerSettingDataIndex\{$planId}\DC\{0E796BDB-100D-47D6-A2D5-F7D2DAA51F51}"; SettingIndexValue = [uint32]$script:power.dc } }
            return $list
        }
        default { throw "Unexpected probe $ClassName" }
    }
}
$r = HReadLockOnWake
Assert ($r['Ac'] -eq 0 -and $r['Dc'] -eq 0) 'wake lock slice'
$script:power = @{ ac = 1; dc = 0; hasDc = $true }
$r = HReadLockOnWake
Assert ($r['Ac'] -eq 1 -and $r['Dc'] -eq 0) 'wake lock slice ac on'
$script:power = @{ ac = 1; dc = 0; hasDc = $false }
Assert ((HReadLockOnWake)['Dc'] -eq 1) 'a missing battery setting mirrors the plugged-in one'
$script:power = @{ ac = 5; dc = 0; hasDc = $true }
Reject { HReadLockOnWake } 'not readable'
$script:calls = @()
function Set-CimInstance { param($InputObject, $ErrorAction); $script:calls += ,@('set', [string]$InputObject.SettingIndexValue) }
function Invoke-CimMethod { param($InputObject, $MethodName, $ErrorAction); $script:calls += ,@('invoke', $MethodName) }
$script:power = @{ ac = 0; dc = 0; hasDc = $true }
HSetLockOnWake 'Dc' 1
Assert ((CallLog) -ceq 'set:1,invoke:Activate') "wake lock write: $(CallLog)"
Reject { HSetLockOnWake 'Other' 1 } 'Unknown hardening item'
Reject { HSetLockOnWake 'Ac' 2 } 'Invalid sign-in-on-wake value'

MakeSpec $pauseJson
$script:fakeFs = $true
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings')
$ts = "yyyy-MM-dd'T'HH:mm:ss'Z'"
$future = [DateTimeOffset]::UtcNow.AddDays(10).UtcDateTime.ToString($ts, [Globalization.CultureInfo]::InvariantCulture)
$past = [DateTimeOffset]::UtcNow.AddDays(-10).UtcDateTime.ToString($ts, [Globalization.CultureInfo]::InvariantCulture)
$nowSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$script:fakeKey = ValueKey @{ PauseUpdatesExpiryTime = $future; PauseFeatureUpdatesEndTime = $future; PauseFeatureUpdatesStartTime = $past }
$r = HReadPause
Assert (($r['PauseUpdatesExpiryTime'] * 60) -gt $nowSeconds -and $r['PauseQualityUpdatesEndTime'] -eq 0 -and $r['PauseFeatureUpdatesStartTime'] -gt 0) 'active pause lists every saved time'
Assert (HAnyUnsafe $r) 'an active pause is unsafe'
$script:fakeKey = ValueKey @{ PauseUpdatesExpiryTime = $past; PauseFeatureUpdatesStartTime = $past }
$r = HReadPause
Assert (!(HAnyUnsafe $r) -and $r['PauseFeatureUpdatesStartTime'] -eq 0) 'an expired pause is not paused'
$script:fakeKey = ValueKey @{ PauseUpdatesExpiryTime = 'not a date' }
Reject { HReadPause } 'is not a date'
$script:fakeKey = ValueKey @{ PauseUpdatesExpiryTime = 5 }
Reject { HReadPause } 'is not text'
$script:fakePaths = @()
Assert (!(HAnyUnsafe (HReadPause))) 'no settings key means no pause'
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings')
$script:fakeKey = ValueKey @{ PauseUpdatesExpiryTime = $future }
$script:calls = @()
function Remove-ItemProperty { param($LiteralPath, $Name, $ErrorAction); $script:calls += ,@('remove', $Name) }
$pauseDef = HDef 'PauseUpdatesExpiryTime'
HSetPause $pauseDef 0
Assert ((CallLog) -ceq 'remove:PauseUpdatesExpiryTime') "pause removed: $(CallLog)"
$script:calls = @()
$minutes = [int64][Math]::Floor(([DateTimeOffset]::UtcNow.AddDays(10).ToUnixTimeSeconds()) / 60)
$script:hWanted = @{ PauseUpdatesExpiryTime = $minutes }
HSetPause $pauseDef $minutes
Assert ($script:calls.Count -eq 1 -and $script:calls[0][0] -ceq 'reg' -and $script:calls[0][2] -cmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$') "pause restored in Windows' own format: $(CallLog)"
$script:calls = @()
$script:hWanted = @{ PauseUpdatesExpiryTime = 100 }
HSetPause $pauseDef 100
Assert ($script:calls.Count -eq 0) 'a pause that already ended is not written back'
Assert (HVerified 'PauseUpdatesExpiryTime' 0 100) 'an ended pause may read back as nothing'
$script:hWanted = @{ PauseUpdatesExpiryTime = $minutes }
Assert (!(HVerified 'PauseUpdatesExpiryTime' 0 $minutes)) 'a pause still in force must read back'
$script:hWanted = @{}
$script:fakeFs = $false

MakeSpec $ssJson
$script:fakeFs = $true
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System')
$script:fakeKey = ValueKey @{ SmartScreenEnabled = 'Off'; EnableSmartScreen = 0 }
$r = HReadSmartScreen
Assert ($r['SmartScreenEnabled'] -eq 0 -and $r['EnableSmartScreen'] -eq 0 -and (HAnyUnsafe $r)) 'smartscreen off by setting and by policy'
$script:fakeKey = ValueKey @{ SmartScreenEnabled = 'warn' }
$r = HReadSmartScreen
Assert ($r['SmartScreenEnabled'] -eq 1 -and $null -eq $r['EnableSmartScreen'] -and !(HAnyUnsafe $r)) 'warn is protected and an absent policy is protected'
$script:fakeKey = ValueKey @{ RequireAdminOnly = 1 }
$r = HReadSmartScreen
Assert ($null -eq $r['SmartScreenEnabled'] -and !(HAnyUnsafe $r)) 'absent setting is the Windows default'
$script:fakeKey = ValueKey @{ SmartScreenEnabled = 'Strange' }
Reject { HReadSmartScreen } 'not recognised'
$script:fakeKey = ValueKey @{ SmartScreenEnabled = 1 }
Reject { HReadSmartScreen } 'not text'
$script:fakeFs = $false
$script:calls = @()
function Test-Path { param($LiteralPath, $ErrorAction); return $true }
HSetSmartScreen (HDef 'SmartScreenEnabled') 1
HSetSmartScreen (HDef 'SmartScreenEnabled') 0
Assert ((CallLog) -ceq 'reg:SmartScreenEnabled:Warn,reg:SmartScreenEnabled:Off') "smartscreen words: $(CallLog)"
Reject { HSetSmartScreen (HDef 'SmartScreenEnabled') 7 } 'Invalid SmartScreen setting'
$script:calls = @()
HSetSmartScreen (HDef 'EnableSmartScreen') $null
Assert ((CallLog) -ceq 'remove:EnableSmartScreen') "policy value removed: $(CallLog)"

# Lock-out safety: a lockout length of 0 or "forever" is not offered.
MakeSpec '{"id":"accounts.lockout_policy","source":"Lockout","dynamic":true,"reboot":false,"keys":[]}'
foreach ($duration in @(0, -1)) {
    $script:lockDuration = $duration
    function HLockoutInfo { return @($script:lockDuration, 1800, 0) }
    Reject { HPreflight } 'would stay locked until an administrator unlocks it'
}
$script:lockDuration = 1800
HPreflight
Remove-Item -LiteralPath function:HLockoutInfo
# Spooler: restart only when nothing is queued, except when applying (preflight already said idle).
# The spool folder falls back to %SystemRoot%; give it one when these tests run off Windows.
if (!$env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
$script:queueItems = @(); $script:queueFails = $false; $script:restarts = 0
function Get-ChildItem { param($LiteralPath, [switch]$Force, $ErrorAction); if ($script:queueFails) { throw 'denied' }; return $script:queueItems }
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction); return $null }
function Get-Service { param($Name, $ErrorAction); return [pscustomobject]@{ Status = 'Running' } }
function Restart-Service { param($Name, [switch]$Force, $ErrorAction); $script:restarts++ }
MakeSpec '{"id":"printer.spooler_remote","source":"Registry","dynamic":false,"reboot":false,"keys":[]}'
$spoolDef = [pscustomobject]@{ rule = 'set'; safe = @(2); absentSafe = $false }
Assert (!(HPrintBusy)) 'empty queue is idle'
$script:queueItems = @('job.SPL'); Assert (HPrintBusy) 'a queued job is busy'
$script:queueItems = @(); $script:queueFails = $true; Assert (HPrintBusy) 'unreadable queue counts as busy'
$script:queueFails = $false
HAfterRegistry $spoolDef 2; Assert ($script:restarts -eq 1) 'apply restarts an idle spooler'
$script:queueItems = @('job.SPL')
HAfterRegistry $spoolDef $null; Assert ($script:restarts -eq 1) 'undo leaves a busy spooler running'
HAfterRegistry $spoolDef 2; Assert ($script:restarts -eq 2) 'apply still restarts (preflight blocks a busy queue)'
$script:queueItems = @()
HAfterRegistry $spoolDef $null; Assert ($script:restarts -eq 3) 'undo restarts an idle spooler'
Remove-Item -LiteralPath function:Get-Service, function:Restart-Service
function Get-ItemProperty { Microsoft.PowerShell.Management\Get-ItemProperty @args }
function Get-ChildItem { Microsoft.PowerShell.Management\Get-ChildItem @args }
$alJson = '{"id":"accounts.autologon","source":"WinlogonAutoLogon","dynamic":false,"reboot":false,"keys":[{"name":"AutoAdminLogon","path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","rule":"set","safe":[0],"absentSafe":true,"fix":0,"max":1}],' + $noGate + '}'
MakeSpec $alJson
function Test-Path { param($LiteralPath, $ErrorAction); if ($script:fakeFs) { return ($script:fakePaths -contains $LiteralPath) }; return $true }
function Get-Item { param($LiteralPath, $ErrorAction); return $script:fakeKey }
$script:fakeFs = $true; $script:fakePaths = @()
function GuardedKey($map) {
    $k = ValueKey $map
    # Reading anything but AutoAdminLogon (saved password, user name) fails the test.
    $k | Add-Member -Force ScriptMethod GetValue { param($n) if ($n -cne 'AutoAdminLogon') { throw "must not read $n" }; return $this.Map[$n] }
    return $k
}
$script:fakeKey = GuardedKey @{ AutoAdminLogon = '1'; DefaultPassword = 'secret'; DefaultUserName = 'bob'; AutoLogonCount = 3 }
$r = HReadAutoLogon
Assert ($r['AutoAdminLogon'] -eq 1 -and (HAnyUnsafe $r)) 'automatic sign-in on is unsafe'
$script:fakeKey = GuardedKey @{ AutoAdminLogon = '0'; DefaultPassword = 'secret' }
$r = HReadAutoLogon
Assert ($r['AutoAdminLogon'] -eq 0 -and !(HAnyUnsafe $r)) 'automatic sign-in off is protected'
$script:fakeKey = GuardedKey @{ DefaultUserName = 'bob' }
$r = HReadAutoLogon
Assert ($null -eq $r['AutoAdminLogon'] -and !(HAnyUnsafe $r)) 'an absent value is protected'
$script:fakeKey = GuardedKey @{ AutoAdminLogon = 1 }
Reject { HReadAutoLogon } 'not text'
$script:fakeKey = GuardedKey @{ AutoAdminLogon = 'maybe' }
Reject { HReadAutoLogon } 'unknown setting'
Assert ((HFixOf (HDef 'AutoAdminLogon') 1) -eq 0) 'only 1 is repaired, to 0'
$script:calls = @()
function New-ItemProperty { param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force, $ErrorAction); $script:calls += ,@('new', $Name, $PropertyType, $Value) }
function Remove-ItemProperty { param($LiteralPath, $Name, $ErrorAction); $script:calls += ,@('remove', $Name) }
HSetAutoLogon 'AutoAdminLogon' 0
HSetAutoLogon 'AutoAdminLogon' 1
HSetAutoLogon 'AutoAdminLogon' $null
Assert ((CallLog) -ceq 'new:AutoAdminLogon:String:0,new:AutoAdminLogon:String:1,remove:AutoAdminLogon') "autologon writes: $(CallLog)"
Reject { HSetAutoLogon 'DefaultPassword' 0 } 'Unknown hardening item'
Reject { HSetAutoLogon 'AutoAdminLogon' 2 } 'Invalid automatic sign-in setting'
$script:fakeFs = $false

$rdJson = '{"id":"remote_desktop.disabled","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"fDenyTSConnections","path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server","rule":"set","safe":[1],"absentSafe":true,"fix":1,"max":1}],"gate":{"areas":["RemoteDesktopServices"],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[{"path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","name":"fDenyTSConnections"}]}}'
MakeSpec $rdJson
Assert (HIsSafe (HDef 'fDenyTSConnections') 1) 'denying connections is protected'
Assert (!(HIsSafe (HDef 'fDenyTSConnections') 0)) 'allowing connections is unsafe'
Assert ((HFixOf (HDef 'fDenyTSConnections') 0) -eq 1) 'repair denies connections'
$oldSession = $env:SESSIONNAME
$env:SESSIONNAME = 'RDP-Tcp#3'
Assert (HRemoteSessionActive) 'a Remote Desktop session is recognised'
$env:SESSIONNAME = $oldSession
function HRemoteSessionActive { return $script:remote }
$script:remote = $false
$script:edition = 'Professional'
function Get-ItemProperty { param($LiteralPath, $Name, $ErrorAction); return [pscustomobject]@{ EditionID = $script:edition } }
HPreflight
Assert $true 'offered on a local session of a capable edition'
$script:remote = $true
Reject { HPreflight } 'you are connected to this computer from another device right now'
$script:remote = $false
foreach ($ed in @('Core', 'CoreSingleLanguage', 'CoreN')) {
    $script:edition = $ed
    Reject { HPreflight } 'Windows Home cannot accept Remote Desktop connections'
}

$webRule = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{0EE85A24-B573-4712-97FF-CC4BC51D8757}'
MakeSpec '{"id":"browser.dns_bypass","source":"Registry","dynamic":false,"reboot":false,"keys":[]}'
$script:fakeFs = $true; $script:fakePaths = @()
Reject { HPreflight } 'Web protection is off'
$script:fakePaths = @($webRule)
HPreflight
$script:fakeFs = $false; $script:fakePaths = @()

# Optional switches: values that sibling controls keep in one policy key, installed-app checks and edition checks.
$aiOwn = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
$aiPath = $aiOwn.Replace('\', '\\')
$sharedJson = '{"id":"privacy.recall","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"DisableAIDataAnalysis","path":"' + $aiPath + '","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"' + $aiPath + '","sharedValues":["DisableClickToDo"],"policyValues":[]}}'
$plainJson = $sharedJson.Replace('"sharedValues":["DisableClickToDo"],', '')
if (!$env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
$script:fakeFs = $true
$script:fakePaths = @($aiOwn)
MakeSpec $sharedJson
$script:fakeKey = FakeKey @('DisableAIDataAnalysis', 'DisableClickToDo')
HGatePolicy
Assert $true 'a sibling control value in the shared policy key is not management'
$script:fakeKey = FakeKey @('DisableAIDataAnalysis', 'DisableClickToDo', 'TurnOffWindowsCopilot')
Reject { HGatePolicy } 'Relevant policy is configured'
MakeSpec $plainJson
$script:fakeKey = FakeKey @('DisableAIDataAnalysis')
HGatePolicy
Assert $true 'a spec written without shared values still gates on its own values'
$script:fakeKey = FakeKey @('DisableAIDataAnalysis', 'DisableClickToDo')
Reject { HGatePolicy } 'Relevant policy is configured'
$script:fakePaths = @(); $script:fakeFs = $false

# Run box: NoRun shares the Explorer policy key with unrelated values, so the spec has no own key and those neighbours are not management.
$explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$runJson = '{"id":"clickfix.run_box","source":"Registry","dynamic":false,"reboot":false,"keys":[{"name":"NoRun","path":"' + $explorerPath.Replace('\', '\\') + '","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","sharedValues":[],"policyValues":[]}}'
$script:fakeFs = $true
$script:fakePaths = @($explorerPath)
MakeSpec $runJson
$script:fakeKey = FakeKey @('NoRun', 'NoAutorun', 'NoDriveTypeAutoRun', 'NoControlPanel')
HGatePolicy
Assert $true 'unrelated values in the Explorer policy key do not block the Run box switch'
$script:fakePaths = @(); $script:fakeFs = $false

$pkgRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications'
$script:pkgNames = @(); $script:pkgRootExists = $true
$savedTestPath = ${function:Test-Path}; $savedChildItem = ${function:Get-ChildItem}; $savedCim = ${function:Get-CimInstance}
function Test-Path { param($LiteralPath, $ErrorAction); return ($LiteralPath -ceq $pkgRoot -and $script:pkgRootExists) }
function Get-ChildItem { param($LiteralPath, [switch]$Name, $ErrorAction); Assert ($LiteralPath -ceq $pkgRoot -and $Name) 'Installed apps were listed from an unexpected place'; return @($script:pkgNames) }
Assert (!(HPackageInstalled 'Microsoft.Paint')) 'no apps listed means Paint is missing'
$script:pkgNames = @('Microsoft.MSPaint_6.2.0.0_x64__8wekyb3d8bbwe', 'Microsoft.Paint.Beta_1.0.0.0_x64__8wekyb3d8bbwe')
Assert (!(HPackageInstalled 'Microsoft.Paint')) 'other apps with a similar name are not Paint'
$script:pkgNames += 'Microsoft.Paint_11.2605.81.0_neutral_~_8wekyb3d8bbwe'
Assert (HPackageInstalled 'Microsoft.Paint') 'Paint is found by its package name'
$script:pkgNames = @('microsoft.windowsnotepad_11.2607.14.0_neutral_~_8wekyb3d8bbwe')
Assert (HPackageInstalled 'Microsoft.WindowsNotepad') 'package names match without regard to case'
$script:pkgRootExists = $false
Reject { HPackageInstalled 'Microsoft.Paint' } 'could not be listed'
$script:pkgRootExists = $true

MakeSpec '{"id":"ai.paint","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}'
$script:pkgNames = @()
Reject { HPreflight } 'Paint was not found on this computer'
$script:pkgNames = @('Microsoft.Paint_11.2605.81.0_neutral_~_8wekyb3d8bbwe')
HPreflight
Assert $true 'offered where Paint is installed'
MakeSpec '{"id":"ai.notepad","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}'
Reject { HPreflight } 'Notepad was not found on this computer'
$script:pkgNames = @('Microsoft.WindowsNotepad_11.2508.38.0_x64__8wekyb3d8bbwe')
HPreflight
Assert $true 'offered where the Notepad app is installed'

function Get-CimInstance { param($ClassName); return [pscustomobject]@{ BuildNumber = $script:build } }
MakeSpec '{"id":"ai.click_to_do","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}'
$script:build = '22631'
Reject { HPreflight } 'this version of Windows does not have it'
$script:build = '26100'
HPreflight
Assert $true 'offered on a version of Windows that has Click to Do'

${function:Test-Path} = $savedTestPath; ${function:Get-ChildItem} = $savedChildItem; ${function:Get-CimInstance} = $savedCim
MakeSpec '{"id":"debloat.widgets_policy","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}'
function Get-Service { param($Name, $ErrorAction); Assert ($Name -ceq 'UCPD') 'Only the user choice protection driver is asked about'; if ($null -eq $script:ucpd) { return $null }; return [pscustomobject]@{ Status = $script:ucpd } }
$script:edition = 'Professional'
$script:ucpd = $null
HPreflight
Assert $true 'Widgets can be turned off on Pro'
$script:ucpd = 'Stopped'
HPreflight
Assert $true 'a stopped protection driver does not block the switch'
$script:ucpd = 'Running'
Reject { HPreflight } 'Windows keeps this setting for you to change yourself'
$script:ucpd = $null
foreach ($ed in @('Core', 'CoreSingleLanguage', 'CoreN')) {
    $script:edition = $ed
    Reject { HPreflight } 'not available on Windows Home'
}
Remove-Item -LiteralPath function:Get-Service
MakeSpec '{"id":"debloat.device_companion_apps","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}'
HPreflight
Assert $true 'device companion apps have no extra requirement'
foreach ($privacyId in @('privacy.online_speech','privacy.typing_inking','privacy.lock_screen_notifications','privacy.signin_email')) {
    MakeSpec ('{"id":"' + $privacyId + '","source":"Registry","dynamic":false,"reboot":false,"keys":[],"gate":{}}')
    $script:edition = 'Professional'
    HPreflight
    Assert $true ($privacyId + ' is offered on Pro')
    foreach ($ed in @('Core', 'CoreSingleLanguage', 'CoreN')) {
        $script:edition = $ed
        Reject { HPreflight } 'not available on Windows Home'
    }
}
$script:edition = 'Professional'


$smbNames = @('SMB1Protocol', 'SMB1Protocol-Client', 'SMB1Protocol-Server', 'SMB1Protocol-Deprecation')
$smbKeys = $smbNames | ForEach-Object {
    '{"name":"' + $_ + '","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}'
}
$smbJson = '{"id":"smb1.disabled","source":"SmbFeature","dynamic":false,"reboot":true,"keys":[' + ($smbKeys -join ',') + '],' + $noGate + '}'
MakeSpec $smbJson
# What Windows reports (one query for all parts) and what is pending a restart.
function SmbFeatures([string]$root, [string]$client, [string]$server, [string]$deprecation = 'Disabled') {
    $script:smbState = @{ 'SMB1Protocol' = $root; 'SMB1Protocol-Client' = $client; 'SMB1Protocol-Server' = $server; 'SMB1Protocol-Deprecation' = $deprecation }
}
function SmbCode([string]$state) { switch ($state) { 'Enabled' { return 1 } 'Disabled' { return 2 } default { return 3 } } }
$script:cimQueries = 0
function Get-CimInstance {
    param($ClassName, $Filter, $OperationTimeoutSec)
    if ($ClassName -cne 'Win32_OptionalFeature') { throw "Unexpected probe $ClassName" }
    $script:cimQueries++
    $rows = @(1..6 | ForEach-Object { [pscustomobject]@{ Name = "Filler$_"; InstallState = [uint32]1 } })
    foreach ($n in @($script:smbState.Keys)) {
        if ($script:smbState[$n] -cne 'Missing') { $rows += [pscustomobject]@{ Name = $n; InstallState = [uint32](SmbCode $script:smbState[$n]) } }
    }
    if (!$Filter) { return $rows }
    if ($Filter -ceq "Name LIKE 'SMB1Protocol%'") { return @($rows | Where-Object { $_.Name -clike 'SMB1Protocol*' }) }
    if ($Filter -cnotmatch "^Name='([A-Za-z0-9-]+)'$") { throw 'Unexpected feature filter' }
    $name = $Matches[1]
    return @($rows | Where-Object { $_.Name -ceq $name })
}
$script:notes = @{}; $script:noteFails = $false
function HSmbNoteGet([string]$name) { if ($script:notes.ContainsKey($name)) { return [int]$script:notes[$name] }; return $null }
function HSmbNotePut([string]$name, $want) {
    if ($script:noteFails) { throw 'note fixture failure' }
    if ($null -eq $want) { $script:notes.Remove($name) } else { $script:notes[$name] = [string][int]$want }
}
$script:calls = @(); $script:restart = $true; $script:parentBringsBack = $false; $script:sawLimit = $true
function Disable-WindowsOptionalFeature { param([switch]$Online, $FeatureName, [switch]$NoRestart, $ErrorAction); $script:calls += ,@('disable', $FeatureName); if (!$script:restart) { $script:smbState[$FeatureName] = 'Disabled' }; return [pscustomobject]@{ RestartNeeded = $script:restart } }
function Enable-WindowsOptionalFeature {
    param([switch]$Online, $FeatureName, [switch]$NoRestart, [switch]$LimitAccess, $ErrorAction)
    $script:calls += ,@('enable', $FeatureName)
    if (!$LimitAccess) { $script:sawLimit = $false }
    if (!$script:restart) { $script:smbState[$FeatureName] = 'Enabled' }
    if ($script:parentBringsBack -and $FeatureName -ceq 'SMB1Protocol') { $script:smbState['SMB1Protocol-Deprecation'] = 'Enabled' }
    return [pscustomobject]@{ RestartNeeded = $script:restart }
}

SmbFeatures 'Enabled' 'Enabled' 'Disabled' 'Enabled'
$script:cimQueries = 0
$r = HReadSmb1
Assert ($r['SMB1Protocol'] -eq 1 -and $r['SMB1Protocol-Client'] -eq 1 -and $r['SMB1Protocol-Server'] -eq 0 -and $r['SMB1Protocol-Deprecation'] -eq 1 -and (HAnyUnsafe $r) -and !$script:hSmb1Unreadable) 'only the parts that are on are listed as on'
Assert ($script:cimQueries -eq 1) "one query reads every part: $script:cimQueries"
SmbFeatures 'Disabled' 'Missing' 'Disabled' 'Missing'
$r = HReadSmb1
Assert (!(HAnyUnsafe $r)) 'disabled or absent parts are protected'
# A feature list that cannot be read is never treated as protected.
$script:smbState = @{}
function Get-CimInstance { param($ClassName, $Filter, $OperationTimeoutSec); return @() }
$r = HReadSmb1
Assert ($script:hSmb1Unreadable -and (HAnyUnsafe $r)) 'an unreadable feature list is flagged and looks unsafe'
Reject { HPreflight } 'the old file-sharing version could not be checked'
function Get-CimInstance {
    param($ClassName, $Filter, $OperationTimeoutSec)
    $rows = @(1..6 | ForEach-Object { [pscustomobject]@{ Name = "Filler$_"; InstallState = [uint32]1 } })
    foreach ($n in @($script:smbState.Keys)) { if ($script:smbState[$n] -cne 'Missing') { $rows += [pscustomobject]@{ Name = $n; InstallState = [uint32](SmbCode $script:smbState[$n]) } } }
    if (!$Filter) { return $rows }
    if ($Filter -ceq "Name LIKE 'SMB1Protocol%'") { return @($rows | Where-Object { $_.Name -clike 'SMB1Protocol*' }) }
    $name = ([regex]::Match($Filter, "^Name='([A-Za-z0-9-]+)'$")).Groups[1].Value
    return @($rows | Where-Object { $_.Name -ceq $name })
}
# Live use of the old version blocks the change.
SmbFeatures 'Enabled' 'Enabled' 'Enabled' 'Enabled'
$null = HReadSmb1
function Get-SmbConnection { param($ErrorAction); return @([pscustomobject]@{ Dialect = $script:dialect }) }
function Get-SmbSession { param($ErrorAction); return @() }
$script:dialect = '3.1.1'
HPreflight
Assert $true 'modern connections do not block'
$script:dialect = '1.50'
Reject { HPreflight } 'something is using the old file sharing right now'
function Get-SmbConnection { param($ErrorAction); throw 'not available' }
HPreflight
Assert $true 'an unreadable connection list does not block'

SmbFeatures 'Enabled' 'Enabled' 'Disabled'
$script:calls = @(); $script:notes = @{}
HSetSmb1 'SMB1Protocol-Server' 0
Assert ((CallLog) -ceq '') 'a part that is already off is not touched'
HSetSmb1 'SMB1Protocol-Client' 0
Assert ((CallLog) -ceq 'disable:SMB1Protocol-Client') "part turned off: $(CallLog)"
Assert ($script:notes['SMB1Protocol-Client'] -ceq '0') 'the change that needs a restart is noted'
$r = HReadSmb1
Assert ($r['SMB1Protocol-Client'] -eq 0 -and $r['SMB1Protocol'] -eq 1) 'until the restart the note says what was asked for'
$script:notes = @{}
$r = HReadSmb1
Assert ($r['SMB1Protocol-Client'] -eq 1) 'after a restart the note is gone and Windows is believed'
SmbFeatures 'Disabled' 'Disabled' 'Disabled'
$script:calls = @(); $script:notes = @{}; $script:sawLimit = $true
HSetSmb1 'SMB1Protocol' 1
HSetSmb1 'SMB1Protocol-Client' 1
Assert ((CallLog) -ceq 'enable:SMB1Protocol,enable:SMB1Protocol-Client') "undo turns parts back on one by one: $(CallLog)"
Assert $script:sawLimit 'turning a part back on never goes online'
$script:restart = $false
SmbFeatures 'Enabled' 'Disabled' 'Disabled'
$script:notes = @{ 'SMB1Protocol' = '1' }
HSetSmb1 'SMB1Protocol' 0
Assert (!$script:notes.ContainsKey('SMB1Protocol')) 'a change that needs no restart leaves no note'
Reject { HSetSmb1 'SMB1Protocol-Other' 0 } 'Unknown hardening item'
Reject { HSetSmb1 'SMB1Protocol' 2 } 'Invalid feature state'
# If the note cannot be kept, the change is put back before the error is raised.
$script:restart = $true; $script:noteFails = $true
SmbFeatures 'Enabled' 'Disabled' 'Disabled'
$script:calls = @(); $script:notes = @{}
Reject { HSetSmb1 'SMB1Protocol' 0 } 'note fixture failure'
Assert ((CallLog) -ceq 'disable:SMB1Protocol,enable:SMB1Protocol') "a part whose note failed is turned back: $(CallLog)"
$script:noteFails = $false

function HRead { return (HReadSmb1) }
function HSet([string]$name, $v) { HSetSmb1 $name $v }
function HPreflight { }
function HGate { }
$script:restart = $true
SmbFeatures 'Enabled' 'Enabled' 'Enabled' 'Enabled'
$script:calls = @(); $script:notes = @{}
HWrite (Input '{"items":{"SMB1Protocol":0,"SMB1Protocol-Client":0,"SMB1Protocol-Server":0,"SMB1Protocol-Deprecation":0}}')
Assert ((CallLog) -ceq 'disable:SMB1Protocol-Server,disable:SMB1Protocol-Deprecation,disable:SMB1Protocol-Client,disable:SMB1Protocol') "turning off goes children first: $(CallLog)"
# Undo: the recorded-on parts come back parent first; a part that was off stays off.
SmbFeatures 'Disabled' 'Disabled' 'Disabled' 'Disabled'
$script:calls = @(); $script:notes = @{}; $script:parentBringsBack = $false
HWrite (Input '{"items":{"SMB1Protocol":1,"SMB1Protocol-Client":1,"SMB1Protocol-Server":0,"SMB1Protocol-Deprecation":1}}')
Assert ((CallLog) -ceq 'enable:SMB1Protocol,enable:SMB1Protocol-Client,enable:SMB1Protocol-Deprecation') "turning on goes parent first: $(CallLog)"
SmbFeatures 'Disabled' 'Disabled' 'Disabled' 'Disabled'
$script:calls = @(); $script:notes = @{}; $script:parentBringsBack = $true
HWrite (Input '{"items":{"SMB1Protocol":1,"SMB1Protocol-Client":1,"SMB1Protocol-Server":0,"SMB1Protocol-Deprecation":0}}')
Assert ((CallLog) -ceq 'enable:SMB1Protocol,enable:SMB1Protocol-Client,disable:SMB1Protocol-Deprecation') "a part that came back by itself is turned off again: $(CallLog)"
$script:parentBringsBack = $false

MakeSpec $alJson
${function:HPreflight} = $realHPreflight
$script:kioskKey = $null
function Test-Path { param($LiteralPath, $ErrorAction); if ($LiteralPath -clike '*AssignedAccessConfiguration') { return ($null -ne $script:kioskKey) }; return $true }
function Get-Item { param($LiteralPath, $ErrorAction); return $script:kioskKey }
function KioskKey($values, $subs) {
    # $subs: name -> KioskKey, or name -> $null for a folder that cannot be opened.
    $k = [pscustomobject]@{ V = $values; S = $subs; Closed = 0 }
    $k | Add-Member ScriptMethod GetValueNames { return @($this.V) }
    $k | Add-Member ScriptMethod GetSubKeyNames { return @($this.S.Keys) }
    $k | Add-Member ScriptMethod OpenSubKey { param($n) return $this.S[$n] }
    $k | Add-Member ScriptMethod Close { $this.Closed++ }
    return $k
}
function StockKiosk { $s = [ordered]@{}; foreach ($n in 'Configs','GroupConfigs','Profiles','RawData') { $s[$n] = KioskKey @() ([ordered]@{}) }; return $s }
HPreflight
Assert $true 'offered when no kiosk is set up'
$script:kioskKey = KioskKey @() ([ordered]@{})
HPreflight
Assert $true 'an empty kiosk key does not block'
$stock = StockKiosk
$script:kioskKey = KioskKey @() $stock
HPreflight
Assert $true 'the empty folders Windows 11 ships with do not block'
Assert (@($stock.Values | Where-Object { $_.Closed -ne 1 }).Count -eq 0) 'every opened kiosk folder is closed'
$s = StockKiosk; $s['Configs'] = KioskKey @() ([ordered]@{ 'S-1-5-21-1' = (KioskKey @('DefaultProfileId') ([ordered]@{})) })
$script:kioskKey = KioskKey @() $s
Reject { HPreflight } 'this computer is set up as a kiosk'
$s = StockKiosk; $s['RawData'] = KioskKey @('Configuration') ([ordered]@{})
$script:kioskKey = KioskKey @() $s
Reject { HPreflight } 'this computer is set up as a kiosk'
$s = StockKiosk; $s['Profiles'] = $null
$script:kioskKey = KioskKey @() $s
Reject { HPreflight } 'this computer is set up as a kiosk'
$script:kioskKey = KioskKey @('Version') ([ordered]@{})
Reject { HPreflight } 'this computer is set up as a kiosk'
$script:fakeFs = $false
$gateJson = '"gate":{"areas":[],"pattern":".","tamperExempt":false,"secedit":false,"ownPolicyKey":"","policyValues":[]}'
function HandledJson([string]$id, [string]$source) { return ('{"id":"' + $id + '","source":"' + $source + '","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[0,2],"absentSafe":false,"fix":0,"max":2}],' + $gateJson + '}') }
MakeSpec (HandledJson 'services.unquoted_paths' 'UnquotedServices')
foreach ($ok in @('Spooler','My Service','svc.name$1','Intel(R) Update {1}+x','App#2,b&c')) { Assert (HNameOk $ok) "service name $ok" }
foreach ($bad in @('','a"b',' lead','trail ','x/y','x\y','a*b','a?b','a[1]',("t`tab"),('s' * 257))) { Assert (!(HNameOk $bad)) "service name accepted: $bad" }
Assert (HNameOk ('s' * 256)) 'a 256 character service name is accepted'
MakeSpec (HandledJson 'firewall.user_dir_inbound_allow' 'UserDirFirewall')
Assert (HNameOk 'My app (inbound)') 'firewall rule name'
foreach ($bad in @('','a"b','wild*card','x[1]',' pad',("t`tab"),('r' * 201))) { Assert (!(HNameOk $bad)) "firewall name accepted: $bad" }
MakeSpec (HandledJson 'net.hosts_file' 'HostsFile')
Assert ((HNameOk 'hosts') -and !(HNameOk 'Hosts') -and !(HNameOk 'hosts2') -and !(HNameOk '')) 'hosts name is exactly hosts'
MakeSpec (HandledJson 'persistence.run_and_tasks' 'StartupItems')
foreach ($ok in @('run-machine:Updater','run-user:My App','folder-user:a.lnk','task:\Vendor\Sync')) { Assert (HNameOk $ok) "startup name $ok" }
foreach ($bad in @('Updater','run-other:x','run-user:','task:Vendor\x','task:\Vendor\','run-user:a*b','run-user:a"b','run-user:x ',('run-user:' + ('n' * 260)))) { Assert (!(HNameOk $bad)) "startup name accepted: $bad" }

# hosts lines: the same flags as the Tools security check
foreach ($flagged in @('0.0.0.0 windowsupdate.com','127.0.0.1 update.microsoft.com','1.2.3.4 www.paypal.com','10.0.0.9   login.microsoft.com # note')) { Assert (HHostsLineFlag $flagged) "hosts line should be flagged: $flagged" }
foreach ($fine in @('127.0.0.1 localhost','::1 localhost','# 1.2.3.4 paypal.com','','   ','1.2.3.4','not-an-ip paypal.com','192.168.1.5 printer.lan')) { Assert (!(HHostsLineFlag $fine)) "hosts line should be left alone: $fine" }

# HHostsFix touches only flagged lines and keeps every other byte, line ending and BOM
$latin = [Text.Encoding]::GetEncoding(28591)
$original = $latin.GetBytes("# my notes`r`n127.0.0.1 localhost`r`n1.2.3.4 www.paypal.com`r`n`r`n192.168.1.5 printer.lan   # keep`r`n0.0.0.0 windowsupdate.com")
$fixedBytes = HHostsFix $original
$fixedText = $latin.GetString($fixedBytes)
Assert ($fixedText -ceq "# my notes`r`n127.0.0.1 localhost`r`n# turned off by Secblitz 1.2.3.4 www.paypal.com`r`n`r`n192.168.1.5 printer.lan   # keep`r`n# turned off by Secblitz 0.0.0.0 windowsupdate.com") "hosts fix text: $fixedText"
Assert (@(HHostsFlaggedLines $fixedBytes).Count -eq 0) 'a fixed hosts file has nothing flagged'
Assert (@(HHostsFlaggedLines $original).Count -eq 2) 'two flagged lines found'
$unmarked = $fixedText.Replace('# turned off by Secblitz ', '')
Assert ($unmarked -ceq $latin.GetString($original)) 'removing the note gives back the original text'
$bomBytes = [byte[]](@(0xEF, 0xBB, 0xBF) + @($latin.GetBytes("1.2.3.4 www.paypal.com`n")))
$bomFixed = HHostsFix $bomBytes
Assert ($bomFixed[0] -eq 0xEF -and $bomFixed[1] -eq 0xBB -and $bomFixed[2] -eq 0xBF -and $latin.GetString($bomFixed, 3, $bomFixed.Length - 3) -ceq "# turned off by Secblitz 1.2.3.4 www.paypal.com`n") 'BOM kept in front of the note'
Assert (HHostsPlain $original) 'plain text accepted'
Assert (!(HHostsPlain ([byte[]]@(0xFF, 0xFE, 0x31, 0x00)))) 'UTF-16 refused'
Assert (!(HHostsPlain ([byte[]]@(0x31, 0x00, 0x32)))) 'NUL bytes refused'
Assert (!(HHostsPlain $latin.GetBytes("a`rb`n"))) 'a lone carriage return is refused'
Assert (!(HHostsPlain $latin.GetBytes("a`r"))) 'a trailing lone carriage return is refused'
Assert (HHostsPlain $latin.GetBytes("a`r`nb`n")) 'CRLF and LF are accepted'
# a byte order mark only counts at the very start of the file
$midBom = [byte[]](@($latin.GetBytes("127.0.0.1 localhost`n")) + @(0xEF, 0xBB, 0xBF) + @($latin.GetBytes("1.2.3.4 www.paypal.com`n")))
Assert (@(HHostsFlaggedLines $midBom).Count -eq 0) 'a mid-file BOM line is not read as flagged'
Assert (@(HHostsFlaggedLines (HHostsFix $midBom)).Count -eq 0) 'fix and reader agree on a mid-file BOM line'

function HHostsBytes { if ($null -eq $script:hostsFile) { return $null }; return [byte[]]$script:hostsFile }
function HHostsWrite([byte[]]$bytes) { $script:hostsWrites++; if ($script:hostsFail) { throw 'fixture write failure' }; $script:hostsFile = [byte[]]$bytes }
function HFlushDns { $script:dnsFlushes++ }
function HHostsReadOnly { return [bool]$script:hostsRo }
function HHostsSetReadOnly([bool]$on) { $script:hostsRo = $on }
function HHostsFlaggedOther { return @('1.2.3.4 www.paypal.com') }
$script:hostsRo = $false
function HStateGet([string]$name) { if ($script:undoState.ContainsKey($name)) { return $script:undoState[$name] }; return $null }
function HStateSet([string]$name, $data) { $script:undoState[$name] = $data }
function HStateRemove([string]$name) { $script:undoState.Remove($name) }
$script:undoState = @{}; $script:hostsWrites = 0; $script:dnsFlushes = 0; $script:hostsFail = $false
$script:hostsFile = $original
$r = HReadHosts
Assert ($r['hosts'] -eq 1) 'flagged hosts file reads 1'
Assert ($script:hLabels.Count -gt 0) 'the flagged hosts lines are named'
HSetHosts 'hosts' 0
Assert ($latin.GetString($script:hostsFile) -ceq $fixedText) 'fix writes the commented file'
Assert ($script:dnsFlushes -eq 1) 'DNS cache flushed after the fix'
Assert ((HReadHosts)['hosts'] -eq 0) 'fixed and unchanged reads 0'
HSetHosts 'hosts' 1
Assert ([Convert]::ToBase64String($script:hostsFile) -ceq [Convert]::ToBase64String($original)) 'undo restores the exact original bytes'
Assert ($script:undoState.Count -eq 0 -and $script:dnsFlushes -eq 2) 'undo clears the saved state and flushes DNS'
Assert ((HReadHosts)['hosts'] -eq 1) 'after undo it is flagged again'
HSetHosts 'hosts' 0
$script:hostsFile = [byte[]](@($script:hostsFile) + @($latin.GetBytes("`r`n# someone else was here")))
Assert ((HReadHosts)['hosts'] -eq 2) 'a file changed since reads 2'
$before = [Convert]::ToBase64String($script:hostsFile)
Reject { HSetHosts 'hosts' 1 } 'changed again'
Assert ([Convert]::ToBase64String($script:hostsFile) -ceq $before) 'a changed hosts file is left alone on undo'
# a read-only hosts file: the mark is cleared for the change and put back by undo
$script:undoState = @{}; $script:hostsFile = $original; $script:hostsRo = $true
HSetHosts 'hosts' 0
Assert (!$script:hostsRo) 'the read-only mark is cleared for the change'
Assert ((HReadHosts)['hosts'] -eq 0) 'fixed and unlocked reads 0'
$script:hostsRo = $true
Assert ((HReadHosts)['hosts'] -eq 2) 'a read-only mark added since reads 2'
Reject { HSetHosts 'hosts' 1 } 'changed again'
$script:hostsRo = $false
HSetHosts 'hosts' 1
Assert ($script:hostsRo -and [Convert]::ToBase64String($script:hostsFile) -ceq [Convert]::ToBase64String($original)) 'undo restores the bytes and the read-only mark'
# UTF-16 is read the way the Tools check reads it: flagged, then Not offered
$script:undoState = @{}; $script:hostsRo = $false
$script:hostsFile = [byte[]]@(0xFF, 0xFE, 0x31, 0x00)
Assert ((HReadHosts)['hosts'] -eq 1) 'a UTF-16 hosts file with a redirect reads 1'
$script:undoState = @{}; $script:hostsFile = $original; $script:hostsFail = $true
Reject { HSetHosts 'hosts' 0 } 'fixture write failure'
$script:hostsFail = $false
Assert ($script:undoState.Count -eq 0) 'a failed fix leaves no saved state'
$script:hostsFile = $latin.GetBytes("127.0.0.1 localhost`r`n")
Reject { HSetHosts 'hosts' 0 } 'no longer needs a change'
Reject { HSetHosts 'other' 0 } 'Invalid hosts file state'
Reject { HSetHosts 'hosts' 2 } 'Invalid hosts file state'
$script:hostsFile = $null
Reject { HHostsPreflight } 'Not offered: the hosts file could not be found'
$script:hostsFile = [byte[]](New-Object byte[] ($hHostsMaxBytes + 1))
Reject { HHostsPreflight } 'Not offered: the hosts file is too large'
$script:hostsFile = [byte[]]@(0xFF, 0xFE, 0x31, 0x00)
Reject { HHostsPreflight } 'Not offered: the hosts file uses a format we cannot keep exactly'

# start-up items: Task Manager's on/off record
Assert (HApprovedEnabled $null) 'no record means on'
Assert (HApprovedEnabled ([byte[]]@(2,0,0,0,0,0,0,0,0,0,0,0))) 'even first byte means on'
Assert (!(HApprovedEnabled ([byte[]]@(3,0,0,0,0,0,0,0,0,0,0,0)))) 'odd first byte means off'
Assert (!(HApprovedEnabled ([byte[]]@(2,0)))) 'a short record is treated as off, never overwritten'
Assert (HIsUserKind 'run-user' -and HIsUserKind 'folder-user' -and !(HIsUserKind 'run-machine') -and !(HIsUserKind 'folder-machine')) 'only per-user kinds depend on who is signed in'
$staleJson = '{"id":"accounts.stale_enabled","source":"StaleAccounts","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],' + $noGate + '}'
MakeSpec $staleJson
$bob = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
$amy = 'S-1-5-21-1111111111-2222222222-3333333333-1002'
$me = 'S-1-5-21-1111111111-2222222222-3333333333-1003'
$adm = 'S-1-5-21-1111111111-2222222222-3333333333-500'
foreach ($ok in @($bob, 'S-1-5-21-1-2-3-1000', 'S-1-5-21-1-2-3-4294967295')) { Assert (HNameOk $ok) "account $ok" }
foreach ($bad in @('', 'Bob', 'S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-501', 'S-1-5-21-1-2-3-503', 'S-1-5-21-1-2-3-504', 'S-1-5-21-1-2-3-999', 'S-1-5-21-1-2-3-01001', 'S-1-5-21-1-2-3', 'S-1-5-21-1-2-3-1001-5', 'S-1-5-32-544', 'S-1-1-0', 's-1-5-21-1-2-3-1001', "S-1-5-21-1-2-3-1001'; calc", 'S-1-5-21-1-2-3-4294967296', "S-1-5-21-1-2-3-1001`n")) { Assert (!(HNameOk $bad)) "account name accepted: $bad" }
function U([string]$sid, [bool]$enabled, $last) { [pscustomobject]@{ SID = [pscustomobject]@{ Value = $sid }; Enabled = $enabled; LastLogon = $last; Name = $(if ($sid -ceq $bob) { 'bob' } elseif ($sid -ceq $amy) { 'amy' } else { 'user' + $sid.Substring($sid.Length - 4) }) } }
$old = (Get-Date).AddDays(-400); $recent = (Get-Date).AddDays(-10)
$script:users = @((U $bob $true $old), (U $amy $true $old), (U $me $true $recent), (U $adm $true $old), (U 'S-1-5-21-1111111111-2222222222-3333333333-1004' $false $old), (U 'S-1-5-21-1111111111-2222222222-3333333333-1005' $true $null), (U 'S-1-5-21-1111111111-2222222222-3333333333-501' $true $old))
function Get-LocalUser { param($SID, $ErrorAction)
    if ($null -eq $SID) { return $script:users }
    $s = if ($SID -is [string]) { $SID } else { [string]$SID.Value }
    $f = @($script:users | Where-Object { $_.SID.Value -ceq $s })
    if ($f.Count -eq 0) { $e = [Management.Automation.ErrorRecord]::new([Exception]::new('not found'), 'UserNotFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $s); throw $e }
    return $f[0]
}
$script:inUse = @{ $me = $true }
$script:inUseFails = $false
function HAccountsInUse { if ($script:inUseFails) { throw 'sessions unreadable' }; return $script:inUse.Clone() }
$script:admins = @($me, $bob)
function HEnabledAdminSids { if ($script:adminsFail) { throw 'group unreadable' }; return @($script:admins) }
$script:adminsFail = $false
$script:hWanted = @{}
$r = HReadStale
Assert ($script:hLabels.Count -eq 2 -and $script:hLabels[$bob] -ceq 'bob' -and $script:hLabels[$amy] -ceq 'amy') "account names are kept for the review sheet: $(($script:hLabels.Values | Sort-Object) -join ',')"
Assert ((HLabelKind $bob) -ceq 'account') 'old accounts are labelled as accounts'
Assert ($r.Count -eq 2 -and $r[$bob] -eq 1 -and $r[$amy] -eq 1) 'only enabled, user-created accounts idle for 180 days are listed (never built-ins, new, disabled or never-signed-in ones)'
$script:inUse = @{ $me = $true; $bob = $true }
$r = HReadStale
Assert ($r.Count -eq 1 -and $r[$amy] -eq 1) 'an account that is signed in or runs a service is never listed'
$script:inUseFails = $true
$r = HReadStale
Assert ($r.Count -eq 2) 'unreadable sessions still list candidates (the preflight then refuses)'
$script:inUseFails = $false; $script:inUse = @{ $me = $true }
$script:hWanted = @{ $bob = 1; 'S-1-5-21-1111111111-2222222222-3333333333-1099' = 0 }
$script:users = @((U $bob $false $old), (U $amy $true $old))
$r = HReadStale
Assert ($r[$bob] -eq 0 -and $r['S-1-5-21-1111111111-2222222222-3333333333-1099'] -eq 0 -and $r[$amy] -eq 1) 'a switched-off account reads as 0, never dropped'
$script:hWanted = @{}
$script:users = @((U $bob $true $old), (U $amy $true $old), (U $me $true $recent), (U $adm $true $old))
HStalePreflight
$script:inUseFails = $true
Reject { HStalePreflight } 'Not offered: Secblitz cannot tell who is signed in'
$script:inUseFails = $false
$script:admins = @($bob); $script:inUse = @{ $me = $true }
Reject { HStalePreflight } 'Not offered: no other administrator account is enabled'
$script:admins = @($bob, $adm)
Reject { HStalePreflight } 'Not offered: no other administrator account is enabled'
$script:admins = @($bob, $me)
HStalePreflight
$script:adminsFail = $true
Reject { HStalePreflight } 'could be confirmed'
$script:adminsFail = $false
$script:admins = @($me, $amy)
HStalePreflight
$script:calls = @()
function Disable-LocalUser { param($SID, $ErrorAction); $script:calls += ,@('disable', $SID) }
function Enable-LocalUser { param($SID, $ErrorAction); $script:calls += ,@('enable', $SID) }
$script:inUse = @{ $me = $true; $adm = $true }
Reject { HBuiltinAdminIdle } 'Not offered: you are signed in with the built-in Administrator account'
Reject { HSetBuiltinAdmin $null 0 } 'signed in with the built-in Administrator'
Assert ($script:calls.Count -eq 0) 'the built-in Administrator is never switched off while someone is signed in with it'
$script:inUseFails = $true
Reject { HBuiltinAdminIdle } 'Not offered: Secblitz cannot tell who is signed in'
$script:inUseFails = $false; $script:inUse = @{ $me = $true }
HBuiltinAdminIdle
HSetBuiltinAdmin $null 0
Assert ($script:calls.Count -eq 1 -and $script:calls[0][0] -ceq 'disable' -and [string]$script:calls[0][1].Value -ceq $adm) 'the idle built-in Administrator can be switched off'
$script:calls = @()
$script:admins = @($me, $bob)
HSetStale $bob 0
HSetStale $bob 1
Assert ((CallLog) -ceq 'disable:S-1-5-21-1111111111-2222222222-3333333333-1001,enable:S-1-5-21-1111111111-2222222222-3333333333-1001') "stale writer: $(CallLog)"
$script:calls = @()
$script:inUse = @{ $me = $true; $bob = $true }
Reject { HSetStale $bob 0 } 'in use'
$script:inUse = @{ $me = $true }
$script:admins = @($bob)
Reject { HSetStale $bob 0 } 'last administrator'
$script:admins = @($bob, $adm)
Reject { HSetStale $bob 0 } 'last administrator'
Reject { HSetStale 'S-1-5-21-1-2-3-500' 0 } 'Invalid account'
Reject { HSetStale 'Bob' 0 } 'Invalid account'
Reject { HSetStale $bob 2 } 'Invalid account'
Reject { HSetStale $bob $null } 'Invalid account'
Reject { HSetStale 'S-1-5-21-1111111111-2222222222-3333333333-1077' 0 } 'no longer exists'
HSetStale 'S-1-5-21-1111111111-2222222222-3333333333-1077' 1
Assert ($script:calls.Count -eq 0) 'nothing is written for a refused or deleted account'
Assert (HItemGone 'S-1-5-21-1111111111-2222222222-3333333333-1077') 'a deleted account is gone'
Assert (!(HItemGone $bob)) 'an existing account is not gone'
Assert (!(HVerified $bob 0 1)) 'switched-off account does not verify as restored'
Assert (HVerified 'S-1-5-21-1111111111-2222222222-3333333333-1077' 0 1) 'undo of a deleted account is complete'
Assert (!(HVerified 'S-1-5-21-1111111111-2222222222-3333333333-1077' 1 0)) 'a deleted account never verifies a switch-off'
${function:HRead} = $realHRead
function HSet([string]$name, $v) { if ($spec.source -ceq 'StaleAccounts') { HSetStale $name $v } else { HSetShare $name $v } }
$script:preflightFails = $false; $script:blocked = $false
$script:users = @((U $bob $true $old), (U $amy $true $old), (U $me $true $recent))
$script:calls = @(); $script:admins = @($me)
$script:inUse = @{ $me = $true }
function Disable-LocalUser { param($SID, $ErrorAction); $script:calls += ,@('disable', $SID); ($script:users | Where-Object { $_.SID.Value -ceq $SID }).Enabled = $false }
function Enable-LocalUser { param($SID, $ErrorAction); $script:calls += ,@('enable', $SID); ($script:users | Where-Object { $_.SID.Value -ceq $SID }).Enabled = $true }
HWrite (ConvertFrom-Json "{`"items`":{`"$bob`":0,`"$amy`":0}}")
Assert ((CallLog) -ceq "disable:$bob,disable:$amy" -and !$script:users[0].Enabled -and !$script:users[1].Enabled -and $script:users[2].Enabled) "both old accounts were switched off, my own was not: $(CallLog)"
$script:calls = @()
HWrite (ConvertFrom-Json "{`"items`":{`"$bob`":1,`"$amy`":1}}")
Assert ((CallLog) -ceq "enable:$bob,enable:$amy" -and $script:users[0].Enabled -and $script:users[1].Enabled) "undo switched them back on: $(CallLog)"
# An account that signed in meanwhile is no longer old: it is refused, nothing is written.
$script:calls = @(); $script:users = @((U $bob $true $recent), (U $me $true $recent))
Reject { HWrite (ConvertFrom-Json "{`"items`":{`"$bob`":0}}") } 'no longer an old account'
Assert ($script:calls.Count -eq 0) 'no write for an account that is no longer old'
$script:calls = @(); $script:users = @((U $me $true $recent))
HWrite (ConvertFrom-Json "{`"items`":{`"$bob`":1}}")
Assert ($script:calls.Count -eq 0) 'undo of a deleted account writes nothing and succeeds'

$shareJson = '{"id":"smb.shares_exposed","source":"ShareGrants","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","rule":"set","safe":[0],"absentSafe":false,"fix":0,"max":1}],' + $noGate + '}'
MakeSpec $shareJson
foreach ($ok in @('Photos|S-1-1-0|Change', 'Work files|S-1-5-32-546|Full', 'Public|S-1-5-7|Change', 'Fotos für alle|S-1-1-0|Full', "Mom's files|S-1-1-0|Change", 'Backup$|S-1-1-0|Full')) { Assert (HNameOk $ok) "share entry $ok" }
foreach ($bad in @('', 'C$|S-1-1-0|Full', 'ADMIN$|S-1-1-0|Full', 'IPC$|S-1-1-0|Change', 'print$|S-1-1-0|Full', 'c$|S-1-1-0|Full', 'Print$|S-1-1-0|Full', 'Photos|S-1-5-11|Change', 'Photos|S-1-1-0|Read', 'Photos|S-1-1-0|change', 'Photos|Everyone|Change', 'Photos|S-1-1-0', 'Photos|S-1-1-0|Change|x', '|S-1-1-0|Change', ' Photos|S-1-1-0|Change', 'Pho"tos|S-1-1-0|Change', "Pho`ntos|S-1-1-0|Change", 'Pho\tos|S-1-1-0|Change', 'Pho:tos|S-1-1-0|Change', "Photos|S-1-1-0|Change`n", ('x' * 81) + '|S-1-1-0|Full')) { Assert (!(HNameOk $bad)) "share entry accepted: $bad" }
function HAccountOfSid([string]$sid) { switch ($sid) { 'S-1-1-0' { return 'Everyone' } 'S-1-5-7' { return 'NT AUTHORITY\ANONYMOUS LOGON' } 'S-1-5-32-546' { return 'BUILTIN\Guests' } 'S-1-5-32-544' { return 'BUILTIN\Administrators' } 'S-1-5-18' { return 'NT AUTHORITY\SYSTEM' } }; throw 'unexpected SID' }
function Sh([string]$name, [bool]$special = $false) { [pscustomobject]@{ Name = $name; Special = $special } }
function ShareAce([string]$account, [string]$right, [string]$type = 'Allow') { [pscustomobject]@{ AccountName = $account; AccessRight = $right; AccessControlType = $type } }
$script:shares = @((Sh 'Photos'), (Sh 'Work files'), (Sh 'Music'), (Sh 'Locked'), (Sh 'C$' $true), (Sh 'Hidden$'), (Sh 'Weird''name'))
$script:acl = @{
    'Photos' = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'PC\Amy' 'Read'))
    'Work files' = @((ShareAce 'BUILTIN\Guests' 'Full'), (ShareAce 'PC\Bob' 'Change'), (ShareAce 'NT AUTHORITY\ANONYMOUS LOGON' 'Read'))
    'Music' = @((ShareAce 'Everyone' 'Read'), (ShareAce 'PC\Bob' 'Full'))
    'Locked' = @((ShareAce 'Everyone' 'Change' 'Deny'), (ShareAce 'PC\Amy' 'Read'))
    'C$' = @((ShareAce 'Everyone' 'Full'))
    'Hidden$' = @((ShareAce 'Everyone' 'Full'), (ShareAce 'PC\Bob' 'Read'))
    'Weird''name' = @((ShareAce 'Everyone' 'Full'), (ShareAce 'PC\Bob' 'Read'))
}
$script:smbFail = $false
function Get-SmbShare { param($Name, $ErrorAction)
    if ($script:smbFail) { throw 'Access is denied' }
    if ($Name) {
        $f = @($script:shares | Where-Object { $_.Name -ceq $Name })
        if ($f.Count -eq 0) { throw ([Management.Automation.ErrorRecord]::new([Exception]::new('No MSFT_SmbShare objects found'), 'CmdletizationQuery_NotFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name)) }
        return $f
    }
    return $script:shares
}
function Get-SmbShareAccess { param($Name, $ErrorAction); if ($script:acl.ContainsKey($Name)) { return $script:acl[$Name] }; return @() }
$script:hWanted = @{}
$r = HReadShares
Assert ($r.Count -eq 4 -and $r['Photos|S-1-1-0|Change'] -eq 1 -and $r['Work files|S-1-5-32-546|Full'] -eq 1 -and $r['Hidden$|S-1-1-0|Full'] -eq 1 -and $r["Weird'name|S-1-1-0|Full"] -eq 1) 'Everyone, Anonymous or Guests with Change or Full on a user-made share are listed, hidden and apostrophe names included (not Read, Deny or built-in shares)'
Assert (HAnyUnsafe $r) 'a broad entry is unsafe'
Assert ($script:hLabels['Photos|S-1-1-0|Change'] -ceq 'Photos' -and $script:hLabels['Work files|S-1-5-32-546|Full'] -ceq 'Work files') 'each shared entry is named by its folder for the review sheet'
Assert ((HLabelKind 'Photos|S-1-1-0|Change') -ceq 'share') 'shared entries are labelled as folders'
$script:hWanted = @{ 'Photos|S-1-1-0|Change' = 1; 'Gone|S-1-1-0|Full' = 1 }
$script:acl['Photos'] = @((ShareAce 'BUILTIN\Administrators' 'Full'))
$r = HReadShares
Assert ($r['Photos|S-1-1-0|Change'] -eq 0 -and $r['Gone|S-1-1-0|Full'] -eq 0) 'a removed entry reads as 0, never dropped'
$script:hWanted = @{}
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'PC\Amy' 'Read'))
$script:shares = @($script:shares[0..6]) + @((Sh 'Extra1'))
HSharesPreflight
Assert $true 'folders that keep another allowed entry pass the preflight'
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'))
Reject { HSharesPreflight } 'Not offered: a shared folder would be left with no one who can open it'
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'PC\Amy' 'Read' 'Deny'))
Reject { HSharesPreflight } 'no one who can open it'
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'PC\Amy' 'Read'))
$script:acl['Work files'] = @((ShareAce 'BUILTIN\Guests' 'Full'), (ShareAce 'NT AUTHORITY\ANONYMOUS LOGON' 'Read'))
HSharesPreflight
Assert $true 'a broad Read entry that stays counts as someone who can open it'
$script:calls = @()
$script:rows = @{}
function Revoke-SmbShareAccess { param($Name, $AccountName, [switch]$Force, $ErrorAction); $script:calls += ,@('revoke', $Name, $AccountName); $script:acl[$Name] = @($script:acl[$Name] | Where-Object { $_.AccountName -ine $AccountName }) }
function Grant-SmbShareAccess { param($Name, $AccountName, $AccessRight, [switch]$Force, $ErrorAction); $script:calls += ,@('grant', $Name, $AccountName, $AccessRight); $script:acl[$Name] = @($script:acl[$Name]) + @((ShareAce $AccountName ([string]$AccessRight))) }
$script:acl['Work files'] = @((ShareAce 'BUILTIN\Guests' 'Full'), (ShareAce 'PC\Bob' 'Change'))
HSetShare 'Photos|S-1-1-0|Change' 0
HSetShare 'Photos|S-1-1-0|Change' 1
Assert ((CallLog) -ceq 'revoke:Photos:Everyone,grant:Photos:Everyone:Change') "share writer: $(CallLog)"
Assert (@($script:acl['Photos']).Count -eq 3 -and @($script:acl['Photos'] | Where-Object { $_.AccountName -ceq 'BUILTIN\Administrators' }).Count -eq 1) 'the other entries are untouched'
$script:calls = @()
Reject { HSetShare 'Photos|S-1-1-0|Full' 0 } 'entry changed'
Reject { HSetShare 'Photos|S-1-5-7|Change' 0 } 'entry changed'
Reject { HSetShare 'Photos|S-1-1-0|Change' 2 } 'Invalid shared folder state'
Reject { HSetShare 'Photos|S-1-1-0|Change' $null } 'Invalid shared folder state'
Reject { HSetShare 'C$|S-1-1-0|Full' 0 } 'Unknown hardening item'
Reject { HSetShare 'Photos|S-1-5-11|Change' 0 } 'Unknown hardening item'
Reject { HSetShare 'Missing|S-1-1-0|Change' 0 } 'no longer exists'
HSetShare 'Missing|S-1-1-0|Change' 1
$script:acl['Locked'] = @((ShareAce 'Everyone' 'Change'))
Reject { HSetShare 'Locked|S-1-1-0|Change' 0 } 'no one who can open it'
$script:acl['Locked'] = @((ShareAce 'Everyone' 'Read'), (ShareAce 'PC\Amy' 'Read'))
Reject { HSetShare 'Locked|S-1-1-0|Change' 1 } 'left alone'
Assert ($script:calls.Count -eq 0) 'nothing is written for a refused change'
$script:acl['Locked'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'PC\Amy' 'Read'))
HSetShare 'Locked|S-1-1-0|Change' 1
Assert ($script:calls.Count -eq 0) 'putting back an entry that is already there writes nothing'
Assert (HItemGone 'Missing|S-1-1-0|Change') 'a removed share is gone'
Assert (!(HItemGone 'Photos|S-1-1-0|Change')) 'an existing share is not gone'
Assert (HVerified 'Missing|S-1-1-0|Change' 0 1) 'undo of a removed share is complete'
Assert (!(HVerified 'Photos|S-1-1-0|Change' 0 1)) 'a missing entry on an existing share does not verify as restored'
$script:calls = @(); $script:hWanted = @{}
$script:shares = @((Sh 'Photos'), (Sh 'Work files'))
$script:acl = @{
    'Photos' = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'PC\Amy' 'Read'))
    'Work files' = @((ShareAce 'BUILTIN\Guests' 'Full'), (ShareAce 'PC\Bob' 'Change'))
}
HWrite (ConvertFrom-Json '{"items":{"Photos|S-1-1-0|Change":0,"Work files|S-1-5-32-546|Full":0}}')
Assert ((CallLog) -ceq 'revoke:Photos:Everyone,revoke:Work files:BUILTIN\Guests' -and @($script:acl['Photos']).Count -eq 2 -and @($script:acl['Work files']).Count -eq 1) "both broad entries removed: $(CallLog)"
$script:calls = @()
HWrite (ConvertFrom-Json '{"items":{"Photos|S-1-1-0|Change":1,"Work files|S-1-5-32-546|Full":1}}')
Assert ((CallLog) -ceq 'grant:Photos:Everyone:Change,grant:Work files:BUILTIN\Guests:Full' -and @($script:acl['Photos']).Count -eq 3 -and @($script:acl['Work files']).Count -eq 2) "undo put both entries back: $(CallLog)"
# A folder that would be left empty blocks the repair before anything is written.
$script:calls = @()
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'))
Reject { HWrite (ConvertFrom-Json '{"items":{"Photos|S-1-1-0|Change":0,"Work files|S-1-5-32-546|Full":0}}') } 'Not offered'
Assert ($script:calls.Count -eq 0) 'no entry was removed from any folder'

# One account with two rows (Read and Change) cannot be removed and put back exactly.
$script:smbFail = $false
$script:calls = @()
$script:shares = @((Sh 'Photos'), (Sh 'Work files'))
$script:acl = @{
    'Photos' = @((ShareAce 'Everyone' 'Change'), (ShareAce 'Everyone' 'Read'), (ShareAce 'PC\Amy' 'Read'))
    'Work files' = @((ShareAce 'BUILTIN\Guests' 'Full'), (ShareAce 'PC\Bob' 'Change'))
}
Reject { HSetShare 'Photos|S-1-1-0|Change' 0 } 'entry changed'
Assert ($script:calls.Count -eq 0) 'nothing is revoked when the account has two rows'
Reject { HSharesPreflight } 'could not be put back exactly'
# A Deny row for the same account is also more than one row.
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'Everyone' 'Full' 'Deny'), (ShareAce 'PC\Amy' 'Read'))
Reject { HSetShare 'Photos|S-1-1-0|Change' 0 } 'entry changed'
# Only administrators would be left: not offered.
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'NT AUTHORITY\SYSTEM' 'Full'))
Reject { HSharesPreflight } 'only administrators'
$script:acl['Photos'] = @((ShareAce 'Everyone' 'Change'), (ShareAce 'BUILTIN\Administrators' 'Full'), (ShareAce 'PC\Amy' 'Change'))
HSharesPreflight
# A failed read is not a deleted share.
$script:smbFail = $true
Reject { HSetShare 'Photos|S-1-1-0|Change' 1 } 'Access is denied'
Reject { HItemGone 'Photos|S-1-1-0|Change' } 'Access is denied'
Reject { HVerified 'Photos|S-1-1-0|Change' 0 1 } 'Access is denied'
$script:smbFail = $false
Assert (HItemGone 'Gone|S-1-1-0|Change') 'a share that does not exist is gone'
# Hidden user shares and apostrophes are handled like any other share; built-in ones never.
$script:shares = @((Sh 'Mom''s files'), (Sh 'Backup$'), (Sh 'D$' $true), (Sh 'ADMIN$' $true))
$script:acl = @{ 'Mom''s files' = @((ShareAce 'Everyone' 'Full'), (ShareAce 'PC\Bob' 'Change')); 'Backup$' = @((ShareAce 'Everyone' 'Change'), (ShareAce 'PC\Bob' 'Change')); 'D$' = @((ShareAce 'Everyone' 'Full')); 'ADMIN$' = @((ShareAce 'Everyone' 'Full')) }
$script:hWanted = @{}
$r = HReadShares
Assert ($r.Count -eq 2 -and $r["Mom's files|S-1-1-0|Full"] -eq 1 -and $r['Backup$|S-1-1-0|Change'] -eq 1) 'the check and the fix see the same shares'
HSharesPreflight
$script:calls = @()
HSetShare "Mom's files|S-1-1-0|Full" 0
Assert ((CallLog) -ceq "revoke:Mom's files:Everyone") "apostrophe share: $(CallLog)"
Reject { HSetShare 'D$|S-1-1-0|Full' 0 } 'Unknown hardening item'

# An account that is signed in or runs a service reads as still switched on.
MakeSpec $staleJson
$script:users = @((U $bob $true $old), (U $amy $true $old), (U $me $true $recent))
$script:inUse = @{ $me = $true; $bob = $true }
$script:inUseFails = $false
$script:hWanted = @{ $bob = 0; $amy = 0 }
$r = HReadStale
Assert ($r[$bob] -eq 1 -and $r[$amy] -eq 1) 'an account in use reads as 1, not 0'
$script:calls = @()
$script:admins = @($me, $amy)
Reject { HWrite (ConvertFrom-Json "{`"items`":{`"$bob`":0,`"$amy`":0}}") } 'in use'
Assert (@($script:calls | Where-Object { $_[0] -eq 'disable' -and $_[1] -eq $bob }).Count -eq 0) 'the account in use was never switched off'
$script:hWanted = @{}

# The real "who is signed in" and administrator readers, with doubles for the system only.
foreach ($fn in @('HAccountsInUse', 'HEnabledAdminSids')) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($HardeningPath, [ref]$tokens, [ref]$errors)
    $node = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $fn }
    . ([scriptblock]::Create($node.Extent.Text))
}
$env:COMPUTERNAME = 'PC'
$sidOf = @{ 'PC\Bob' = $bob; 'PC\Amy' = $amy; 'PC\Cara' = 'S-1-5-21-1111111111-2222222222-3333333333-1010'; 'PC\svcuser' = 'S-1-5-21-1111111111-2222222222-3333333333-1011' }
function HCurrentSid { return $me }
function HSidOfAccount([string]$account) { if ($sidOf.ContainsKey($account)) { return $sidOf[$account] }; throw 'No mapping' }
function LU([string]$domain, [string]$name, [string]$logon) { [pscustomobject]@{ Antecedent = [pscustomobject]@{ Domain = $domain; Name = $name }; Dependent = [pscustomobject]@{ LogonId = $logon } } }
$script:cim = @{
    Win32_LogonSession = @([pscustomobject]@{ LogonId = '1' }, [pscustomobject]@{ LogonId = '2' }, [pscustomobject]@{ LogonId = '3' })
    Win32_LoggedOnUser = @((LU 'PC' 'Bob' '1'), (LU 'NT AUTHORITY' 'SYSTEM' '2'), (LU 'Window Manager' 'DWM-1' '3'), (LU 'PC' 'Amy' '9'))
    Win32_ComputerSystem = @([pscustomobject]@{ UserName = 'PC\Cara' })
    Win32_Service = @([pscustomobject]@{ StartName = '.\svcuser' }, [pscustomobject]@{ StartName = 'LocalSystem' }, [pscustomobject]@{ StartName = 'NT AUTHORITY\NetworkService' }, [pscustomobject]@{ StartName = 'NT SERVICE\x' }, [pscustomobject]@{ StartName = 'PC\Nobody' }, [pscustomobject]@{ StartName = $null })
}
function Get-CimInstance { param($ClassName); return $script:cim[$ClassName] }
$u = HAccountsInUse
Assert ($u.Count -eq 4 -and $u.ContainsKey($me) -and $u.ContainsKey($bob) -and $u.ContainsKey($sidOf['PC\Cara']) -and $u.ContainsKey($sidOf['PC\svcuser'])) "in use: the running account, a live session, the console user and a service account: $($u.Keys -join ',')"
Assert (!$u.ContainsKey($amy)) 'an ended session does not count'
$script:cim.Win32_LoggedOnUser = @((LU 'PC' 'Ghost' '1'))
Reject { HAccountsInUse } 'No mapping'
$script:cim.Win32_LoggedOnUser = @()
$script:cim.Win32_ComputerSystem = @([pscustomobject]@{ UserName = 'PC\Ghost' })
Reject { HAccountsInUse } 'No mapping'
$script:cim.Win32_ComputerSystem = @([pscustomobject]@{ UserName = $null })
Assert ((HAccountsInUse).Count -eq 2) 'no console user and no live sessions leaves the running account and the service account'

function Mem([string]$sid, [string]$class) { [pscustomobject]@{ SID = [pscustomobject]@{ Value = $sid }; ObjectClass = $class } }
$grp = 'S-1-5-21-1111111111-2222222222-3333333333-1500'
$script:users = @((U $bob $true $old), (U $amy $false $old), (U $adm $true $old))
function Get-LocalGroupMember { param($SID, $ErrorAction); return @((Mem $bob 'User'), (Mem $amy 'User'), (Mem $adm 'User'), (Mem $grp 'Group'), (Mem 'S-1-12-1-1-2-3-4' 'User')) }
$a = @(HEnabledAdminSids)
Assert ($a.Count -eq 2 -and $a -ccontains $bob -and $a -ccontains $adm) 'enabled administrators: users only, switched on, local'
# The built-in Administrator never counts as an administrator who stays.
function HAccountsInUse { return @{ $me = $true } }
$script:users = @((U $bob $true $old), (U $adm $true $old))
function Get-LocalGroupMember { param($SID, $ErrorAction); return @((Mem $bob 'User'), (Mem $adm 'User')) }
Reject { HStalePreflight } 'no other administrator account is enabled'

$recJson = '{"id":"recovery.winre_enabled","source":"RecoveryTools","dynamic":false,"reboot":false,"keys":[{"name":"Enabled","path":"","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $noGate + '}'
MakeSpec $recJson
if ($env:SystemRoot) {
    Assert ((HRecoveryDir) -clike '*\System32\Recovery') "recovery folder: $(HRecoveryDir)"
    Assert ((HReagentPath) -clike '*\System32\ReAgentc.exe') "recovery tool: $(HReagentPath)"
}
# The real launcher refuses anything but the two changes before starting anything.
Reject { HRunReagent '/boottore' } 'Unknown recovery tools change'
Reject { HRunReagent '/info' } 'Unknown recovery tools change'
Reject { HRunReagent '/ENABLE' } 'Unknown recovery tools change'
$realRecoveryDir = ${function:HRecoveryDir}
$realReagentPath = ${function:HReagentPath}
$realRunReagent = ${function:HRunReagent}
$recRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'secblitz-recovery-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($recRoot)
try {
    function HRecoveryDir { return $recRoot }
    function HReagentPath { return [IO.Path]::Combine($recRoot, 'ReAgentc.exe') }
    # A missing tool is refused before anything is started.
    Reject { HRunReagent '/enable' } 'recovery tools are missing'
    function RecoveryConfig([string]$body) {
        [IO.File]::WriteAllText([IO.Path]::Combine($recRoot, 'ReAgent.xml'), "<?xml version='1.0' encoding='utf-8'?>`r`n<WindowsRE version=`"2.0`">`r`n  <WinreBCD id=`"{00000000-0000-0000-0000-000000000000}`"/>`r`n$body`r`n  <WinREStaged state=`"0`"/>`r`n</WindowsRE>`r`n")
    }
    function RecoveryState([string]$state) { RecoveryConfig ('  <InstallState state="' + $state + '"/>') }
    function RecoveryImage([int]$size) {
        $image = [IO.Path]::Combine($recRoot, 'Winre.wim')
        if ($size -lt 0) { if ([IO.File]::Exists($image)) { [IO.File]::Delete($image) }; return }
        [IO.File]::WriteAllBytes($image, [byte[]]::new($size))
    }
    function RecoveryTool([bool]$present) {
        $tool = [IO.Path]::Combine($recRoot, 'ReAgentc.exe')
        if ($present) { [IO.File]::WriteAllBytes($tool, [byte[]]@(77, 90)) } elseif ([IO.File]::Exists($tool)) { [IO.File]::Delete($tool) }
    }
    RecoveryState '1'
    $r = HReadRecovery
    Assert ($r['Enabled'] -eq 1 -and !(HAnyUnsafe $r)) 'recovery tools that are on are protected'
    RecoveryState '0'
    $r = HReadRecovery
    Assert ($r['Enabled'] -eq 0 -and (HAnyUnsafe $r)) 'recovery tools that are off need a look'
    Assert ((HFixOf (HDef 'Enabled') 0) -eq 1) 'off is only ever repaired to on'
    Assert (HIsSafe (HDef 'Enabled') 1) 'on is safe'
    Assert (!(HIsSafe (HDef 'Enabled') $null)) 'an unknown state is never safe'
    # Anything but exactly one plain on or off is unreadable, never a guess.
    foreach ($bad in @('2', '', 'Enabled', ' 1', 'true')) {
        RecoveryState $bad
        Reject { HReadRecovery } 'not readable'
    }
    RecoveryConfig '  <InstallState state="1"/><InstallState state="0"/>'
    Reject { HReadRecovery } 'not readable'
    RecoveryConfig '  <OsInstallAvailable state="0"/>'
    Reject { HReadRecovery } 'not readable'
    [IO.File]::WriteAllText([IO.Path]::Combine($recRoot, 'ReAgent.xml'), "<?xml version='1.0'?><Other><InstallState state=`"1`"/></Other>")
    Reject { HReadRecovery } 'not readable'
    # A document type declaration is refused outright: the file is data, never instructions.
    [IO.File]::WriteAllText([IO.Path]::Combine($recRoot, 'ReAgent.xml'), "<?xml version='1.0'?><!DOCTYPE WindowsRE [<!ENTITY x `"1`">]><WindowsRE><InstallState state=`"&x;`"/></WindowsRE>")
    Reject { HReadRecovery } ''
    [IO.File]::Delete([IO.Path]::Combine($recRoot, 'ReAgent.xml'))
    Reject { HReadRecovery } 'not readable'
    ${function:HRead} = $realHRead
    RecoveryState '0'
    $r = HRead
    Assert ($r.Count -eq 1 -and $r['Enabled'] -eq 0) 'the dispatcher reads the recovery tools state'

    # Offered only while Windows still has the image and its own tool.
    ${function:HPreflight} = $realHPreflight
    RecoveryImage 4096
    RecoveryTool $true
    HPreflight
    Assert $true 'offered when the image and the tool are there'
    RecoveryImage (-1)
    Reject { HPreflight } 'Not offered: the recovery tools are missing from this computer'
    RecoveryImage 0
    Reject { HPreflight } 'Not offered: the recovery tools are missing from this computer'
    RecoveryImage 4096
    RecoveryTool $false
    Reject { HPreflight } 'Not offered: the recovery tools are missing from this computer'
    RecoveryTool $true
    function HGate { }
    RecoveryImage (-1)
    $o = HObserve
    Assert (!$o.eligible -and $o.reason -ceq 'Not offered: the recovery tools are missing from this computer' -and $o.value.items['Enabled'] -eq 0) "a missing image is a plain Not offered: $($o.reason)"
    RecoveryImage 4096
    $o = HObserve
    Assert ($o.eligible -and $o.value.items['Enabled'] -eq 0) 'offered when the tools are off and can come back'
    RecoveryState '1'
    RecoveryImage (-1)
    $o = HObserve
    Assert ($o.eligible -and $o.value.items['Enabled'] -eq 1) 'tools that are on need no image check'

    $script:calls = @(); $script:reagentCode = 0; $script:reagentWorks = $true
    function HRunReagent([string]$verb) {
        $script:calls += ,@('reagentc', $verb)
        if ($script:reagentCode -eq 0 -and $script:reagentWorks) { RecoveryState $(if ($verb -ceq '/enable') { '1' } else { '0' }) }
        return $script:reagentCode
    }
    RecoveryState '1'
    HSetRecovery 'Enabled' 1
    Assert ((CallLog) -ceq '') 'tools that are already on are not touched'
    RecoveryState '0'
    HSetRecovery 'Enabled' 1
    Assert ((CallLog) -ceq 'reagentc:/enable' -and (HReadRecovery).Enabled -eq 1) "turned on: $(CallLog)"
    $script:calls = @()
    HSetRecovery 'Enabled' 0
    Assert ((CallLog) -ceq 'reagentc:/disable' -and (HReadRecovery).Enabled -eq 0) "turned back off: $(CallLog)"
    Reject { HSetRecovery 'Other' 1 } 'Unknown hardening item'
    Reject { HSetRecovery 'Enabled' 2 } 'Invalid recovery tools state'
    Reject { HSetRecovery 'Enabled' $null } 'Invalid recovery tools state'
    $script:reagentCode = 2
    Reject { HSetRecovery 'Enabled' 1 } 'Windows could not change the recovery tools (code 2)'
    $script:reagentCode = 0

    ${function:HSet} = $realHSet
    RecoveryState '0'
    RecoveryImage 4096
    RecoveryTool $true
    $script:calls = @()
    HWrite (Input '{"items":{"Enabled":1}}')
    Assert ((CallLog) -ceq 'reagentc:/enable' -and (HReadRecovery).Enabled -eq 1) "repair turns the tools on: $(CallLog)"
    # Undo is never held back by the offer checks (the image has moved into place by now).
    RecoveryImage (-1)
    $script:calls = @()
    HWrite (Input '{"items":{"Enabled":0}}')
    Assert ((CallLog) -ceq 'reagentc:/disable' -and (HReadRecovery).Enabled -eq 0) "undo turns them back off: $(CallLog)"
    # A repair is refused before anything runs when the image is gone.
    $script:calls = @()
    Reject { HWrite (Input '{"items":{"Enabled":1}}') } 'Not offered: the recovery tools are missing from this computer'
    Assert ((CallLog) -ceq '') 'nothing runs when the fix is not offered'
    # The tool reports success but nothing changed: stop, and do not run it again.
    RecoveryImage 4096
    $script:reagentWorks = $false
    $script:calls = @()
    Reject { HWrite (Input '{"items":{"Enabled":1}}') } 'Readback did not match'
    Assert ((CallLog) -ceq 'reagentc:/enable' -and (HReadRecovery).Enabled -eq 0) "a change that did not happen is not undone blindly: $(CallLog)"
    $script:reagentWorks = $true
    # The tool fails: there is nothing to put back.
    $script:reagentCode = 5
    $script:calls = @()
    Reject { HWrite (Input '{"items":{"Enabled":1}}') } 'Windows could not change the recovery tools'
    Assert ((CallLog) -ceq 'reagentc:/enable') "a failed change runs the tool once: $(CallLog)"
    $script:reagentCode = 0
    Reject { HWrite (Input '{"items":{"Enabled":1,"Other":0}}') } 'Unknown hardening item'
    Reject { HWrite (Input '{"items":{}}') } 'must contain every item'
} finally {
    ${function:HRecoveryDir} = $realRecoveryDir
    ${function:HReagentPath} = $realReagentPath
    ${function:HRunReagent} = $realRunReagent
    [IO.Directory]::Delete($recRoot, $true)
}

$wrJson = '{"id":"privacy.wifi_random_address","source":"WifiRandomAddress","dynamic":true,"reboot":false,"keys":[{"name":"*","path":"","valueName":"*","rule":"set","safe":[1],"absentSafe":false,"fix":1,"max":1}],' + $noGate + '}'
MakeSpec $wrJson
$wifiA = '{AAAAAAAA-1111-1111-1111-111111111111}'
$wifiB = '{BBBBBBBB-2222-2222-2222-222222222222}'
foreach ($ok in @($wifiA, $wifiB.ToLowerInvariant())) { Assert (HNameOk $ok) "wifi adapter id $ok" }
foreach ($bad in @('Wi-Fi', '{1111}', ($wifiA + "'; calc"), '')) { Assert (!(HNameOk $bad)) "wifi adapter id accepted: $bad" }
Assert ((HFixOf (HDef $wifiA) 0) -eq 1 -and (HIsSafe (HDef $wifiA) 1) -and !(HIsSafe (HDef $wifiA) 0)) 'random addresses off is repaired to on'
$realWifiAdapters = ${function:HWifiAdapters}
$realWifiState = ${function:HWifiRandomState}
$realRunHidden = ${function:HRunHidden}
$realNetshPath = ${function:HNetshPath}
if ($env:SystemRoot) { Assert ((& $realNetshPath) -clike '*\System32\netsh.exe') 'the Wi-Fi tool is the one in System32' }
$script:wifiList = @(@{ id = $wifiA; name = 'Wi-Fi' }, @{ id = $wifiB; name = 'Wi-Fi 2' })
$script:wifiStates = @{ $wifiA = 0; $wifiB = 1 }
$script:ran = @(); $script:netshCode = 0; $script:netshWorks = $true
$netRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'secblitz-netsh-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($netRoot)
$netshFile = [IO.Path]::Combine($netRoot, 'netsh.exe')
[IO.File]::WriteAllBytes($netshFile, [byte[]]@(77, 90))
try {
    function HWifiAdapters { return $script:wifiList }
    function HWifiRandomState([string]$id) { if ($script:wifiStates.ContainsKey($id)) { return $script:wifiStates[$id] }; return $null }
    function HNetshPath { return $netshFile }
    function HRunHidden([string]$exe, [string]$arguments) {
        $script:ran += ,@($exe, $arguments)
        if ($script:netshCode -eq 0 -and $script:netshWorks -and $arguments -cmatch '^wlan set randomization enabled=(yes|no) interface="Wi-Fi"$') {
            $script:wifiStates[$wifiA] = $(if ($Matches[1] -ceq 'yes') { 1 } else { 0 })
        }
        return $script:netshCode
    }

    $r = HReadWifiRandom
    Assert ($r.Count -eq 2 -and $r[$wifiA] -eq 0 -and $r[$wifiB] -eq 1) 'each adapter is read'
    Assert (HAnyUnsafe $r) 'an adapter with random addresses off needs a look'
    $r = HRead
    Assert ($r.Count -eq 2 -and $r[$wifiA] -eq 0) 'the dispatcher reads the Wi-Fi adapters'
    $script:wifiStates = @{ $wifiA = $null; $wifiB = 2 }
    Assert ((HReadWifiRandom).Count -eq 0) 'unreadable adapters are skipped'
    $script:wifiStates = @{ $wifiA = 0; $wifiB = 1 }

    HPreflight
    Assert $true 'offered when an adapter can be read'
    $script:wifiList = @()
    Reject { HPreflight } 'Not offered: this computer has no Wi-Fi adapter'
    $script:wifiList = @(@{ id = $wifiA; name = 'Wi-Fi' })
    $script:wifiStates = @{}
    Reject { HPreflight } 'Wi-Fi settings of this computer could not be read'

    $script:wifiList = @()
    $o = HObserve
    Assert (!$o.eligible -and $o.reason -ceq 'Not offered: this computer has no Wi-Fi adapter' -and $o.value.items.Count -eq 0) "no Wi-Fi adapter is a plain Not offered: $($o.reason)"
    $script:wifiList = @(@{ id = $wifiA; name = 'Wi-Fi' })
    $script:wifiStates = @{ $wifiA = 0 }
    $o = HObserve
    Assert ($o.eligible -and $o.value.items[$wifiA] -eq 0) 'offered while random addresses are off'
    $script:wifiStates = @{ $wifiA = 1 }
    $o = HObserve
    Assert ($o.eligible -and $o.value.items[$wifiA] -eq 1) 'nothing to offer once they are on'

    $script:wifiList = @(@{ id = $wifiA; name = 'Wi-Fi' }, @{ id = $wifiB; name = 'Wi-Fi 2' })
    $script:ran = @()
    HSetWifiRandom $wifiA 1
    Assert ($script:ran.Count -eq 1 -and $script:ran[0][0] -ceq $netshFile -and $script:ran[0][1] -ceq 'wlan set randomization enabled=yes interface="Wi-Fi"') "turned on: $($script:ran[0][1])"
    HSetWifiRandom $wifiB 0
    Assert ($script:ran.Count -eq 2 -and $script:ran[1][1] -ceq 'wlan set randomization enabled=no interface="Wi-Fi 2"') "turned off: $($script:ran[1][1])"
    Reject { HSetWifiRandom $wifiA 2 } 'Invalid Wi-Fi address setting'
    Reject { HSetWifiRandom 'Wi-Fi' 1 } 'Invalid Wi-Fi address setting'
    Reject { HSetWifiRandom '{CCCCCCCC-3333-3333-3333-333333333333}' 1 } 'exactly once'
    foreach ($badName in @('Wi-Fi" & calc', 'Wi-Fi\', ' Wi-Fi', ('x' * 257), '')) {
        $script:wifiList = @(@{ id = $wifiA; name = $badName })
        Reject { HSetWifiRandom $wifiA 1 } 'cannot be used safely'
    }
    Assert ($script:ran.Count -eq 2) 'nothing is run for a name that cannot be quoted safely'
    $script:wifiList = @(@{ id = $wifiA; name = 'Wi-Fi' })
    $script:netshCode = 1
    Reject { HSetWifiRandom $wifiA 1 } 'could not change the Wi-Fi address setting (code 1)'
    $script:netshCode = 0
    [IO.File]::Delete($netshFile)
    Reject { HSetWifiRandom $wifiA 1 } 'Wi-Fi tool is missing'
    [IO.File]::WriteAllBytes($netshFile, [byte[]]@(77, 90))

    $script:wifiStates = @{ $wifiA = 0 }
    $script:ran = @()
    HWrite (Input ('{"items":{"' + $wifiA + '":1}}'))
    Assert ($script:wifiStates[$wifiA] -eq 1 -and $script:ran.Count -eq 1) 'repair turns random addresses on'
    HWrite (Input ('{"items":{"' + $wifiA + '":0}}'))
    Assert ($script:wifiStates[$wifiA] -eq 0 -and $script:ran.Count -eq 2) 'undo turns them back off'
    Reject { HWrite (Input '{"items":{"{CCCCCCCC-3333-3333-3333-333333333333}":1}}') } 'no longer exists'
    Reject { HWrite (Input '{"items":{"Wi-Fi":1}}') } 'Unknown hardening item'
    $script:netshWorks = $false
    $script:ran = @()
    Reject { HWrite (Input ('{"items":{"' + $wifiA + '":1}}')) } 'Readback did not match'
    Assert ($script:wifiStates[$wifiA] -eq 0) 'a change that did not happen is reported, not assumed'
    $script:netshWorks = $true
    $script:netshCode = 1
    Reject { HWrite (Input ('{"items":{"' + $wifiA + '":1}}')) } 'could not change the Wi-Fi address setting'
    Assert ($script:wifiStates[$wifiA] -eq 0) 'a refused change leaves the adapter alone'
    $script:netshCode = 0
} finally {
    ${function:HWifiAdapters} = $realWifiAdapters
    ${function:HWifiRandomState} = $realWifiState
    ${function:HRunHidden} = $realRunHidden
    ${function:HNetshPath} = $realNetshPath
    [IO.Directory]::Delete($netRoot, $true)
}


# ---- browser.extensions_off: list changes with gaps and foreign entries, name checks, state
$idA = 'a' * 32; $idB = 'b' * 32; $idC = 'c' * 32
$nameA = "chromium:chrome:$idA"; $nameB = "chromium:chrome:$idB"; $nameC = "chromium:edge:$idC"
Assert (HAddonNameOk $nameA) 'a Chrome add-on name is accepted'
Assert (HAddonNameOk $nameC) 'an Edge add-on name is accepted'
foreach ($case in @(
        @('{"host_permissions":["*://*/*"]}', 'sites'),
        @('{"permissions":["<all_urls>"]}', 'sites'),
        @('{"permissions":["nativeMessaging"]}', 'programs'),
        @('{"permissions":["storage","nativeMessaging"],"host_permissions":["https://*/*"]}', 'sites,programs'),
        @('{"permissions":["storage"],"host_permissions":["https://example.com/*"]}', ''),
        @('{"permissions":[],"host_permissions":[]}', ''),
        @('{"name":"No permissions"}', ''),
        @('{"permissions":"<all_urls>"}', ''))) {
    $why = @(HAddonWhy (ConvertFrom-Json -InputObject $case[0])) -join ','
    Assert ($why -ceq $case[1]) "add-on permissions $($case[0]) read as '$why'"
}
foreach ($bad in @('', '*', "chromium:firefox:$idA", "chromium:chrome:$('q' * 32)", "chromium:chrome:$('a' * 31)", "chromium:chrome:$('a' * 33)", "chromium:chrome:$idA`n", "Chromium:chrome:$idA", "chromium:chrome:$($idA.ToUpper())")) {
    Assert (!(HAddonNameOk $bad)) "the add-on name '$bad' is refused"
}
$script:addonLists = @{ chrome = @{}; edge = @{} }
$script:addonMe = $true
$script:addonInventory = @(
    @{ name = $nameA; browser = 'chrome'; id = $idA; title = 'Alpha'; why = @('sites') },
    @{ name = $nameB; browser = 'chrome'; id = $idB; title = 'Beta'; why = @('sites', 'programs') },
    @{ name = $nameC; browser = 'edge'; id = $idC; title = 'Gamma'; why = @() })
function HAddonList([string]$browser) { $copy = @{}; foreach ($k in $script:addonLists[$browser].Keys) { $copy[$k] = $script:addonLists[$browser][$k] }; return $copy }
function HAddonPut([string]$browser, [string]$number, [string]$id) { $script:addonLists[$browser][$number] = $id }
function HAddonDrop([string]$browser, [string]$number) { $script:addonLists[$browser].Remove($number) }
function HAddonInventory { return $script:addonInventory }
function HInteractiveIsMe { return $script:addonMe }
function HStateNames { return @($script:undoState.Keys) }
function HStateGet([string]$name) { if ($script:undoState.ContainsKey($name)) { return $script:undoState[$name] }; return $null }
function HStateSet([string]$name, $data) { $script:undoState[$name] = $data }
function HStateRemove([string]$name) { $script:undoState.Remove($name) }
function HLabel([string]$key, [string]$text) { }
$script:undoState = @{}

$script:addonLists.chrome = @{ '1' = 'x' * 32; '4' = 'y' * 32; 'note' = 'z' * 32 }
$before = (HAddonList 'chrome')
Assert ((HAddonNextNumber $before) -eq 5) 'the next free number follows the highest one and ignores odd names'
Assert ((HAddonNextNumber @{}) -eq 1) 'an empty list starts at 1'
$r = HReadExtensions
Assert ($r[$nameA] -eq 1 -and $r[$nameB] -eq 1 -and $r[$nameC] -eq 1) 'add-ons that are on read 1'
HSetExtension $nameA 0
Assert ($script:addonLists.chrome['5'] -ceq $idA) 'turning off adds the id at the next free number'
Assert ($script:addonLists.chrome.Count -eq 4 -and $script:addonLists.chrome['1'] -ceq ('x' * 32) -and $script:addonLists.chrome['4'] -ceq ('y' * 32) -and $script:addonLists.chrome['note'] -ceq ('z' * 32)) 'foreign entries are untouched'
Assert ($script:undoState[$nameA].v -ceq '5') 'the exact number is recorded'
$r = HReadExtensions
Assert ($r[$nameA] -eq 0 -and $r[$nameB] -eq 1) 'a turned off add-on reads 0 and the others stay 1'
Reject { HSetExtension $nameA 0 } 'already turned off'
HSetExtension $nameB 0
Assert ($script:addonLists.chrome['6'] -ceq $idB) 'the second add-on takes the next number'
$script:addonLists.chrome.Remove('5')
Assert ((HReadExtensions)[$nameA] -eq 2) 'a removed entry reads as changed since'
$script:addonLists.chrome['5'] = $idB
Assert ((HReadExtensions)[$nameA] -eq 2) 'a different id at the number reads as changed since'
Reject { HSetExtension $nameA 1 } 'changed again'
Assert ($script:addonLists.chrome['5'] -ceq $idB -and $script:undoState.ContainsKey($nameA)) 'a changed entry is left alone'
$script:addonLists.chrome['5'] = $idA
HSetExtension $nameA 1
Assert (!$script:addonLists.chrome.ContainsKey('5') -and $script:addonLists.chrome['6'] -ceq $idB -and $script:addonLists.chrome['4'] -ceq ('y' * 32)) 'undo removes only its own value and never renumbers'
Assert (!$script:undoState.ContainsKey($nameA)) 'undo clears the saved state'
HSetExtension $nameB 1
Assert ($script:addonLists.chrome.Count -eq 3) 'the list is back to its foreign entries'
HSetExtension $nameA 0
Assert ($script:addonLists.chrome['5'] -ceq $idA) 'a freed number is reused only when it is the highest'
HSetExtension $nameA 1
$script:undoState = @{ $nameB = @{ v = '9'; id = $idB } }
HSetExtension $nameB 1
Assert ($script:undoState.Count -eq 0) 'undo of an entry that is already gone just forgets it'

HSetExtension $nameC 0
Assert ($script:addonLists.edge['1'] -ceq $idC -and $script:addonLists.chrome.Count -eq 3) 'Edge has its own list'
HSetExtension $nameC 1
Assert ($script:addonLists.edge.Count -eq 0) 'Edge undo empties its list'

Reject { HSetExtension 'chromium:chrome:short' 0 } 'Invalid browser add-on'
Reject { HSetExtension $nameA 2 } 'Invalid browser add-on'
Reject { HSetExtension "chromium:chrome:$('d' * 32)" 0 } 'no longer needs a change'
$script:addonLists.chrome['7'] = '*'
Reject { HSetExtension $nameA 0 } 'rules changed'
Assert (!$script:undoState.ContainsKey($nameA) -and $script:addonLists.chrome.Count -eq 4) 'a catch-all rule stops the change'
Reject { HAddonPreflight } 'already turns off every add-on'
$script:addonLists.chrome.Remove('7')
$script:addonLists.chrome['8'] = $null
Reject { HAddonPreflight } 'could not be read'
$script:addonLists.chrome.Remove('8')
HAddonPreflight
Assert $true 'a list with only foreign ids passes the preflight'
$script:addonMe = $false
Reject { HSetExtension $nameA 0 } 'another account'
Assert (!(HReadExtensions).ContainsKey($nameA)) 'another account is not offered the add-ons'
$script:addonMe = $true

Write-Output "Hardening PowerShell fixtures passed: $script:checks checks"
