# bluetooth-janx-unified-v10.ps1
# PS 7.5 host with a PS 5.1 WinRT worker (no .AsTask). Includes live BLE sniffer.

param([string]$PreferredAdapterMatch = "5.3")

# ---------------- Common helpers ----------------
$script:HasPnpDevice = $false
function Ensure-PnpDeviceModule {
  try { Import-Module PnpDevice -ErrorAction Stop; $script:HasPnpDevice = $true } catch { $script:HasPnpDevice = $false }
}
Ensure-PnpDeviceModule

function Convert-IfJson {
  param($Value, [int]$Depth = 10)
  if ($Value -is [string]) {
    $s = $Value.Trim()
    if ($s.StartsWith('{') -or $s.StartsWith('[')) { return ($s | ConvertFrom-Json -Depth $Depth) }
    # Attempt to strip preface noise and extract JSON
    $startObj = $s.IndexOf('{'); $startArr = $s.IndexOf('[')
    $start = @($startObj, $startArr) | Where-Object { $_ -ge 0 } | Sort-Object | Select-Object -First 1
    if ($start -ge 0) {
      $candidate = $s.Substring($start)
      $endBrace = $candidate.LastIndexOf('}'); $endBracket = $candidate.LastIndexOf(']')
      $end = [Math]::Max($endBrace, $endBracket)
      if ($end -ge 0) {
        $json = $candidate.Substring(0, $end + 1)
        try { return ($json | ConvertFrom-Json -Depth $Depth) } catch { }
      }
    }
    return $s  # return raw text if still not JSON
  } else {
    return $Value  # already an object
  }
}

# ---------------- PnP tasks in PS 7.5 ----------------
function Get-PairedDevices {
  if (-not $script:HasPnpDevice) { Write-Warning "PnpDevice module missing; returning empty."; return @() }
  Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName } |
    Sort-Object FriendlyName |
    Select-Object Status, FriendlyName, InstanceId
}
function Disable-Enable-Device {
  param([Parameter(Mandatory)][string]$InstanceId)
  if (-not $script:HasPnpDevice) { Write-Warning "PnpDevice module missing."; return }
  Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep 1.5
  Enable-PnpDevice  -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Toggled device: $InstanceId" -ForegroundColor Yellow
}
function Toggle-BtRadio {
  param([string]$Vid='VID_0BDA')
  if (-not $script:HasPnpDevice) { Write-Warning "PnpDevice module missing."; return }
  $d = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match $Vid } | Select-Object -First 1
  if (-not $d) { Write-Error "BT radio with $Vid not found."; return }
  Write-Host "Toggling: $($d.FriendlyName) [$($d.InstanceId)]"
  Disable-Enable-Device -InstanceId $d.InstanceId
}
function Remove-BtDevice {
  param([Parameter(Mandatory)][string]$Match)
  if ($script:HasPnpDevice) {
    $dev = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object {
      $_.InstanceId -eq $Match -or ($_.FriendlyName -and $_.FriendlyName -like "*$Match*")
    } | Select-Object -First 1
    if ($dev) {
      Write-Host "Removing (PnP): $($dev.FriendlyName) [$($dev.InstanceId)]" -ForegroundColor Yellow
      Remove-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
      Write-Host "Removed." -ForegroundColor Green
      return
    }
  }
  Write-Warning "Falling back to 'pnputil /remove-device'."
  & pnputil.exe /remove-device "$Match" | Write-Host
}

# ---------------- PS 5.1 bridge ----------------
function Get-Ps51Path {
  $p = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path $p)) { throw "Windows PowerShell 5.1 not found at: $p" }
  return $p
}

function Invoke-PS51 {
  param(
    [Parameter(Mandatory)][string]$Operation,  # Scan, PairId, PairName, Adapters, SetRadio, AdapterInfo, Sniffer
    [hashtable]$Args = @{},
    [switch]$StreamToConsole
  )
  $ps51 = Get-Ps51Path

  # Worker code (native WinRT, no noisy banners)
  $helper = @'
#Requires -Version 5.1
param([Parameter(Mandatory)][string]$Operation,[hashtable]$Args)
$ErrorActionPreference='Stop'; $InformationPreference='SilentlyContinue'
function Ensure-WinRT { $tn='Windows.Devices.Enumeration.DeviceInformation, Windows, ContentType=WindowsRuntime'; $t=[type]::GetType($tn,$false);
  if(-not $t){ $wm=Join-Path $env:WINDIR 'System32\WinMetadata\Windows.winmd'; if(Test-Path $wm){try{Add-Type -Path $wm -ErrorAction Stop}catch{}}; $t=[type]::GetType($tn,$false) }
  if(-not $t){ throw 'WinRT projection unavailable.' } }
function Await-WinRT($op){ $t=[type]::GetType('Windows.Foundation.AsyncStatus, Windows, ContentType=WindowsRuntime'); $Started=[enum]::Parse($t,'Started'); while($op.Status -eq $Started){Start-Sleep -Milliseconds 50}; if($op.PSObject.Methods.Name -contains 'GetResults'){return $op.GetResults()}}
function Get-Aqs([ValidateSet('BLE','Classic','All')]$Mode='All'){ switch($Mode){'BLE'{'System.Devices.Aep.ProtocolId:="{bb7bb05e-5972-42b5-94fc-76eaa7084d49}"'}'Classic'{'System.Devices.Aep.ProtocolId:="{e0cbf06c-cd8b-4647-bb8a-263B43F0F974}"'}default{'System.Devices.Aep.ProtocolId:="{bb7bb05e-5972-42b5-94fc-76eaa7084d49}" OR System.Devices.Aep.ProtocolId:="{e0cbf06c-cd8b-4647-bb8a-263B43F0F974}"'}}}
function Find-Devices($Mode='All'){
  Ensure-WinRT
  $aqs=Get-Aqs $Mode
  $coll=Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
  $coll | ForEach-Object {
    [pscustomobject]@{
      Name     = $_.Name
      Id       = $_.Id
      IsPaired = (try { [bool]$_.Pairing.IsPaired } catch { $null })
    }
  } | Sort-Object Name
}
function Pair-ById([string]$Id,[string]$Pin){
  Ensure-WinRT
  if ($Id -notlike 'Bluetooth#*') { return @{Status='Error';Error='Provide DeviceInformation.Id starting with Bluetooth#'} }
  $di=Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($Id)); if(-not $di){return @{Status='Error';Error='DeviceInformation not found'}}
  try{ if($di.Pairing.IsPaired){ return @{Status='AlreadyPaired';Name=$di.Name;Messages=@()} } } catch{}
  $script:PairingPin=$Pin; $script:OutMsgs=New-Object System.Collections.ArrayList
  $custom=$di.Pairing.Custom
  $h=Register-ObjectEvent -InputObject $custom -EventName PairingRequested -Action {
    $req=$EventArgs; switch($req.PairingKind){
      'DisplayPin'      { [void]$script:OutMsgs.Add(('PIN: {0}' -f $req.Pin)); $req.Accept() }
      'ConfirmPinMatch' { [void]$script:OutMsgs.Add(('Confirm PIN: {0}' -f $req.Pin)); $req.Accept() }
      'ConfirmOnly'     { [void]$script:OutMsgs.Add('ConfirmOnly'); $req.Accept() }
      'ProvidePin'      { $p=$script:PairingPin; if(-not $p){$p='0000'}; [void]$script:OutMsgs.Add('Providing PIN: ' + $p); $req.Accept($p) }
      default           { [void]$script:OutMsgs.Add('Accept default'); $req.Accept() }
    }
  }
  try{
    $kT=[type]::GetType('Windows.Devices.Enumeration.DevicePairingKinds, Windows, ContentType=WindowsRuntime')
    $k=[enum]::Parse($kT,'ConfirmOnly') -bor [enum]::Parse($kT,'DisplayPin') -bor [enum]::Parse($kT,'ConfirmPinMatch') -bor [enum]::Parse($kT,'ProvidePin')
    $lT=[type]::GetType('Windows.Devices.Enumeration.DevicePairingProtectionLevel, Windows, ContentType=WindowsRuntime'); $Def=[enum]::Parse($lT,'Default'); $None=[enum]::Parse($lT,'None')
    $r =Await-WinRT ($custom.PairAsync($Def,$k));   if($r.Status  -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired){return @{Status='Paired'       ;Name=$di.Name;Messages=$script:OutMsgs}}
    $r2=Await-WinRT ($di.Pairing.PairAsync($None)); if($r2.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired){return @{Status='PairedBasic'  ;Name=$di.Name;Messages=$script:OutMsgs}}
    $r3=Await-WinRT ($di.Pairing.PairAsync($Def));  if($r3.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired){return @{Status='PairedDefault';Name=$di.Name;Messages=$script:OutMsgs}}
    return @{Status='Failed';Name=$di.Name;Details="$($r.Status)/$($r2.Status)/$($r3.Status)";Messages=$script:OutMsgs}
  } finally { if($h){Unregister-Event -SourceIdentifier $h.Name | Out-Null} }
}
function Pair-ByName([string]$Name,[int]$Retries=3,[int]$Between=2,[string]$Pin){
  $rx=New-Object System.Text.RegularExpressions.Regex ([regex]::Escape($Name)),'IgnoreCase'
  for($i=1;$i -le $Retries;$i++){
    $d=Find-Devices All | Where-Object { $_.Name -and $rx.IsMatch($_.Name) -and (-not $_.IsPaired) } | Select-Object -First 1
    if($d){ return (Pair-ById -Id $d.Id -Pin $Pin) }
    Write-Host ("[{0}/{1}] No discoverable match for '{2}'. Re-scanning..." -f $i,$Retries,$Name)
    Start-Sleep -Seconds $Between
  }
  return @{Status='NoMatch';Name=$Name}
}
function Adapters {
  Ensure-WinRT
  $radios=Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync())
  $bt=$radios | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth }
  $bt | ForEach-Object { [pscustomobject]@{ Name=$_.Name; State=$_.State; Id=$_.DeviceId } } | Sort-Object Name
}
function SetRadio([string]$NameOrId,[string]$State){
  Ensure-WinRT
  $radios=Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync())
  $bt=$radios | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth }
  $m=$bt | Where-Object { $_.DeviceId -eq $NameOrId -or ($_.Name -and $_.Name -like "*$NameOrId*") } | Select-Object -First 1
  if(-not $m){ return @{ Status='Error'; Error="No adapter matched '$NameOrId'." } }
  $target= if($State -eq 'On'){ [Windows.Devices.Radios.RadioState]::On } else { [Windows.Devices.Radios.RadioState]::Off }
  [void](Await-WinRT ($m.SetStateAsync($target)))
  return @{ Name=$m.Name; State="$($target)" }
}
function AdapterInfo {
  Ensure-WinRT
  $a=$null; try{$a=Await-WinRT ([Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync())}catch{}
  $r=$null; if($a){try{$r=Await-WinRT ($a.GetRadioAsync())}catch{}}
  if(-not $r){ $rs=Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync()); $r=$rs | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth } | Select-Object -First 1 }
  $addr=$null; if($a -and $a.BluetoothAddress){ $addr=('{0:X12}' -f $a.BluetoothAddress) }
  [pscustomobject]@{ HasDefaultAdapter=[bool]$a; BluetoothAddressHex=$addr; IsLowEnergySupported=($a -and $a.IsLowEnergySupported); IsClassicSupported=($a -and $a.IsClassicSupported); RadioName=($r.Name); RadioState=($r.State); RadioId=($r.DeviceId) }
}
switch($Operation){
  'Scan'        { Find-Devices ($Args.Mode) | ConvertTo-Json -Depth 6; break }
  'PairId'      { (Pair-ById -Id $Args.Id -Pin $Args.Pin) | ConvertTo-Json -Depth 6; break }
  'PairName'    { (Pair-ByName -Name $Args.Name -Retries $Args.Retries -Between $Args.Between -Pin $Args.Pin) | ConvertTo-Json -Depth 6; break }
  'Adapters'    { Adapters | ConvertTo-Json -Depth 5; break }
  'SetRadio'    { (SetRadio -NameOrId $Args.NameOrId -State $Args.State) | ConvertTo-Json -Depth 4; break }
  'AdapterInfo' { AdapterInfo | ConvertTo-Json -Depth 6; break }
  'Sniffer'     {
    Ensure-WinRT
    $w=[Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()
    $sT=[type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode, Windows, ContentType=WindowsRuntime')
    if($sT){ $Active=[enum]::Parse($sT,'Active'); try{$w.ScanningMode=$Active}catch{} }
    if($Args.NameLike){ $script:Filter=New-Object System.Text.RegularExpressions.Regex ($Args.NameLike),'IgnoreCase' } else { $script:Filter=$null }
    Register-ObjectEvent -InputObject $w -EventName Received -SourceIdentifier 'ADV' -Action {
      $e=$EventArgs; $name=$e.Advertisement.LocalName
      if($script:Filter -and -not $script:Filter.IsMatch([string]$name)){ return }
      $mac=('{0:X12}' -f $e.BluetoothAddress) -replace '(.{2})(?=.)','$1:'
      Write-Host ("ADV  MAC={0,-17} RSSI={1,4}dBm  Name={2}" -f $mac,$e.RawSignalStrengthInDBm, ($name -as [string]))
    } | Out-Null
    try{ $w.Start(); Start-Sleep -Seconds $Args.Seconds; $w.Stop() } finally { Unregister-Event -SourceIdentifier 'ADV' -ErrorAction SilentlyContinue | Out-Null }
    break
  }
  default       { @{ Status='Error'; Error=("Unknown operation: {0}" -f $Operation) } | ConvertTo-Json -Depth 3; break }
}
'@

  $payload = @{ Operation = $Operation; Args = $Args } | ConvertTo-Json -Depth 6
  $runner = @"
`$ErrorActionPreference='Stop'
`$inputJson = @'
$payload
'@ | ConvertFrom-Json
& {
$helper
} -Operation `$inputJson.Operation -Args `$inputJson.Args
"@

  if ($StreamToConsole) {
    & $ps51 -NoProfile -ExecutionPolicy Bypass -Command $runner
    return
  } else {
    $out = & $ps51 -NoProfile -ExecutionPolicy Bypass -Command $runner 2>&1
    $joined = ($out | Out-String)
    return $joined
  }
}

# ---------------- Public wrappers (PS 7.5) ----------------
function Get-BtAdapters {
  $res = Invoke-PS51 -Operation Adapters
  Convert-IfJson $res | Sort-Object Name
}
function Get-BtAdapterInfo {
  Convert-IfJson (Invoke-PS51 -Operation AdapterInfo)
}
function Set-BtAdapterState {
  param([Parameter(Mandatory)][ValidateSet('On','Off')]$State,[Parameter(Mandatory)][string]$NameOrId)
  [void](Invoke-PS51 -Operation SetRadio -Args @{ NameOrId=$NameOrId; State=$State })
  Get-BtAdapters | Where-Object { $_.Name -like "*$NameOrId*" -or $_.Id -eq $NameOrId }
}
function Find-BtDevices {
  param([ValidateSet('BLE','Classic','All')]$Mode='All')
  Convert-IfJson (Invoke-PS51 -Operation Scan -Args @{ Mode=$Mode }) | Sort-Object Name
}
function Pair-BtDevice {
  param([Parameter(Mandatory)][string]$DeviceIdOrAddress,[string]$Pin)
  if ($DeviceIdOrAddress -notlike 'Bluetooth#*') { throw "Provide DeviceInformation.Id starting with 'Bluetooth#'." }
  Convert-IfJson (Invoke-PS51 -Operation PairId -Args @{ Id=$DeviceIdOrAddress; Pin=$Pin })
}
function Pair-BtByName {
  param([Parameter(Mandatory)][string]$NameMatch,[string]$Pin,[int]$Retries=8,[int]$BetweenSeconds=2)
  Convert-IfJson (Invoke-PS51 -Operation PairName -Args @{ Name=$NameMatch; Retries=$Retries; Between=$BetweenSeconds; Pin=$Pin })
}
function Start-BleSniffer {
  param([int]$Seconds=15,[string]$NameLike)
  Write-Host "Starting live sniffer (PS 5.1 child)..." -ForegroundColor Cyan
  Invoke-PS51 -Operation Sniffer -Args @{ Seconds=$Seconds; NameLike=$NameLike } -StreamToConsole
}

# --------- Listeners (run sniffer + pairing attempts together) ---------
function Listen-ForKeyboard {
  param(
    [string]$NameMatch = 'Keyboard K380',
    [ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',
    [int]$TimeoutMinutes = 5,
    [string]$Pin
  )
  $stopAt = (Get-Date).AddMinutes($TimeoutMinutes)

  # kick off sniffer as a background job so ADV frames show up while we loop
  $sniffJob = Start-Job -ScriptBlock {
    param($sec,$filter)
    & $using:PSCommandPath  # no-op if sourced; ensure functions in scope
    Start-BleSniffer -Seconds $sec -NameLike $filter
  } -ArgumentList @([int]([TimeSpan]::FromMinutes($TimeoutMinutes).TotalSeconds), $NameMatch)

  Write-Host "Listening for '$NameMatch' and attempting auto-pair… (Mode=$Mode, Timeout=$TimeoutMinutes min)" -ForegroundColor Cyan
  do {
    $result = Pair-BtByName -NameMatch $NameMatch -Retries 1 -BetweenSeconds 1 -Pin $Pin
    if ($result -and $result.Status -match '^Paired') {
      Write-Host ("Paired: {0}" -f $result.Name) -ForegroundColor Green
      break
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $stopAt)

  if ($sniffJob) { Receive-Job $sniffJob -Wait -AutoRemoveJob | Out-Null }
  if (-not $result -or ($result.Status -notmatch '^Paired')) {
    Write-Warning "Finished listening window without a successful pair for '$NameMatch'."
  }
}

function Listen-ForPairables {
  param(
    [ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',
    [int]$TimeoutMinutes = 3
  )
  $seconds = [int]([TimeSpan]::FromMinutes($TimeoutMinutes).TotalSeconds)
  Write-Host "Sniffing for ANY pairable device (ADV frames) for $TimeoutMinutes min…" -ForegroundColor Cyan
  Start-BleSniffer -Seconds $seconds
}

Write-Host "Loaded bluetooth-janx-unified-v10.ps1 (PS7 bridge + 5.1 WinRT). Commands:" -ForegroundColor Cyan
@"
Get-BtAdapterInfo
Get-BtAdapters
Set-BtAdapterState -State On -NameOrId '5.3'
Find-BtDevices -Mode All | ft
Pair-BtByName -NameMatch 'Keyboard K380' -Retries 10 -BetweenSeconds 1 -Pin '777036'
Pair-BtDevice -DeviceIdOrAddress 'Bluetooth#Bluetooth...'
Find-BtDevices -Mode All | ft
Listen-ForKeyboard -NameMatch 'Keyboard K380' -TimeoutMinutes 3 -Pin '777036'
Get-PairedDevices
Toggle-BtRadio
Remove-BtDevice -Match 'Logitech'
"@ | Write-Host
