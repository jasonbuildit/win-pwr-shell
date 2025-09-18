#Requires -Version 5.1
<#  bluetooth-janx-all-v8.ps1  (Windows PowerShell 5.1 x64)
    - Admin + WinRT bootstrap (forces PS 5.1 x64; loads Windows.winmd if needed)
    - Manual WinRT await (no .AsTask)
    - Adapter helpers: Get-BtAdapterInfo, Force-BtDefaultAdapter, Get/Set state
    - Live BLE sniffer (PS 5.1–safe)
    - Snapshot scan (BLE/Classic)
    - Hardened pairing (requests all kinds + fallbacks)
    - Pair-BtByName (retries)
    - BLE connect
    - PnP list/toggle/remove (+ pnputil fallback)
    - Prefer BT 5.3 dongle by name match
    - Listen-ForKeyboard: prints live advertisements AND pairs
    - Listen-ForPairables
#>

param(
  [string]$PreferredAdapterMatch = "5.3",
  [ValidateSet("BLE","Classic","All")]
  [string]$ScanMode = "All"
)

# -------------------- Admin guard --------------------
function Ensure-Admin {
  $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pri = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $pri.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Re-launching elevated..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb  = "runas"
    [void][System.Diagnostics.Process]::Start($psi)
    exit
  }
}
Ensure-Admin

# -------------------- WinRT bootstrap --------------------
function Ensure-WinRT {
  if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    $ps51 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path $ps51)) { throw "This script requires Windows PowerShell 5.1 (64-bit)." }
    Start-Process $ps51 -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
  }
  if (-not [Environment]::Is64BitProcess) {
    $ps51x64 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process $ps51x64 -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
  }

  $typeName = 'Windows.Devices.Enumeration.DeviceInformation, Windows, ContentType=WindowsRuntime'
  $t = [type]::GetType($typeName, $false)
  if (-not $t) {
    $winmd = Join-Path $env:WINDIR 'System32\WinMetadata\Windows.winmd'
    if (Test-Path $winmd) {
      try { Add-Type -Path $winmd -ErrorAction Stop } catch { }
      $t = [type]::GetType($typeName, $false)
    }
  }
  if (-not $t) { throw "WinRT Bluetooth APIs unavailable. Confirm PS 5.1 x64 and Windows.winmd presence." }
}
Ensure-WinRT

# -------------------- PnP module guard --------------------
function Ensure-PnpDeviceModule {
  try { Import-Module PnpDevice -ErrorAction Stop; $script:HasPnpDevice = $true }
  catch { $script:HasPnpDevice = $false }
}
Ensure-PnpDeviceModule

# -------------------- Manual WinRT await --------------------
function Await-WinRT {
  param([Parameter(Mandatory=$true)]$op)
  if ($op -and $op.PSObject -and ($op.PSObject.Methods.Name -contains 'Start')) { try { $op.Start() } catch { } }
  $AsyncStatusType = [type]::GetType('Windows.Foundation.AsyncStatus, Windows, ContentType=WindowsRuntime')
  if (-not $AsyncStatusType) { throw "WinRT AsyncStatus type not found." }
  $Started   = [enum]::Parse($AsyncStatusType,'Started')
  $Error     = [enum]::Parse($AsyncStatusType,'Error')
  $Canceled  = [enum]::Parse($AsyncStatusType,'Canceled')
  while ($op.Status -eq $Started) { Start-Sleep -Milliseconds 50 }
  if ($op.Status -eq $Error)    { try { throw "WinRT async error: $($op.ErrorCode)" } catch { throw "WinRT async error (unspecified)" } }
  if ($op.Status -eq $Canceled) { throw "WinRT async canceled." }
  if ($op.PSObject.Methods.Name -contains 'GetResults') { return $op.GetResults() }
  return $null
}

# -------------------- Utilities --------------------
function Get-BtAqsFilter {
  param([ValidateSet("BLE","Classic","All")]$Mode = "All")
  switch ($Mode) {
    "BLE"     { 'System.Devices.Aep.ProtocolId:="{bb7bb05e-5972-42b5-94fc-76eaa7084d49}"' }
    "Classic" { 'System.Devices.Aep.ProtocolId:="{e0cbf06c-cd8b-4647-bb8a-263B43F0F974}"' }
    default   { 'System.Devices.Aep.ProtocolId:="{bb7bb05e-5972-42b5-94fc-76eaa7084d49}" OR System.Devices.Aep.ProtocolId:="{e0cbf06c-cd8b-4647-bb8a-263B43F0F974}"' }
  }
}
function Format-BtMac { param([Parameter(Mandatory)][UInt64]$Address) $hex=('{0:X12}' -f $Address); $bytes=@(); for($i=0;$i -lt 12;$i+=2){$bytes+=$hex.Substring($i,2)}; ($bytes -join ':') }
function Get-BtMacFromDeviceId {
  param([Parameter(Mandatory)][string]$DeviceId)
  try { $ble = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromIdAsync($DeviceId)); if ($ble -and $ble.BluetoothAddress) { return (Format-BtMac $ble.BluetoothAddress) } } catch { }
  try { $bd  = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothDevice]::FromIdAsync($DeviceId));  if ($bd  -and $bd.BluetoothAddress) { return (Format-BtMac $bd.BluetoothAddress) } } catch { }
  return $null
}

# -------------------- Adapter diagnostics & control --------------------
function Get-BtAdapters {
  $radios = Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync())
  $bt = $radios | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth }
  $items = foreach ($r in $bt) {
    [pscustomobject]@{ Name=$r.Name; State=$r.State; Id=$r.DeviceId; Score=if ($r.Name -match [regex]::Escape($PreferredAdapterMatch)) {100}else{0}; _raw=$r }
  }
  $items | Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Name';Descending=$false}
}
function Set-BtAdapterState {
  [CmdletBinding(DefaultParameterSetName='ByObject')]
  param(
    [Parameter(Mandatory, Position=0)][ValidateSet("On","Off")][string]$State,
    [Parameter(ParameterSetName='ByObject')]$Radio,
    [Parameter(ParameterSetName='ByName')][string]$NameOrId
  )
  if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    $adapters = Get-BtAdapters; if (-not $adapters) { throw "No Bluetooth radios detected." }
    if ($NameOrId -match '^(primary|first)$') { $Radio = ($adapters | Select-Object -First 1)._raw }
    elseif ($NameOrId -match '^(secondary|second)$') { $Radio = ($adapters | Select-Object -Skip 1 | Select-Object -First 1)._raw }
    else { $match = $adapters | Where-Object { $_.Id -eq $NameOrId -or ($_.Name -and $_.Name -like "*$NameOrId*") } | Select-Object -First 1; if (-not $match) { throw "No adapter matched '$NameOrId'." }; $Radio = $match._raw }
  }
  if (-not $Radio) { throw "Provide -Radio (from Get-BtAdapters)._raw or use -NameOrId." }
  if ($State -eq "On")  { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::On))) }
  else                   { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::Off))) }
}
function Get-BtAdapterInfo {
  try {
    $adapter = $null
    try { $adapter = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync()) } catch { }

    $radio = $null
    if ($adapter) { try { $radio = Await-WinRT ($adapter.GetRadioAsync()) } catch { } }
    if (-not $radio) {
      $radios = Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync())
      $radio  = $radios | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth } | Select-Object -First 1
    }

    # Precompute values for PS 5.1
    $hasDefault = [bool]$adapter
    $addrHex    = $null; if ($adapter -and $adapter.BluetoothAddress) { $addrHex = '{0:X12}' -f $adapter.BluetoothAddress }
    $isLESup    = $null; if ($adapter) { $isLESup    = $adapter.IsLowEnergySupported }
    $isClSup    = $null; if ($adapter) { $isClSup    = $adapter.IsClassicSupported }
    $isPerSup   = $null; if ($adapter) { $isPerSup   = $adapter.IsPeripheralRoleSupported }
    $isCentSup  = $null; if ($adapter) { try { $isCentSup = $adapter.IsCentralRoleSupported } catch { $isCentSup = $null } }
    $radioName  = $null; if ($radio) { $radioName  = $radio.Name }
    $radioState = $null; if ($radio) { $radioState = $radio.State }
    $radioId    = $null; if ($radio) { $radioId    = $radio.DeviceId }

    $obj = [pscustomobject]@{
      HasDefaultAdapter          = $hasDefault
      BluetoothAddressHex        = $addrHex
      IsLowEnergySupported       = $isLESup
      IsClassicSupported         = $isClSup
      IsPeripheralRoleSupported  = $isPerSup
      IsCentralRoleSupported     = $isCentSup
      RadioName                  = $radioName
      RadioState                 = $radioState
      RadioId                    = $radioId
    }

    Write-Host "Adapter/Radio capabilities:" -ForegroundColor Cyan
    $obj | Format-List *

    if (-not $adapter) {
      Write-Warning "No Default BluetoothAdapter. Ensure preferred radio is ON and others OFF."
      Write-Host "Tips:" -ForegroundColor Yellow
      Write-Host "  • Get-BtAdapters | ft" -ForegroundColor DarkGray
      Write-Host "  • Set-BtAdapterState On -NameOrId primary; turn off secondaries" -ForegroundColor DarkGray
      Write-Host "  • Ensure 'Bluetooth Support Service' is running: Get-Service bthserv | Start-Service" -ForegroundColor DarkGray
    }

    return $obj
  } catch { Write-Error "Get-BtAdapterInfo failed: $($_.Exception.Message)" }
}
function Force-BtDefaultAdapter {
  param([string]$PreferNameOrId = $PreferredAdapterMatch,[int]$TimeoutSeconds = 10)
  $ads = Get-BtAdapters; if (-not $ads) { throw "No Bluetooth radios found." }
  $match = $ads | Where-Object { $_.Name -like "*$PreferNameOrId*" -or $_.Id -eq $PreferNameOrId } | Select-Object -First 1
  if (-not $match) { $match = $ads | Select-Object -First 1 }
  Write-Host "Preferring adapter: $($match.Name)" -ForegroundColor Cyan
  if ($match.State -ne [Windows.Devices.Radios.RadioState]::On) { Set-BtAdapterState On -Radio $match._raw }
  foreach ($r in $ads) { if ($r.Id -ne $match.Id -and $r.State -eq [Windows.Devices.Radios.RadioState]::On) { Write-Host "Turning OFF secondary: $($r.Name)" -ForegroundColor DarkGray; Set-BtAdapterState Off -Radio $r._raw } }
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do { try { $a = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync()); if ($a) { Write-Host "Default BluetoothAdapter is now present." -ForegroundColor Green; return $true } } catch { } Start-Sleep -Milliseconds 300 } while ((Get-Date) -lt $deadline)
  Write-Warning "Timed out waiting for Default adapter."; return $false
}

# -------------------- Live BLE sniffer (PS 5.1 safe) --------------------
# -------------------- Live BLE sniffer (PS 5.1 safe) --------------------
function Start-BleSniffer {
  param(
    [int]$Seconds = 15,
    [string]$NameLike,
    [int]$MaxRows = 200
  )

  # State shared with event action
  $script:BleSniff_Count   = 0
  $script:BleSniff_MaxRows = $MaxRows
  if ($NameLike) {
    $script:BleSniff_NameRegex = New-Object System.Text.RegularExpressions.Regex ($NameLike), 'IgnoreCase'
  } else {
    $script:BleSniff_NameRegex = $null
  }

  # Type checks
  $watcherType = [type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows, ContentType=WindowsRuntime')
  if (-not $watcherType) { throw "BLE Advertisement types unavailable (WinRT projection missing)." }

  # Watcher
  $watcher = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()

  # Active scanning for better LocalName
  $scanModeType = [type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode, Windows, ContentType=WindowsRuntime')
  if ($scanModeType) {
    $Active = [enum]::Parse($scanModeType,'Active')
    try { $watcher.ScanningMode = $Active } catch { }
  }

  # Helper callable from event runspace
  function script:__FmtUuids([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisement]$adv) {
    try {
      $uuids = @()
      foreach ($u in $adv.ServiceUuids) { $uuids += $u.ToString() }
      if ($uuids.Count -gt 0) { return ($uuids -join ',') }
    } catch { }
    return $null
  }

  # Register handler (fixed SourceIdentifier; no -PassThru)
  $srcId = 'BleSniffer_Received'
  Register-ObjectEvent -InputObject $watcher -EventName Received -SourceIdentifier $srcId -Action {
    try {
      $args  = $EventArgs
      $mac   = ('{0:X12}' -f $args.BluetoothAddress) -replace '(.{2})(?=.)','$1:'
      $rssi  = $args.RawSignalStrengthInDBm
      $name  = $args.Advertisement.LocalName
      $svc   = script:__FmtUuids($args.Advertisement)

      if ($script:BleSniff_NameRegex -and (-not $script:BleSniff_NameRegex.IsMatch([string]$name))) { return }

      $script:BleSniff_Count++
      if ($script:BleSniff_Count -gt $script:BleSniff_MaxRows) { return }

      $safeName = if ([string]::IsNullOrWhiteSpace($name)) { '(none)' } else { $name }
      $safeSvc  = if ([string]::IsNullOrWhiteSpace($svc))  { '' } else { $svc }

      # Format first (PS 5.1-safe), then Write-Host
      $msg = "ADV {0,4}  MAC={1,-17} RSSI={2,4}dBm  Name={3}  Services=[{4}]" -f `
             $script:BleSniff_Count, $mac, $rssi, $safeName, $safeSvc
      Write-Host $msg -ForegroundColor Gray
    } catch {
      Write-Warning ("Sniffer event error: {0}" -f $_.Exception.Message)
    }
  } | Out-Null

  try {
    $label = if ($NameLike) { "filter NameLike='$NameLike'" } else { "no name filter" }
    Write-Host ("Starting BLE sniffer... {0}" -f $label) -ForegroundColor Cyan

    $watcher.Start()

    if ($Seconds -gt 0) {
      $deadline = (Get-Date).AddSeconds($Seconds)
      while ((Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
      $watcher.Stop()
    } else {
      Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
      while ($true) { Start-Sleep -Seconds 1 }
    }
  }
  finally {
    try {
      if ($watcher.Status -ne ([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcherStatus]::Stopped)) {
        $watcher.Stop()
      }
    } catch { }
    Unregister-Event -SourceIdentifier $srcId -ErrorAction SilentlyContinue | Out-Null
    Remove-Item function:\__FmtUuids -ErrorAction SilentlyContinue
    Remove-Variable -Name BleSniff_NameRegex -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name BleSniff_Count     -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name BleSniff_MaxRows   -Scope Script -ErrorAction SilentlyContinue
  }
}

# -------------------- Scanning (snapshot) --------------------
function Find-BtDevices {
  param([ValidateSet("BLE","Classic","All")]$Mode="All")
  $aqs  = Get-BtAqsFilter -Mode $Mode
  $coll = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
  $items = foreach ($di in $coll) {
    [pscustomobject]@{ Name=$di.Name; Id=$di.Id; IsPaired=(try {[bool]$di.Pairing.IsPaired} catch {$null}); Address=$null; IsConnected=$null; LeConnectable=$null }
  }
  $items | Sort-Object Name
}

# -------------------- Pair / Connect / PnP --------------------
function Convert-BtAddrToUlong { param([Parameter(Mandatory)][string]$Address) $hex=$Address -replace "[:\-]",""; if ($hex.Length -ne 12) { throw "Address must be AA:BB:CC:DD:EE:FF" }; [uint64]::Parse($hex,[System.Globalization.NumberStyles]::HexNumber) }
function Pair-BtDevice {
  param([Parameter(Mandatory)][string]$DeviceIdOrAddress,[string]$Pin)
  if ($DeviceIdOrAddress -notlike "Bluetooth#*") { throw "Pass a DeviceInformation.Id (copy from Find-BtDevices or Listen-ForPairables)." }
  $di = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($DeviceIdOrAddress))
  if (-not $di) { throw "DeviceInformation not found for: $DeviceIdOrAddress" }
  try { if ($di.Pairing.IsPaired) { Write-Host "Already paired: $($di.Name)" -ForegroundColor Yellow; return } } catch { }
  $script:PairingPin = $Pin
  $custom = $di.Pairing.Custom
  $handler = Register-ObjectEvent -InputObject $custom -EventName PairingRequested -Action {
    $req = $EventArgs
    switch ($req.PairingKind) {
      "DisplayPin"      { Write-Host "========== PAIRING PIN ==========" -ForegroundColor Green; Write-Host "Type this PIN on the KEYBOARD, then press Enter: $($req.Pin)" -ForegroundColor Green; Write-Host "=================================" -ForegroundColor Green; $req.Accept() }
      "ConfirmPinMatch" { Write-Host "Confirm PIN: $($req.Pin)" -ForegroundColor Green; $req.Accept() }
      "ConfirmOnly"     { Write-Host "Confirming pairing request..." -ForegroundColor Yellow; $req.Accept() }
      "ProvidePin"      { $p = $script:PairingPin; if (-not $p) { $p = "0000" }; Write-Host "Providing PIN $p" -ForegroundColor Yellow; $req.Accept($p) }
      default           { $req.Accept() }
    }
  }
  $kindsType = [type]::GetType('Windows.Devices.Enumeration.DevicePairingKinds, Windows, ContentType=WindowsRuntime')
  $kinds = [enum]::Parse($kindsType,'ConfirmOnly') -bor [enum]::Parse($kindsType,'DisplayPin') -bor [enum]::Parse($kindsType,'ConfirmPinMatch') -bor [enum]::Parse($kindsType,'ProvidePin')
  $levelType = [type]::GetType('Windows.Devices.Enumeration.DevicePairingProtectionLevel, Windows, ContentType=WindowsRuntime')
  $Default   = [enum]::Parse($levelType,'Default')
  $None      = [enum]::Parse($levelType,'None')
  try {
    Write-Host "Pairing (custom, all kinds) with: $($di.Name)" -ForegroundColor Cyan
    $res = Await-WinRT ($custom.PairAsync($Default,$kinds))
    if ($res.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) { Write-Host "Paired: $($di.Name)" -ForegroundColor Green; return }
    Write-Warning ("Custom pairing failed: {0}" -f $res.Status)
    Write-Host "Retrying basic PairAsync (Protection=None)..." -ForegroundColor Yellow
    $res2 = Await-WinRT ($di.Pairing.PairAsync($None))
    if ($res2.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) { Write-Host "Paired (basic): $($di.Name)" -ForegroundColor Green; return }
    Write-Host "Retrying basic PairAsync (Protection=Default)..." -ForegroundColor Yellow
    $res3 = Await-WinRT ($di.Pairing.PairAsync($Default))
    if ($res3.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) { Write-Host "Paired (basic/default): $($di.Name)" -ForegroundColor Green; return }
    throw "Pair failed after retries. Results: Custom=$($res.Status), BasicNone=$($res2.Status), BasicDefault=$($res3.Status)"
  } finally {
    if ($handler) { Unregister-Event -SourceIdentifier $handler.Name | Out-Null }
    Remove-Variable -Name PairingPin -Scope Script -ErrorAction SilentlyContinue
  }
}
function Pair-BtByName {
  param([Parameter(Mandatory)][string]$NameMatch,[string]$Pin,[int]$Retries=3,[int]$BetweenSeconds=2)
  $rx = New-Object System.Text.RegularExpressions.Regex ([regex]::Escape($NameMatch)), 'IgnoreCase'
  for ($i=1; $i -le $Retries; $i++) {
    $candidates = Find-BtDevices -Mode All | Where-Object { $_.Name -and $rx.IsMatch($_.Name) -and (-not $_.IsPaired) }
    $c = $candidates | Select-Object -First 1
    if ($c) {
      Write-Host ("[{0}/{1}] Attempting to pair: {2}" -f $i,$Retries,$c.Name) -ForegroundColor Cyan
      try { Pair-BtDevice -DeviceIdOrAddress $c.Id -Pin $Pin; return } catch { Write-Warning ("[{0}/{1}] Pair attempt failed: {2}" -f $i,$Retries,$_.Exception.Message) }
    } else {
      Write-Host ("[{0}/{1}] No discoverable match for '{2}'. Re-scanning..." -f $i,$Retries,$NameMatch) -ForegroundColor DarkGray
    }
    Start-Sleep -Seconds $BetweenSeconds
  }
  throw "No success pairing a device matching '$NameMatch' after $Retries tries."
}
function Connect-BleDevice { param([Parameter(Mandatory)][string]$Address) $addrU=Convert-BtAddrToUlong -Address $Address; $ble=Await-WinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromBluetoothAddressAsync($addrU)); if (-not $ble){throw "BLE device not found/visible: $Address"}; $svc=Await-WinRT ($ble.GetGattServicesAsync()); Write-Host ("Connected to {0} (Services={1})" -f $ble.Name,$svc.Services.Count) -ForegroundColor Green; $ble }

function Get-PairedDevices {
  if (-not $script:HasPnpDevice) { Write-Warning "PnpDevice module not available. Showing WinRT discoverable devices instead."; return (Find-BtDevices -Mode All | Select-Object @{n='Status';e={'(unknown)'}}, @{n='FriendlyName';e={$_.Name}}, @{n='InstanceId';e={$_.Id}}) }
  Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName } | Sort-Object FriendlyName | Select-Object Status, FriendlyName, InstanceId
}
function Disable-Enable-Device { param([Parameter(Mandatory)][string]$InstanceId) if (-not $script:HasPnpDevice){Write-Warning "PnpDevice module not available; cannot toggle '$InstanceId'.";return}; Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; Start-Sleep 2; Enable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; Write-Host "Toggled device: $InstanceId" -ForegroundColor Yellow }
function Remove-BtDevice {
  param([Parameter(Mandatory)][string]$Match)
  try {
    $cand = Find-BtDevices -Mode All | Where-Object { $_.Id -eq $Match -or ($_.Name -and $_.Name -like "*$Match*") } | Select-Object -First 1
    if ($cand) {
      $di = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($cand.Id))
      if ($di -and $di.Pairing -and $di.Pairing.IsPaired) {
        Write-Host "Unpairing (WinRT): $($di.Name)" -ForegroundColor Yellow
        $un = Await-WinRT ($di.Pairing.UnpairAsync())
        if ($un.Status -eq [Windows.Devices.Enumeration.DeviceUnpairingResultStatus]::Unpaired) { Write-Host "Unpaired." -ForegroundColor Green; return }
        else { Write-Warning "WinRT unpair result: $($un.Status) — will try device removal." }
      }
    }
  } catch { Write-Warning "WinRT unpair attempt failed: $($_.Exception.Message)" }
  $hasRemoveCmd = $false
  if ($script:HasPnpDevice) { $hasRemoveCmd = [bool](Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue) } else { try { Import-Module PnpDevice -ErrorAction Stop; $script:HasPnpDevice=$true; $hasRemoveCmd=[bool](Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue) } catch { $hasRemoveCmd=$false } }
  if ($hasRemoveCmd) {
    $dev = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -eq $Match -or ($_.FriendlyName -and $_.FriendlyName -like "*$Match*") } | Select-Object -First 1
    if ($dev) { Write-Host "Removing (PnP): $($dev.FriendlyName) [$($dev.InstanceId)]" -ForegroundColor Yellow; Remove-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false; Write-Host "Removed." -ForegroundColor Green; return }
  }
  Write-Warning "PnpDevice module/cmdlet not available or device not resolved. Falling back to 'pnputil /remove-device'."
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName="pnputil.exe"; $psi.Arguments="/remove-device `"$Match`""; $psi.UseShellExecute=$true; $psi.Verb="runas"
  $p=[System.Diagnostics.Process]::Start($psi); $p.WaitForExit()
  if ($p.ExitCode -eq 0) { Write-Host "Removed via pnputil." -ForegroundColor Green } else { throw "pnputil failed with exit code $($p.ExitCode)." }
}
function Toggle-BtRadio { param([string]$Vid='VID_0BDA') if (-not $script:HasPnpDevice){Write-Warning "PnpDevice module not available; cannot toggle radios.";return}; $d=Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match $Vid } | Select-Object -First 1; if (-not $d){Write-Error "BT radio with $Vid not found.";return}; Write-Host "Toggling: $($d.FriendlyName) [$($d.InstanceId)]"; Disable-Enable-Device -InstanceId $d.InstanceId }

# -------------------- Listeners --------------------
function Listen-ForKeyboard {
  param(
    [string]$NameMatch = 'Keyboard K380',
    [ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',
    [int]$TimeoutMinutes = 10,
    [string]$Pin
  )

  $aqs   = Get-BtAqsFilter -Mode $Mode
  $regex = New-Object System.Text.RegularExpressions.Regex ([regex]::Escape($NameMatch)), 'IgnoreCase'
  $seen  = New-Object 'System.Collections.Generic.HashSet[string]'
  $stopAt = (Get-Date).AddMinutes($TimeoutMinutes)

  # --- Inline BLE sniffer wired-in (visibility while pairing) ---
  $snifferWatcher = $null
  $snifferSrcId   = 'ListenKF_Adv'
  try {
    $snifferWatcher = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()
    $scanModeType = [type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode, Windows, ContentType=WindowsRuntime')
    if ($scanModeType) {
      $Active = [enum]::Parse($scanModeType,'Active')
      try { $snifferWatcher.ScanningMode = $Active } catch { }
    }
    function script:__FmtUuidsKF([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisement]$adv) {
      try { $uuids=@(); foreach ($u in $adv.ServiceUuids) { $uuids += $u.ToString() }; if ($uuids.Count -gt 0) { return ($uuids -join ',') } } catch { } return $null
    }
    $script:ListenKF_Regex = $regex

    Register-ObjectEvent -InputObject $snifferWatcher -EventName Received -SourceIdentifier $snifferSrcId -Action {
      try {
        $args = $EventArgs
        $mac  = ('{0:X12}' -f $args.BluetoothAddress) -replace '(.{2})(?=.)','$1:'
        $name = $args.Advertisement.LocalName
        if ($name -and $name.Length -gt 0) {
          if ($script:ListenKF_Regex -and (-not $script:ListenKF_Regex.IsMatch($name))) { return }
          $svc  = script:__FmtUuidsKF($args.Advertisement)
          $safeSvc = if ([string]::IsNullOrWhiteSpace($svc)) { '' } else { $svc }
          Write-Host ("ADV   MAC={0,-17} RSSI={1,4}dBm  Name={2}  Services=[{3}]"
            -f $mac, $args.RawSignalStrengthInDBm, $name, $safeSvc) -ForegroundColor Gray
        }
      } catch { }
    } | Out-Null

    $snifferWatcher.Start()
  } catch {
    Write-Warning "Inline BLE sniffer unavailable: $($_.Exception.Message)"
  }
  # -------------------------------------------------------------

  Write-Host "Listening (polling) for '$NameMatch' keyboard… Mode=$Mode, Timeout=$TimeoutMinutes min" -ForegroundColor White
  Write-Host "Put the keyboard in pairing mode now." -ForegroundColor White

  while ((Get-Date) -lt $stopAt) {
    try {
      $coll = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
      foreach ($di in $coll) {
        $name = $di.Name
        if (-not $name) { continue }
        if (-not $regex.IsMatch($name)) { continue }
        $isPaired = $false; try { $isPaired = [bool]$di.Pairing.IsPaired } catch { $isPaired = $false }
        if (-not $isPaired -and -not $seen.Contains($di.Id)) {
          [void]$seen.Add($di.Id)
          Write-Host "Detected candidate: $name — attempting to pair..." -ForegroundColor Cyan
          try { Pair-BtDevice -DeviceIdOrAddress $di.Id -Pin $Pin }
          catch { Write-Warning ("Pair attempt failed for '{0}': {1}" -f $name, $_.Exception.Message) }
        }
      }
    } catch { Write-Warning ("Scan error: {0}" -f $_.Exception.Message) }
    Start-Sleep -Seconds 1
  }

  Write-Host "Listener finished." -ForegroundColor Yellow

  # Stop & clean sniffer
  try {
    if ($snifferWatcher -and $snifferWatcher.Status -ne ([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcherStatus]::Stopped)) {
      $snifferWatcher.Stop()
    }
  } catch { }
  Unregister-Event -SourceIdentifier $snifferSrcId -ErrorAction SilentlyContinue | Out-Null
  Remove-Item function:\__FmtUuidsKF -ErrorAction SilentlyContinue
  Remove-Variable -Name ListenKF_Regex -Scope Script -ErrorAction SilentlyContinue
}

function Listen-ForPairables {
  param([ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',[int]$TimeoutMinutes = 10)
  $aqs = Get-BtAqsFilter -Mode $Mode
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  Write-Host "Listening (polling) for ANY pairable Bluetooth device… Mode=$Mode, Timeout=$TimeoutMinutes min" -ForegroundColor White
  $stopAt = (Get-Date).AddMinutes($TimeoutMinutes)
  while ((Get-Date) -lt $stopAt) {
    try {
      $coll = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
      foreach ($di in $coll) {
        if (-not $di) { continue }
        $canPair = $false; $isPaired = $false
        try { $canPair = [bool]$di.Pairing.CanPair } catch { }
        try { $isPaired = [bool]$di.Pairing.IsPaired } catch { }
        if ($canPair -and -not $isPaired -and -not $seen.Contains($di.Id)) {
          [void]$seen.Add($di.Id)
          $mac = $null; try { $mac = Get-BtMacFromDeviceId -DeviceId $di.Id } catch { }; if (-not $mac) { $mac = '(unknown)' }
          Write-Host ("PAIRABLE: {0}  MAC={1}`n         Id={2}" -f $di.Name, $mac, $di.Id) -ForegroundColor Cyan
        }
      }
    } catch { Write-Warning ("Scan error: {0}" -f $_.Exception.Message) }
    Start-Sleep -Seconds 1
  }
  Write-Host "Listener finished." -ForegroundColor Yellow
}

# -------------------- Prefer BT 5.3 dongle (optional) --------------------
try {
  $adapters = Get-BtAdapters
  if ($adapters) {
    $primary = $adapters | Select-Object -First 1
    if ($primary.State -ne [Windows.Devices.Radios.RadioState]::On) { [void](Await-WinRT ($primary._raw.SetStateAsync([Windows.Devices.Radios.RadioState]::On))) }
    foreach ($r in ($adapters | Select-Object -Skip 1)) {
      if ($r.State -eq [Windows.Devices.Radios.RadioState]::On) {
        Write-Host "Turning OFF secondary adapter: $($r.Name)" -ForegroundColor DarkGray
        [void](Await-WinRT ($r._raw.SetStateAsync([Windows.Devices.Radios.RadioState]::Off)))
      }
    }
  }
} catch { Write-Warning "Adapter preference skipped: $($_.Exception.Message)" }

# -------------------- Ready hints --------------------
Write-Host "`nReady. Common commands:" -ForegroundColor Cyan
@"
Get-BtAdapterInfo
Force-BtDefaultAdapter -PreferNameOrId '5.3'

# Live BLE advertisements (prove the radio hears air)
Start-BleSniffer -Seconds 20               # or: -NameLike 'Logi'

# Snapshot scan (BLE + Classic)
Find-BtDevices -Mode All | ft

# Pair by DeviceInformation Id
Pair-BtDevice -DeviceIdOrAddress 'Bluetooth#Bluetooth....'
Pair-BtDevice -DeviceIdOrAddress 'Bluetooth#Bluetooth....' -Pin '0000'

# Pair discoverable by name (retries)
Pair-BtByName -NameMatch 'Keyboard K380' -Retries 8 -BetweenSeconds 1 -Pin '777036'

# List paired devices (PnP or discoverable fallback)
Get-PairedDevices

# Toggle radio (Realtek VID example)
Toggle-BtRadio

# Remove (WinRT → PnP → pnputil)
Remove-BtDevice -Match 'Logitech'

# Keyboard listener with live ads + pairing
Listen-ForKeyboard -NameMatch 'Keyboard K380' -Mode All -TimeoutMinutes 3
"@ | Write-Output
