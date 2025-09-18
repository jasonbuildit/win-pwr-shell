#Requires -Version 5.1
<#  bluetooth-janx-all-v6.ps1  (Windows PowerShell 5.1 x64)
    - WinRT bootstrap (forces PS 5.1 x64 & loads Windows.winmd if needed)
    - Admin/self-elevate guard
    - Manual WinRT await (no .AsTask extension calls)
    - Snapshot scan (BLE/Classic)
    - Pair by DeviceInformation.Id (prints PIN if needed)  [hardened]
    - Pair-BtByName convenience with retries               [hardened]
    - BLE connect (open GATT)
    - List paired, remove (unpair), toggle device
    - Remove fallback: WinRT unpair → PnP → pnputil
    - Prefer BT 5.3 dongle by name match
    - Listen-ForKeyboard / Listen-ForPairables
#>

param(
  [string]$PreferredAdapterMatch = "5.3",       # prefer dongle whose *name* contains this
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
  # Require Windows PowerShell 5.1 (Desktop) and 64-bit process
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

  # Try to project WinRT Bluetooth types; if missing, load Windows.winmd
  $typeName = 'Windows.Devices.Enumeration.DeviceInformation, Windows, ContentType=WindowsRuntime'
  $t = [type]::GetType($typeName, $false)
  if (-not $t) {
    $winmd = Join-Path $env:WINDIR 'System32\WinMetadata\Windows.winmd'
    if (Test-Path $winmd) {
      try { Add-Type -Path $winmd -ErrorAction Stop } catch { }
      $t = [type]::GetType($typeName, $false)
    }
  }
  if (-not $t) {
    throw "WinRT Bluetooth APIs are unavailable in this session. Confirm PS 5.1 x64 and that C:\Windows\System32\WinMetadata\Windows.winmd exists."
  }
}
Ensure-WinRT

# -------------------- PnP module guard --------------------
function Ensure-PnpDeviceModule {
  try { Import-Module PnpDevice -ErrorAction Stop; $script:HasPnpDevice = $true }
  catch { $script:HasPnpDevice = $false }
}
Ensure-PnpDeviceModule

# -------------------- Manual WinRT await (no .AsTask) --------------------
function Await-WinRT {
  param([Parameter(Mandatory=$true)]$op)
  if ($op -and $op.PSObject -and ($op.PSObject.Methods.Name -contains 'Start')) { try { $op.Start() } catch { } }
  $AsyncStatusType = [type]::GetType('Windows.Foundation.AsyncStatus, Windows, ContentType=WindowsRuntime')
  if (-not $AsyncStatusType) { throw "WinRT AsyncStatus type not found. Use Windows PowerShell 5.1 on Windows." }
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

function Format-BtMac {
  param([Parameter(Mandatory)][UInt64]$Address)
  $hex = ('{0:X12}' -f $Address)
  $bytes = @(); for ($i=0; $i -lt 12; $i+=2) { $bytes += $hex.Substring($i,2) }
  return ($bytes -join ':')
}

function Get-BtMacFromDeviceId {
  param([Parameter(Mandatory)][string]$DeviceId)
  try {
    $ble = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromIdAsync($DeviceId))
    if ($ble -and $ble.BluetoothAddress) { return (Format-BtMac $ble.BluetoothAddress) }
  } catch { }
  try {
    $bd = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothDevice]::FromIdAsync($DeviceId))
    if ($bd -and $bd.BluetoothAddress) { return (Format-BtMac $bd.BluetoothAddress) }
  } catch { }
  return $null
}

# -------------------- Adapter diagnostics & live BLE sniffer --------------------
function Get-BtAdapterInfo {
  <#
    .SYNOPSIS
      Shows Bluetooth adapter/radio capabilities and state via WinRT.
    .NOTES
      Confirms whether LE/Classic are supported and whether the Radio is powered ON.
  #>
  try {
    $adapter = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothAdapter]::GetDefaultAsync())
    if (-not $adapter) { throw "BluetoothAdapter.GetDefaultAsync() returned null (no default adapter)" }

    $radio = $null
    try { $radio = Await-WinRT ($adapter.GetRadioAsync()) } catch { }

    $obj = [pscustomobject]@{
      BluetoothAddress                 = if ($adapter.BluetoothAddress) { ('{0:X12}' -f $adapter.BluetoothAddress) } else { $null }
      IsLowEnergySupported             = $adapter.IsLowEnergySupported
      IsClassicSupported               = $adapter.IsClassicSupported
      IsPeripheralRoleSupported        = $adapter.IsPeripheralRoleSupported
      IsCentralRoleSupported           = (try { $adapter.IsCentralRoleSupported } catch { $null })
      AreClassicSecureConnectionsSupported = (try { $adapter.AreClassicSecureConnectionsSupported } catch { $null })
      RadioName                        = (try { $radio.Name } catch { $null })
      RadioState                       = (try { $radio.State } catch { $null })
      RadioId                          = (try { $radio.DeviceId } catch { $null })
    }

    Write-Host "Adapter capabilities/state:" -ForegroundColor Cyan
    $obj | Format-List *
    return $obj
  } catch {
    Write-Error "Get-BtAdapterInfo failed: $($_.Exception.Message)"
  }
}

function Start-BleSniffer {
  param(
    [int]$Seconds = 15,
    [string]$NameLike,
    [int]$MaxRows = 200
  )

  if ($NameLike) {
    $script:BleSniff_NameRegex = New-Object System.Text.RegularExpressions.Regex ($NameLike), 'IgnoreCase'
  } else {
    $script:BleSniff_NameRegex = $null
  }
  $script:BleSniff_Count = 0

  $watcherType = [type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher, Windows, ContentType=WindowsRuntime')
  if (-not $watcherType) { throw "BLE Advertisement types unavailable (WinRT projection missing)." }

  $watcher = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher]::new()
  $scanModeType = [type]::GetType('Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode, Windows, ContentType=WindowsRuntime')
  if ($scanModeType) {
    $Active = [enum]::Parse($scanModeType,'Active')
    try { $watcher.ScanningMode = $Active } catch { }
  }

  function script:__FmtUuids([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisement]$adv) {
    try {
      $uuids = @()
      foreach ($u in $adv.ServiceUuids) { $uuids += $u.ToString() }
      if ($uuids.Count -gt 0) { return ($uuids -join ',') }
    } catch { }
    return $null
  }

  $received = Register-ObjectEvent -InputObject $watcher -EventName Received -Action {
    try {
      $args = $EventArgs
      $macU64 = $args.BluetoothAddress
      $mac = ('{0:X12}' -f $macU64) -replace '(.{2})(?=.)','$1:'
      $rssi = $args.RawSignalStrengthInDBm
      $name = $args.Advertisement.LocalName
      $svc  = script:__FmtUuids($args.Advertisement)

      if ($script:BleSniff_NameRegex -and (-not $script:BleSniff_NameRegex.IsMatch([string]$name))) { return }

      $script:BleSniff_Count++

      $safeName = if ([string]::IsNullOrWhiteSpace($name)) { '(none)' } else { $name }
      $safeSvc  = if ([string]::IsNullOrWhiteSpace($svc))  { '' } else { $svc }

      Write-Host ("ADV {0,4}  MAC={1,-17} RSSI={2,4}dBm  Name={3}  Services=[{4}]" `
        -f $script:BleSniff_Count, $mac, $rssi, $safeName, $safeSvc) -ForegroundColor Gray
    } catch {
      Write-Warning "Sniffer event error: $($_.Exception.Message)"
    }
  } -PassThru

  try {
    Write-Host ("Starting BLE sniffer... {0}" -f (if ($NameLike) { "filter NameLike='$NameLike'" } else { "no name filter" })) -ForegroundColor Cyan
    $watcher.Start()

    if ($Seconds -gt 0) {
      $deadline = (Get-Date).AddSeconds($Seconds)
      while ((Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
      $watcher.Stop()
    } else {
      Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
      while ($true) { Start-Sleep -Seconds 1 }
    }
  } finally {
    if ($watcher.Status -ne ([Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcherStatus]::Stopped)) {
      try { $watcher.Stop() } catch { }
    }
    if ($received) { Unregister-Event -SourceIdentifier $received.Name | Out-Null }
    Remove-Item -Path function:\__FmtUuids -ErrorAction SilentlyContinue
    Remove-Variable -Name BleSniff_NameRegex -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name BleSniff_Count -Scope Script -ErrorAction SilentlyContinue
  }
}



# -------------------- Adapters --------------------
function Get-BtAdapters {
  $radios = Await-WinRT ([Windows.Devices.Radios.Radio]::GetRadiosAsync())
  $bt = $radios | Where-Object { $_.Kind -eq [Windows.Devices.Radios.RadioKind]::Bluetooth }
  $items = foreach ($r in $bt) {
    [pscustomobject]@{
      Name  = $r.Name
      State = $r.State
      Id    = $r.DeviceId
      Score = if ($r.Name -match [regex]::Escape($PreferredAdapterMatch)) { 100 } else { 0 }
      _raw  = $r
    }
  }
  $items | Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Name';Descending=$false}
}

function Set-BtAdapterState {
  [CmdletBinding(DefaultParameterSetName='ByObject')]
  param(
    [Parameter(Mandatory, Position=0)]
    [ValidateSet("On","Off")]
    [string]$State,

    # Option A: pass the WinRT Radio object (_raw from Get-BtAdapters)
    [Parameter(ParameterSetName='ByObject', Mandatory=$false, Position=1)]
    $Radio,

    # Option B: pass a name fragment or exact DeviceId (we'll resolve it)
    [Parameter(ParameterSetName='ByName', Mandatory=$false, Position=1)]
    [string]$NameOrId
  )

  # Resolve string input to a Radio object if needed
  if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    $adapters = Get-BtAdapters
    if (-not $adapters) { throw "No Bluetooth radios detected." }

    if ($NameOrId -match '^(primary|first)$') { $Radio = ($adapters | Select-Object -First 1)._raw }
    elseif ($NameOrId -match '^(secondary|second)$') { $Radio = ($adapters | Select-Object -Skip 1 | Select-Object -First 1)._raw }
    else {
      $match = $adapters | Where-Object { $_.Id -eq $NameOrId -or ($_.Name -and $_.Name -like "*$NameOrId*") } | Select-Object -First 1
      if (-not $match) { throw "No adapter matched '$NameOrId'. Use Get-BtAdapters to see available names/ids." }
      $Radio = $match._raw
    }
  }

  if (-not $Radio) { throw "Provide -Radio (from Get-BtAdapters)._raw or use -NameOrId to resolve." }

  if ($State -eq "On")  { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::On))) }
  else                   { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::Off))) }
}

# -------------------- Scanning (snapshot, 1-arg overload) --------------------
function Find-BtDevices {
  param([ValidateSet("BLE","Classic","All")]$Mode="All")
  $aqs  = Get-BtAqsFilter -Mode $Mode
  $coll = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
  $items = foreach ($di in $coll) {
    [pscustomobject]@{
      Name          = $di.Name
      Id            = $di.Id
      IsPaired      = (try { [bool]$di.Pairing.IsPaired } catch { $null })
      Address       = $null
      IsConnected   = $null
      LeConnectable = $null
    }
  }
  $items | Sort-Object Name
}

# -------------------- Pair / Connect / PnP --------------------
function Convert-BtAddrToUlong {
  param([Parameter(Mandatory)][string]$Address) # "AA:BB:CC:DD:EE:FF"
  $hex = $Address -replace "[:\-]",""
  if ($hex.Length -ne 12) { throw "Address must be AA:BB:CC:DD:EE:FF" }
  [uint64]::Parse($hex,[System.Globalization.NumberStyles]::HexNumber)
}

# >>>>>>>>>> HARDENED PAIRING <<<<<<<<<<
function Pair-BtDevice {
  param(
    [Parameter(Mandatory)][string]$DeviceIdOrAddress,
    [string]$Pin
  )

  # This build requires a DeviceInformation.Id
  if ($DeviceIdOrAddress -notlike "Bluetooth#*") {
    throw "Pass a DeviceInformation.Id (copy from Find-BtDevices or Listen-ForPairables). MAC pairing is disabled in this compatibility build."
  }

  # Resolve a fresh DeviceInformation
  $di = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($DeviceIdOrAddress))
  if (-not $di) { throw "DeviceInformation not found for: $DeviceIdOrAddress" }

  # Already paired?
  try {
    if ($di.Pairing.IsPaired) {
      Write-Host "Already paired: $($di.Name)" -ForegroundColor Yellow
      return
    }
  } catch { }

  # Prepare event handler for PIN/confirm flows
  $script:PairingPin = $Pin  # avoid $using: in PS5.1 events
  $custom = $di.Pairing.Custom
  $handler = Register-ObjectEvent -InputObject $custom -EventName PairingRequested -Action {
    $req = $EventArgs
    switch ($req.PairingKind) {
      "DisplayPin" {
        Write-Host "========== PAIRING PIN ==========" -ForegroundColor Green
        Write-Host "Type this PIN on the KEYBOARD, then press Enter: $($req.Pin)" -ForegroundColor Green
        Write-Host "=================================" -ForegroundColor Green
        $req.Accept()
      }
      "ConfirmPinMatch" { Write-Host "Confirm PIN: $($req.Pin)" -ForegroundColor Green; $req.Accept() }
      "ConfirmOnly"     { Write-Host "Confirming pairing request..." -ForegroundColor Yellow; $req.Accept() }
      "ProvidePin"      {
        $p = $script:PairingPin; if (-not $p) { $p = "0000" }
        Write-Host "Providing PIN $p" -ForegroundColor Yellow
        $req.Accept($p)
      }
      default           { $req.Accept() }
    }
  }

  # Request all common pairing kinds to satisfy HID/Logitech flows
  $kindsType = [type]::GetType('Windows.Devices.Enumeration.DevicePairingKinds, Windows, ContentType=WindowsRuntime')
  $kinds = [enum]::Parse($kindsType,'ConfirmOnly') `
         -bor [enum]::Parse($kindsType,'DisplayPin') `
         -bor [enum]::Parse($kindsType,'ConfirmPinMatch') `
         -bor [enum]::Parse($kindsType,'ProvidePin')

  $levelType = [type]::GetType('Windows.Devices.Enumeration.DevicePairingProtectionLevel, Windows, ContentType=WindowsRuntime')
  $Default   = [enum]::Parse($levelType,'Default')
  $None      = [enum]::Parse($levelType,'None')

  try {
    Write-Host "Pairing (custom, all kinds) with: $($di.Name)" -ForegroundColor Cyan
    $res = Await-WinRT ($custom.PairAsync($Default, $kinds))
    if ($res.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) {
      Write-Host "Paired: $($di.Name)" -ForegroundColor Green
      return
    }

    Write-Warning ("Custom pairing failed: {0}" -f $res.Status)

    # Fallback 1: try basic PairAsync with relaxed protection
    Write-Host "Retrying basic PairAsync (Protection=None)..." -ForegroundColor Yellow
    $res2 = Await-WinRT ($di.Pairing.PairAsync($None))
    if ($res2.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) {
      Write-Host "Paired (basic): $($di.Name)" -ForegroundColor Green
      return
    }

    # Fallback 2: try basic PairAsync(Default)
    Write-Host "Retrying basic PairAsync (Protection=Default)..." -ForegroundColor Yellow
    $res3 = Await-WinRT ($di.Pairing.PairAsync($Default))
    if ($res3.Status -eq [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) {
      Write-Host "Paired (basic/default): $($di.Name)" -ForegroundColor Green
      return
    }

    throw "Pair failed after retries. Results: Custom=$($res.Status), BasicNone=$($res2.Status), BasicDefault=$($res3.Status)"
  }
  finally {
    if ($handler) { Unregister-Event -SourceIdentifier $handler.Name | Out-Null }
    Remove-Variable -Name PairingPin -Scope Script -ErrorAction SilentlyContinue
  }
}

function Pair-BtByName {
  param(
    [Parameter(Mandatory)][string]$NameMatch,
    [string]$Pin,
    [int]$Retries = 3,
    [int]$BetweenSeconds = 2
  )

  $rx = New-Object System.Text.RegularExpressions.Regex ([regex]::Escape($NameMatch)), 'IgnoreCase'

  for ($i=1; $i -le $Retries; $i++) {
    $candidates = Find-BtDevices -Mode All |
      Where-Object { $_.Name -and $rx.IsMatch($_.Name) -and (-not $_.IsPaired) }

    $c = $candidates | Select-Object -First 1
    if ($c) {
      Write-Host ("[{0}/{1}] Attempting to pair: {2}" -f $i,$Retries,$c.Name) -ForegroundColor Cyan
      try {
        Pair-BtDevice -DeviceIdOrAddress $c.Id -Pin $Pin
        return
      } catch {
        Write-Warning ("[{0}/{1}] Pair attempt failed: {2}" -f $i,$Retries,$_.Exception.Message)
      }
    } else {
      Write-Host ("[{0}/{1}] No discoverable match for '{2}'. Re-scanning..." -f $i,$Retries,$NameMatch) -ForegroundColor DarkGray
    }
    Start-Sleep -Seconds $BetweenSeconds
  }

  throw "No success pairing a device matching '$NameMatch' after $Retries tries."
}

function Connect-BleDevice {
  param([Parameter(Mandatory)][string]$Address)
  $addrU = Convert-BtAddrToUlong -Address $Address
  $ble   = Await-WinRT ([Windows.Devices.Bluetooth.BluetoothLEDevice]::FromBluetoothAddressAsync($addrU))
  if (-not $ble) { throw "BLE device not found/visible: $Address" }
  $svc   = Await-WinRT ($ble.GetGattServicesAsync())   # opening GATT usually forces LE link
  Write-Host ("Connected to {0} (Services={1})" -f $ble.Name,$svc.Services.Count) -ForegroundColor Green
  $ble
}

function Get-PairedDevices {
  if (-not $script:HasPnpDevice) {
    Write-Warning "PnpDevice module not available. Showing WinRT discoverable devices instead."
    return (Find-BtDevices -Mode All | Select-Object @{n='Status';e={'(unknown)'}}, @{n='FriendlyName';e={$_.Name}}, @{n='InstanceId';e={$_.Id}})
  }
  Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName } |
    Sort-Object FriendlyName |
    Select-Object Status, FriendlyName, InstanceId
}

function Disable-Enable-Device {
  param([Parameter(Mandatory)][string]$InstanceId)
  if (-not $script:HasPnpDevice) {
    Write-Warning "PnpDevice module not available; cannot toggle '$InstanceId'."
    return
  }
  Disable-PnpDevice -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep 2
  Enable-PnpDevice  -InstanceId $InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Toggled device: $InstanceId" -ForegroundColor Yellow
}

function Remove-BtDevice {
  param([Parameter(Mandatory)][string]$Match)

  # 1) WinRT unpair first
  try {
    $cand = Find-BtDevices -Mode All | Where-Object { $_.Id -eq $Match -or ($_.Name -and $_.Name -like "*$Match*") } | Select-Object -First 1
    if ($cand) {
      $di = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($cand.Id))
      if ($di -and $di.Pairing -and $di.Pairing.IsPaired) {
        Write-Host "Unpairing (WinRT): $($di.Name)" -ForegroundColor Yellow
        $un = Await-WinRT ($di.Pairing.UnpairAsync())
        if ($un.Status -eq [Windows.Devices.Enumeration.DeviceUnpairingResultStatus]::Unpaired) {
          Write-Host "Unpaired." -ForegroundColor Green
          return
        } else {
          Write-Warning "WinRT unpair result: $($un.Status) — will try device removal."
        }
      }
    }
  } catch {
    Write-Warning "WinRT unpair attempt failed: $($_.Exception.Message)"
  }

  # 2) PnP removal if module available
  $hasRemoveCmd = $false
  if ($script:HasPnpDevice) {
    $hasRemoveCmd = [bool](Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue)
  } else {
    try {
      Import-Module PnpDevice -ErrorAction Stop
      $script:HasPnpDevice = $true
      $hasRemoveCmd = [bool](Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue)
    } catch { $hasRemoveCmd = $false }
  }

  if ($hasRemoveCmd) {
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

  # 3) Fallback to pnputil
  Write-Warning "PnpDevice module/cmdlet not available or device not resolved. Falling back to 'pnputil /remove-device'."
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName   = "pnputil.exe"
  $psi.Arguments  = "/remove-device `"$Match`""
  $psi.UseShellExecute = $true
  $psi.Verb = "runas"
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  if ($p.ExitCode -eq 0) { Write-Host "Removed via pnputil." -ForegroundColor Green }
  else { throw "pnputil failed with exit code $($p.ExitCode)." }
}

function Toggle-BtRadio {
  param([string]$Vid = 'VID_0BDA') # Realtek
  if (-not $script:HasPnpDevice) { Write-Warning "PnpDevice module not available; cannot toggle radios."; return }
  $d = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
       Where-Object { $_.InstanceId -match $Vid } | Select-Object -First 1
  if (-not $d) { Write-Error "BT radio with $Vid not found."; return }
  Write-Host "Toggling: $($d.FriendlyName) [$($d.InstanceId)]"
  Disable-Enable-Device -InstanceId $d.InstanceId
}

# -------------------- Listeners --------------------
function Listen-ForKeyboard {
  param(
    [string]$NameMatch = 'Keyboard K380',
    [ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',
    [int]$TimeoutMinutes = 10,
    [string]$Pin  # optional fallback for ProvidePin
  )

  $aqs   = Get-BtAqsFilter -Mode $Mode
  $regex = New-Object System.Text.RegularExpressions.Regex ([regex]::Escape($NameMatch)), 'IgnoreCase'
  $seen  = New-Object 'System.Collections.Generic.HashSet[string]'

  Write-Host "Listening (polling) for '$NameMatch' keyboard… Mode=$Mode, Timeout=$TimeoutMinutes min" -ForegroundColor White
  Write-Host "Put the keyboard in pairing mode now." -ForegroundColor White
  $stopAt = (Get-Date).AddMinutes($TimeoutMinutes)

  while ((Get-Date) -lt $stopAt) {
    try {
      $coll = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($aqs))
      foreach ($di in $coll) {
        $name = $di.Name
        if (-not $name) { continue }
        if (-not $regex.IsMatch($name)) { continue }

        $isPaired = $false
        try { $isPaired = [bool]$di.Pairing.IsPaired } catch { $isPaired = $false }

        if (-not $isPaired -and -not $seen.Contains($di.Id)) {
          [void]$seen.Add($di.Id)
          Write-Host "Detected candidate: $name — attempting to pair..." -ForegroundColor Cyan
          try { Pair-BtDevice -DeviceIdOrAddress $di.Id -Pin $Pin }
          catch { Write-Warning ("Pair attempt failed for '{0}': {1}" -f $name, $_.Exception.Message) }
        }
      }
    } catch {
      Write-Warning ("Scan error: {0}" -f $_.Exception.Message)
    }
    Start-Sleep -Seconds 1
  }

  Write-Host "Listener finished." -ForegroundColor Yellow
}

function Listen-ForPairables {
  param(
    [ValidateSet('BLE','Classic','All')] [string]$Mode = 'All',
    [int]$TimeoutMinutes = 10
  )

  $aqs   = Get-BtAqsFilter -Mode $Mode
  $seen  = New-Object 'System.Collections.Generic.HashSet[string]'

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
          $mac = $null
          try { $mac = Get-BtMacFromDeviceId -DeviceId $di.Id } catch { }
          if (-not $mac) { $mac = '(unknown)' }

          Write-Host ("PAIRABLE: {0}  MAC={1}`n         Id={2}" -f $di.Name, $mac, $di.Id) -ForegroundColor Cyan
        }
      }
    } catch {
      Write-Warning ("Scan error: {0}" -f $_.Exception.Message)
    }
    Start-Sleep -Seconds 1
  }

  Write-Host "Listener finished." -ForegroundColor Yellow
}

# -------------------- Prefer BT 5.3 dongle (optional) --------------------
try {
  $adapters = Get-BtAdapters
  if ($adapters) {
    $primary = $adapters | Select-Object -First 1
    if ($primary.State -ne [Windows.Devices.Radios.RadioState]::On) {
      [void](Await-WinRT ($primary._raw.SetStateAsync([Windows.Devices.Radios.RadioState]::On)))
    }
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
# Snapshot scan (BLE + Classic)
Find-BtDevices -Mode All | ft

# Pair by DeviceInformation Id (copy Id from Find-BtDevices or Listen-ForPairables)
Pair-BtDevice -DeviceIdOrAddress 'Bluetooth#Bluetooth....'
Pair-BtDevice -DeviceIdOrAddress 'Bluetooth#Bluetooth....' -Pin '0000'   # legacy PIN flow

# Pair first discoverable match by name (e.g., 'Keyboard K380'), with retries
Pair-BtByName -NameMatch 'Keyboard K380' -Retries 5 -BetweenSeconds 2   # optional: -Pin '0000'

# Force BLE connect (opens GATT) — requires MAC
Connect-BleDevice -Address 'AA:BB:CC:DD:EE:FF'

# List paired devices (PnP if available; otherwise discoverable list)
Get-PairedDevices

# Toggle a Realtek radio (by VID)
Toggle-BtRadio

# Remove (unpair/remove) by name or InstanceId
# Order: WinRT Unpair → Remove-PnpDevice → pnputil /remove-device
Remove-BtDevice -Match 'USB\\VID_0BDA&PID_C829\\00E04C000001'

# Listen for a keyboard and auto-pair (10 min timeout)
Listen-ForKeyboard -NameMatch '' -Mode All -TimeoutMinutes 10

# Listen for ANY device that is pairable and print MAC + Id
Listen-ForPairables -Mode All -TimeoutMinutes 5
"@ | Write-Output
