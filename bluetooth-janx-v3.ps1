#Requires -Version 5.1
<#  bluetooth-janx-all-v4.ps1  (Windows PowerShell 5.1 x64)
    - WinRT bootstrap (forces PS 5.1 x64 & loads Windows.winmd if needed)
    - Manual WinRT await (no .AsTask extension calls)
    - Snapshot scan (BLE/Classic)
    - Pair by DeviceInformation.Id (prints PIN if needed)
    - BLE connect (open GATT)
    - List paired, remove (unpair), toggle device
    - Prefer BT 5.3 dongle by name match
    - Listen-ForKeyboard: auto-pairs a matching keyboard (e.g., Logitech)
    - Listen-ForPairables: prints Name + MAC for ANY device in pairing mode
#>

param(
  [string]$PreferredAdapterMatch = "5.3",       # prefer dongle whose *name* contains this
  [ValidateSet("BLE","Classic","All")]
  [string]$ScanMode = "All"
)

# -------------------- WinRT bootstrap --------------------
function Ensure-WinRT {
  # Require Windows PowerShell 5.1 (Desktop) and 64-bit process
  if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5) {
    $ps51 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path $ps51)) { throw "This script requires Windows PowerShell 5.1 (64-bit)." }
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    Start-Process $ps51 -ArgumentList ($args -join ' ') -Verb RunAs
    exit
  }
  if (-not [Environment]::Is64BitProcess) {
    $ps51x64 = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    Start-Process $ps51x64 -ArgumentList ($args -join ' ') -Verb RunAs
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
  if ($op -and $op.PSObject -and ($op.PSObject.Methods.Name -contains 'Start')) {
    try { $op.Start() } catch { }
  }
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
  param([ValidateSet("On","Off")]$State,[Parameter(Mandatory)]$Radio)
  if ($State -eq "On") { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::On))) }
  else { [void](Await-WinRT ($Radio.SetStateAsync([Windows.Devices.Radios.RadioState]::Off))) }
}

# -------------------- Scanning (snapshot, 1-arg overload) --------------------
function Find-BtDevices {
  param([ValidateSet("BLE","Classic","All")]$Mode="All",[int]$Seconds=8)
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

function Pair-BtDevice {
  param([Parameter(Mandatory)][string]$DeviceIdOrAddress,[string]$Pin)

  # Compatibility: require DeviceInformation.Id
  if ($DeviceIdOrAddress -notlike "Bluetooth#*") {
    throw "Pass a DeviceInformation Id (copy from Find-BtDevices or Listen-ForPairables). MAC pairing is disabled in this compatibility build."
  }

  $di = Await-WinRT ([Windows.Devices.Enumeration.DeviceInformation]::CreateFromIdAsync($DeviceIdOrAddress))
  if (-not $di) { throw "DeviceInformation not found for: $DeviceIdOrAddress" }
  if ($di.Pairing.IsPaired) { Write-Host "Already paired: $($di.Name)" -ForegroundColor Yellow; return }

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
      "ConfirmOnly"     { $req.Accept() }
      "ProvidePin"      {
        $p = $script:PairingPin; if (-not $p) { $p = "0000" }
        Write-Host "Providing PIN $p" -ForegroundColor Yellow
        $req.Accept($p)
      }
      default           { $req.Accept() }
    }
  }

  try {
    Write-Host "Pairing with: $($di.Name)" -ForegroundColor Cyan
    $res = Await-WinRT ($custom.PairAsync([Windows.Devices.Enumeration.DevicePairingProtectionLevel]::Default))
    if ($res.Status -ne [Windows.Devices.Enumeration.DevicePairingResultStatus]::Paired) { throw "Pair failed: $($res.Status)" }
    Write-Host "Paired: $($di.Name)" -ForegroundColor Green
  } finally {
    if ($handler) { Unregister-Event -SourceIdentifier $handler.Name | Out-Null }
    Remove-Variable -Name PairingPin -Scope Script -ErrorAction SilentlyContinue
  }
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

  # Try WinRT unpair first (no PnP required)
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
          Write-Warning "WinRT unpair result: $($un.Status) — will try PnP (if available)."
        }
      }
    }
  } catch {
    Write-Warning "WinRT unpair attempt failed: $($_.Exception.Message)"
  }

  # Fallback to PnP removal
  if (-not $script:HasPnpDevice) {
    Write-Warning "PnpDevice module not available. Unable to remove '$Match' via PnP."
    return
  }

  $dev = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object {
    $_.InstanceId -eq $Match -or ($_.FriendlyName -and $_.FriendlyName -like "*$Match*")
  } | Select-Object -First 1

  if (-not $dev) { throw "No Bluetooth device matched '$Match'." }
  Write-Host "Removing (PnP): $($dev.FriendlyName) [$($dev.InstanceId)]" -ForegroundColor Yellow
  Remove-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
  Write-Host "Removed." -ForegroundColor Green
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
    [string]$NameMatch = 'Logitech',
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

# Force BLE connect (opens GATT) — requires MAC
Connect-BleDevice -Address 'AA:BB:CC:DD:EE:FF'

# List paired devices (PnP if available; otherwise discoverable list)
Get-PairedDevices

# Toggle a Realtek radio (by VID)
Toggle-BtRadio

# Remove (unpair) by name or InstanceId (WinRT unpair first; falls back to PnP if available)
Remove-BtDevice -Match 'Logitech Keyboard'

# Listen for a Logitech keyboard and auto-pair (10 min timeout)
Listen-ForKeyboard -NameMatch 'Logitech' -Mode All -TimeoutMinutes 10

# Listen for ANY device that is pairable and print MAC + Id
Listen-ForPairables -Mode All -TimeoutMinutes 5
"@ | Write-Output
