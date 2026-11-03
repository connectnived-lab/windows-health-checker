<#
.SYNOPSIS
    Windows Health Checker - a read-only health report for Windows 10/11 PCs.

.DESCRIPTION
    Runs a set of read-only checks on the local computer (OS, uptime, CPU, memory,
    disks, Windows Update, antivirus, firewall, BitLocker, network, battery, failed
    logins and more). Each check returns PASS, WARN, FAIL or INFO with a short reason
    and a recommendation. Results are shown as a coloured console summary and saved
    as a self-contained HTML report with an overall score out of 100. A JSON export
    is available for ticketing or RMM tools.

    The script makes no changes to the computer. It does not need administrator
    rights; a few checks (failed logins, BitLocker via cmdlet) return more detail
    when run elevated and are marked INFO when they cannot be read.

    Works on Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER OutputPath
    Folder where the HTML/JSON reports are written. Defaults to the current user's
    Desktop (or the TEMP folder if the Desktop cannot be found).

.PARAMETER NoHtml
    Do not write the HTML report.

.PARAMETER Json
    Also write the results as a JSON file.

.PARAMETER Quiet
    Suppress all console output. Useful for scheduled tasks and RMM tools.
    The exit code still reports the result (see NOTES).

.PARAMETER SkipUpdateCheck
    Skip the online Windows Update search, which can take up to a minute.
    The date of the last installed update is still checked.

.PARAMETER OpenReport
    Open the HTML report in the default browser when finished.

.PARAMETER PassThru
    Write the report object to the pipeline.

.PARAMETER DemoData
    Build the report from built-in sample data instead of this computer.
    Used for screenshots, testing and trying the tool on non-Windows systems.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\WindowsHealthChecker.ps1

.EXAMPLE
    .\WindowsHealthChecker.ps1 -OutputPath C:\Temp\Reports -Json -OpenReport

.EXAMPLE
    .\WindowsHealthChecker.ps1 -Quiet -Json -NoHtml -OutputPath \\server\share\health

.NOTES
    Author : Nived NS
    License: MIT
    Exit codes: 0 = all checks passed, 1 = at least one WARN, 2 = at least one FAIL.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$NoHtml,
    [switch]$Json,
    [switch]$Quiet,
    [switch]$SkipUpdateCheck,
    [switch]$OpenReport,
    [switch]$PassThru,
    [switch]$DemoData
)

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Settings and thresholds. Adjust these to match your organisation's policy.
# ---------------------------------------------------------------------------
$Script:WhcVersion = '1.0.0'
$Script:WhcQuiet   = [bool]$Quiet

$Script:WhcThresholds = @{
    DiskWarnPercent         = 15     # free space below this % -> WARN
    DiskFailPercent         = 5      # free space below this % -> FAIL
    MemoryWarnPercent       = 80     # RAM in use at or above this % -> WARN
    MemoryFailPercent       = 90
    CpuWarnPercent          = 75     # average CPU load at or above this % -> WARN
    CpuFailPercent          = 90
    UptimeWarnDays          = 14     # days since last reboot
    UptimeFailDays          = 30
    SignatureWarnDays       = 3      # antivirus definitions age
    SignatureFailDays       = 7
    ScanWarnDays            = 14     # days since the last antivirus scan
    UpdateWarnDays          = 45     # days since the last installed update
    UpdateFailDays          = 60
    StartupWarnCount        = 15     # number of startup programs
    BatteryWarnPercent      = 80     # full charge capacity vs design capacity
    BatteryFailPercent      = 60
    FailedLoginWarnCount    = 5      # failed logons (event 4625) in 24 hours
    FailedLoginFailCount    = 20
    ProcessWarnPercentOfRam = 25     # single process using more than this % of RAM
    LatencyWarnMs           = 150
    UpdateSearchTimeoutSec  = 90
    # Windows 11 builds older than this are flagged as an older feature update.
    # 26100 = 24H2. Update this value as Microsoft's support lifecycle moves on.
    MinWindows11Build       = 26100
}

# Weight of each check in the overall score (PASS = full, WARN = half, FAIL = 0).
$Script:WhcWeights = @{
    OS = 8; Uptime = 4; PendingReboot = 4; Cpu = 4; Memory = 6
    DiskSystem = 7; DiskOther = 3; Updates = 14; Antivirus = 15; Firewall = 10
    BitLocker = 8; FailedLogins = 5; NetworkAdapters = 6; Internet = 6
    TopProcesses = 2; Startup = 3; Battery = 3
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Write-WhcHost {
    # Console output that respects -Quiet. Write-Host is used on purpose for colour.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param([string]$Text = '', [string]$Color = 'Gray', [switch]$NoNewline)
    if ($Script:WhcQuiet) { return }
    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
}

function Test-WhcIsWindows {
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Test-WhcIsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function New-WhcResult {
    # Every check returns objects of this shape. Builds an object only; changes nothing.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')] [string]$Status,
        [Parameter(Mandatory)] [string]$Detail,
        [string]$Recommendation = '',
        [double]$Weight = 0,
        $Data = $null
    )
    [pscustomobject][ordered]@{
        Id             = $Id
        Category       = $Category
        Name           = $Name
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
        Weight         = $Weight
        Data           = $Data
    }
}

function Get-WhcWorstStatus {
    # Returns the most severe status from a list (FAIL > WARN > PASS > INFO).
    param([string[]]$Status)
    if ($Status -contains 'FAIL') { return 'FAIL' }
    if ($Status -contains 'WARN') { return 'WARN' }
    if ($Status -contains 'PASS') { return 'PASS' }
    return 'INFO'
}

function Format-WhcByteSize {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N1} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Format-WhcAge {
    # "3 days", "5 hours", "12 minutes"
    param([double]$Days)
    if ($Days -ge 2) { return ('{0:N0} days' -f [math]::Floor($Days)) }
    if ($Days -ge 1) { return '1 day' }
    $hours = $Days * 24
    if ($hours -ge 1) { return ('{0:N0} hours' -f [math]::Floor($hours)) }
    return ('{0:N0} minutes' -f [math]::Floor($hours * 60))
}

function ConvertTo-WhcDateString {
    param($Date)
    if ($null -eq $Date) { return $null }
    return ([datetime]$Date).ToString('yyyy-MM-dd HH:mm')
}

# ===========================================================================
# DATA COLLECTION
# Each Get-Whc*Data function only reads from Windows and returns a plain
# object. The matching Test-Whc* function turns that object into results.
# Keeping the two apart lets the evaluation logic be tested with mock data.
# ===========================================================================

function Get-WhcSystemInfo {
    $os  = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs  = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = @(Get-CimInstance -ClassName Win32_Processor)[0]
    $serial = $null
    try { $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber } catch { $serial = $null }
    $domain = $cs.Domain
    if (-not $cs.PartOfDomain) { $domain = "$($cs.Workgroup) (workgroup)" }
    [pscustomobject][ordered]@{
        ComputerName      = $env:COMPUTERNAME
        UserName          = "$env:USERDOMAIN\$env:USERNAME"
        Manufacturer      = $cs.Manufacturer
        Model             = $cs.Model
        SerialNumber      = $serial
        OperatingSystem   = $os.Caption
        OsVersion         = $os.Version
        Processor         = ($cpu.Name -replace '\s+', ' ').Trim()
        TotalMemory       = Format-WhcByteSize ([double]$cs.TotalPhysicalMemory)
        Domain            = $domain
        RunAsAdmin        = Test-WhcIsAdmin
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-WhcOsData {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $displayVersion = $null
    $ubr = $null
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.PSObject.Properties['DisplayVersion']) { $displayVersion = $cv.DisplayVersion }
        elseif ($cv.PSObject.Properties['ReleaseId']) { $displayVersion = $cv.ReleaseId }
        if ($cv.PSObject.Properties['UBR']) { $ubr = $cv.UBR }
    } catch { Write-Verbose $_.Exception.Message }
    [pscustomobject]@{
        Caption        = $os.Caption
        Version        = $os.Version
        BuildNumber    = [int]$os.BuildNumber
        UBR            = $ubr
        DisplayVersion = $displayVersion
        Architecture   = $os.OSArchitecture
    }
}

function Get-WhcUptimeData {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{ LastBootUpTime = [datetime]$os.LastBootUpTime }
}

function Get-WhcPendingRebootData {
    # These registry keys are readable by standard users.
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $rename = $false
    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
        if ($sm.PSObject.Properties['PendingFileRenameOperations'] -and $sm.PendingFileRenameOperations) { $rename = $true }
    } catch { Write-Verbose $_.Exception.Message }
    [pscustomobject]@{ ComponentServicing = $cbs; WindowsUpdate = $wu; FileRename = $rename }
}

function Get-WhcCpuData {
    # LoadPercentage is a point-in-time value, so take three samples.
    $samples = @()
    for ($i = 0; $i -lt 3; $i++) {
        $load = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        if ($null -ne $load) { $samples += [double]$load }
        if ($i -lt 2) { Start-Sleep -Milliseconds 700 }
    }
    $cpu = @(Get-CimInstance -ClassName Win32_Processor)
    $avg = $null
    if ($samples.Count) { $avg = [math]::Round(($samples | Measure-Object -Average).Average, 0) }
    [pscustomobject]@{
        LoadPercent       = $avg
        Name              = ($cpu[0].Name -replace '\s+', ' ').Trim()
        Cores             = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
        LogicalProcessors = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    }
}

function Get-WhcMemoryData {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [pscustomobject]@{
        TotalKB = [double]$os.TotalVisibleMemorySize
        FreeKB  = [double]$os.FreePhysicalMemory
    }
}

function Get-WhcDiskData {
    # DriveType 3 = local fixed disk
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3'
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }
    foreach ($d in @($disks)) {
        [pscustomobject]@{
            Drive      = $d.DeviceID
            Label      = $d.VolumeName
            FileSystem = $d.FileSystem
            SizeBytes  = [double]$d.Size
            FreeBytes  = [double]$d.FreeSpace
            IsSystem   = ($d.DeviceID -eq $systemDrive)
        }
    }
}

function Get-WhcUpdateData {
    param([switch]$SkipSearch)

    # Last installed update, from the hotfix list (no admin needed).
    $lastInstalled = $null
    try {
        $dates = @()
        foreach ($hf in @(Get-HotFix -ErrorAction Stop)) {
            if ($hf.InstalledOn) {
                try { $dates += [datetime]$hf.InstalledOn } catch { Write-Verbose $_.Exception.Message }
            }
        }
        if ($dates.Count) { $lastInstalled = ($dates | Sort-Object -Descending)[0] }
    } catch { Write-Verbose $_.Exception.Message }

    $status = 'Skipped'
    $err = $null
    $pending = @()
    if (-not $SkipSearch) {
        # The Windows Update search can be slow, so it runs in a background job
        # with a timeout. Searching does not require administrator rights.
        $job = Start-Job -ScriptBlock {
            $session  = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $result   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
            foreach ($u in $result.Updates) {
                [pscustomobject]@{
                    Title    = $u.Title
                    Severity = $u.MsrcSeverity
                    KB       = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
                }
            }
        }
        $done = Wait-Job -Job $job -Timeout $Script:WhcThresholds.UpdateSearchTimeoutSec
        if ($done) {
            try {
                $pending = @(Receive-Job -Job $job -ErrorAction Stop | Select-Object Title, Severity, KB)
                $status = 'OK'
            } catch {
                $status = 'Failed'
                $err = $_.Exception.Message
            }
        } else {
            Stop-Job -Job $job
            $status = 'Timeout'
            $err = "Windows Update did not answer within $($Script:WhcThresholds.UpdateSearchTimeoutSec) seconds"
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        SearchStatus  = $status
        SearchError   = $err
        Pending       = $pending
        LastInstalled = $lastInstalled
    }
}

function ConvertFrom-WhcProductState {
    # productState is a bit field. As a 6-digit hex string: digits 3-4 are the
    # engine state (10/11 = on) and digits 5-6 the definitions state (00 = up to date).
    param([string]$Name, [int]$ProductState)
    $hex = '{0:x6}' -f $ProductState
    [pscustomobject]@{
        Name     = $Name
        Enabled  = ($hex.Substring(2, 2) -eq '10' -or $hex.Substring(2, 2) -eq '11')
        UpToDate = ($hex.Substring(4, 2) -eq '00')
    }
}

function Get-WhcAntivirusData {
    $defender = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        # Scan ages are reported as UInt32.MaxValue when a scan has never run.
        $quickAge = $null; if ($mp.QuickScanAge -lt 100000) { $quickAge = [double]$mp.QuickScanAge }
        $fullAge  = $null; if ($mp.FullScanAge -lt 100000)  { $fullAge  = [double]$mp.FullScanAge }
        $mode = $null
        if ($mp.PSObject.Properties['AMRunningMode']) { $mode = $mp.AMRunningMode }
        $defender = [pscustomobject]@{
            AntivirusEnabled          = [bool]$mp.AntivirusEnabled
            RealTimeProtectionEnabled = [bool]$mp.RealTimeProtectionEnabled
            SignatureAgeDays          = [double]$mp.AntivirusSignatureAge
            SignatureLastUpdated      = ConvertTo-WhcDateString $mp.AntivirusSignatureLastUpdated
            QuickScanAgeDays          = $quickAge
            FullScanAgeDays           = $fullAge
            LastQuickScan             = ConvertTo-WhcDateString $mp.QuickScanEndTime
            Mode                      = $mode
        }
    } catch { Write-Verbose $_.Exception.Message }

    # Security Center lists every registered antivirus, including third-party products.
    $products = @()
    try {
        foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)) {
            $products += ConvertFrom-WhcProductState -Name $p.displayName -ProductState ([int]$p.productState)
        }
    } catch { Write-Verbose $_.Exception.Message }

    [pscustomobject]@{ Defender = $defender; Products = $products }
}

function Get-WhcFirewallData {
    try {
        foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            [pscustomobject]@{ Name = [string]$p.Name; Enabled = ([string]$p.Enabled -eq 'True' -or [string]$p.Enabled -eq '1') }
        }
    } catch {
        # Fallback for systems without the NetSecurity module (English output only).
        $current = $null
        foreach ($line in @(netsh advfirewall show allprofiles state)) {
            if ($line -match '^(Domain|Private|Public) Profile') { $current = $Matches[1] }
            elseif ($current -and $line -match '^State\s+(\w+)') {
                [pscustomobject]@{ Name = $current; Enabled = ($Matches[1] -eq 'ON') }
                $current = $null
            }
        }
    }
}

function Get-WhcTopProcessData {
    $totalKB = [double](Get-CimInstance -ClassName Win32_OperatingSystem).TotalVisibleMemorySize
    $top = Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5
    $list = foreach ($p in $top) {
        $cpu = $null
        try { $cpu = [math]::Round($p.TotalProcessorTime.TotalSeconds, 0) } catch { Write-Verbose $_.Exception.Message }
        [pscustomobject]@{ Name = $p.ProcessName; Id = $p.Id; MemoryMB = [math]::Round($p.WorkingSet64 / 1MB, 0); CpuSeconds = $cpu }
    }
    [pscustomobject]@{ TotalMemoryMB = [math]::Round($totalKB / 1KB, 0); Processes = @($list) }
}

function Get-WhcStartupData {
    $items = @(Get-CimInstance -ClassName Win32_StartupCommand | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location }
    })
    [pscustomobject]@{ Count = $items.Count; Items = $items }
}

function Get-WhcBatteryData {
    $battery = @(Get-CimInstance -ClassName Win32_Battery)
    if ($battery.Count -eq 0) { return [pscustomobject]@{ Present = $false } }
    $design = $null; $full = $null
    try {
        $design = (@(Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryStaticData -ErrorAction Stop)[0]).DesignedCapacity
        $full   = (@(Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)[0]).FullChargedCapacity
    } catch { Write-Verbose $_.Exception.Message }
    [pscustomobject]@{
        Present            = $true
        ChargePercent      = $battery[0].EstimatedChargeRemaining
        DesignCapacity     = $design
        FullChargeCapacity = $full
    }
}

function Get-WhcNetworkAdapterData {
    $configs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE'
    foreach ($c in @($configs)) {
        [pscustomobject]@{
            Name    = $c.Description
            MAC     = $c.MACAddress
            DHCP    = [bool]$c.DHCPEnabled
            IPv4    = @($c.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
            Gateway = @($c.DefaultIPGateway | Where-Object { $_ })
            DNS     = @($c.DNSServerSearchOrder | Where-Object { $_ })
        }
    }
}

function Get-WhcInternetData {
    # .NET classes behave the same on PowerShell 5.1 and 7.
    $pings = foreach ($target in @('1.1.1.1', '8.8.8.8')) {
        $ok = $false; $ms = $null
        try {
            $reply = (New-Object System.Net.NetworkInformation.Ping).Send($target, 2000)
            if ($reply.Status -eq 'Success') { $ok = $true; $ms = [int]$reply.RoundtripTime }
        } catch { Write-Verbose $_.Exception.Message }
        [pscustomobject]@{ Target = $target; Success = $ok; LatencyMs = $ms }
    }
    $dnsOk = $false
    try { $dnsOk = @([System.Net.Dns]::GetHostAddresses('www.microsoft.com')).Count -gt 0 } catch { Write-Verbose $_.Exception.Message }
    # The same test page Windows uses to decide whether it has internet access.
    $httpOk = $false
    try {
        $req = [System.Net.WebRequest]::Create('http://www.msftconnecttest.com/connecttest.txt')
        $req.Timeout = 5000
        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $httpOk = ($reader.ReadToEnd() -match 'Microsoft Connect Test')
        $reader.Close(); $resp.Close()
    } catch { Write-Verbose $_.Exception.Message }
    [pscustomobject]@{ Pings = @($pings); DnsOk = $dnsOk; HttpOk = $httpOk }
}

function Get-WhcFailedLoginData {
    param([datetime]$Since = (Get-Date).AddHours(-24))
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $Since } -ErrorAction Stop)
    } catch {
        $msg = $_.Exception.Message
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $msg -match 'No events were found') {
            return [pscustomobject]@{ Status = 'OK'; Count = 0; TopAccounts = @() }
        }
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -match 'unauthorized|access is denied|privilege') {
            return [pscustomobject]@{ Status = 'AccessDenied'; Count = $null; TopAccounts = @() }
        }
        return [pscustomobject]@{ Status = 'Error'; Count = $null; TopAccounts = @(); Error = $msg }
    }
    # Property 5 of event 4625 is the target account name.
    $names = foreach ($ev in $events) {
        try { [string]$ev.Properties[5].Value } catch { 'unknown' }
    }
    $top = @($names | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 |
        ForEach-Object { [pscustomobject]@{ Account = $_.Name; Count = $_.Count } })
    [pscustomobject]@{ Status = 'OK'; Count = $events.Count; TopAccounts = $top }
}

function Get-WhcBitLockerData {
    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }
    $isLaptop = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0

    # Get-BitLockerVolume needs administrator rights.
    try {
        $v = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop
        $protection = [string]$v.ProtectionStatus
        $volume = [string]$v.VolumeStatus
        if ($volume -eq 'EncryptionInProgress') { $protection = 'Encrypting' }
        elseif ($volume -eq 'DecryptionInProgress') { $protection = 'Decrypting' }
        elseif ($protection -eq 'Off' -and $volume -eq 'FullyEncrypted') { $protection = 'Suspended' }
        return [pscustomobject]@{ Source = 'BitLocker cmdlet'; Drive = $systemDrive; Protection = $protection; IsLaptop = $isLaptop }
    } catch { Write-Verbose $_.Exception.Message }

    # Without admin rights, Explorer's shell property gives the protection state.
    # Values: 1 = On, 2 = Off, 3 = Encrypting, 4 = Decrypting, 5 = Suspended, 6 = On (locked)
    try {
        $shell = New-Object -ComObject Shell.Application
        $value = $shell.NameSpace($systemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $map = @{ 1 = 'On'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On' }
        $protection = 'Unknown'
        if ($null -ne $value -and $map.ContainsKey([int]$value)) { $protection = $map[[int]$value] }
        return [pscustomobject]@{ Source = 'Shell'; Drive = $systemDrive; Protection = $protection; IsLaptop = $isLaptop }
    } catch { Write-Verbose $_.Exception.Message }

    [pscustomobject]@{ Source = 'None'; Drive = $systemDrive; Protection = 'Unknown'; IsLaptop = $isLaptop }
}

# ===========================================================================
# EVALUATION
# Each Test-Whc* function takes the collected data and returns one or more
# results. These functions never touch the system, so they are unit-tested.
# ===========================================================================

function Test-WhcOperatingSystem {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $w = $Script:WhcWeights.OS
    $ver = $Data.Caption
    if ($Data.DisplayVersion) { $ver = "$ver $($Data.DisplayVersion)" }
    $build = "$($Data.BuildNumber)"
    if ($null -ne $Data.UBR) { $build = "$build.$($Data.UBR)" }
    $detail = "$ver (build $build)"

    if ($Data.Caption -match 'Windows 11') {
        if ($Data.BuildNumber -ge $t.MinWindows11Build) {
            return New-WhcResult -Id 'os' -Category 'System' -Name 'Operating system' -Status PASS -Detail $detail -Weight $w -Data $Data
        }
        return New-WhcResult -Id 'os' -Category 'System' -Name 'Operating system' -Status WARN -Detail "$detail - older Windows 11 feature update" `
            -Recommendation 'Install the latest Windows 11 feature update; older releases stop receiving security fixes.' -Weight $w -Data $Data
    }
    if ($Data.Caption -match 'Windows 10') {
        return New-WhcResult -Id 'os' -Category 'System' -Name 'Operating system' -Status WARN -Detail "$detail - Windows 10 support ended on 14 Oct 2025" `
            -Recommendation 'Upgrade to Windows 11, or confirm the PC is enrolled in Extended Security Updates (ESU).' -Weight $w -Data $Data
    }
    if ($Data.Caption -match 'Windows (7|8|Vista|XP)') {
        return New-WhcResult -Id 'os' -Category 'System' -Name 'Operating system' -Status FAIL -Detail "$detail - no longer supported" `
            -Recommendation 'Replace or upgrade this PC. It no longer receives security updates.' -Weight $w -Data $Data
    }
    New-WhcResult -Id 'os' -Category 'System' -Name 'Operating system' -Status INFO -Detail $detail -Data $Data
}

function Test-WhcUptime {
    param([Parameter(Mandatory)] $Data, [datetime]$Now = (Get-Date))
    $t = $Script:WhcThresholds
    $days = ($Now - [datetime]$Data.LastBootUpTime).TotalDays
    $detail = "Last reboot $(ConvertTo-WhcDateString $Data.LastBootUpTime) ($(Format-WhcAge $days) ago)"
    $status = 'PASS'; $rec = ''
    if ($days -gt $t.UptimeFailDays) { $status = 'FAIL'; $rec = 'Restart the PC. Long uptimes delay updates and can cause slowness.' }
    elseif ($days -gt $t.UptimeWarnDays) { $status = 'WARN'; $rec = 'Restart the PC to finish updates and clear memory.' }
    $info = [pscustomobject]@{ LastBootUpTime = ConvertTo-WhcDateString $Data.LastBootUpTime; UptimeDays = [math]::Round($days, 1) }
    New-WhcResult -Id 'uptime' -Category 'System' -Name 'Uptime / last reboot' -Status $status -Detail $detail -Recommendation $rec -Weight $Script:WhcWeights.Uptime -Data $info
}

function Test-WhcPendingReboot {
    param([Parameter(Mandatory)] $Data)
    $w = $Script:WhcWeights.PendingReboot
    $reasons = @()
    if ($Data.ComponentServicing) { $reasons += 'component servicing' }
    if ($Data.WindowsUpdate)      { $reasons += 'Windows Update' }
    if ($Data.FileRename)         { $reasons += 'pending file operations' }
    if ($reasons.Count) {
        return New-WhcResult -Id 'pendingreboot' -Category 'System' -Name 'Pending reboot' -Status WARN -Detail ('Restart required by: ' + ($reasons -join ', ')) `
            -Recommendation 'Restart the PC to complete the pending changes.' -Weight $w -Data $Data
    }
    New-WhcResult -Id 'pendingreboot' -Category 'System' -Name 'Pending reboot' -Status PASS -Detail 'No restart pending' -Weight $w -Data $Data
}

function Test-WhcCpu {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    if ($null -eq $Data.LoadPercent) {
        return New-WhcResult -Id 'cpu' -Category 'Performance' -Name 'CPU usage' -Status INFO -Detail 'CPU load could not be read' -Data $Data
    }
    $load = [double]$Data.LoadPercent
    $detail = "$load% average load - $($Data.Name) ($($Data.Cores) cores / $($Data.LogicalProcessors) threads)"
    $status = 'PASS'; $rec = ''
    if ($load -ge $t.CpuFailPercent) { $status = 'FAIL'; $rec = 'Check Task Manager for the process using the CPU; end it or scan for malware.' }
    elseif ($load -ge $t.CpuWarnPercent) { $status = 'WARN'; $rec = 'CPU is busy. Check the top processes in Task Manager.' }
    New-WhcResult -Id 'cpu' -Category 'Performance' -Name 'CPU usage' -Status $status -Detail $detail -Recommendation $rec -Weight $Script:WhcWeights.Cpu -Data $Data
}

function Test-WhcMemory {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    if (-not $Data.TotalKB) {
        return New-WhcResult -Id 'memory' -Category 'Performance' -Name 'Memory usage' -Status INFO -Detail 'Memory size could not be read' -Data $Data
    }
    $usedKB = $Data.TotalKB - $Data.FreeKB
    $usedPct = [math]::Round(($usedKB / $Data.TotalKB) * 100, 0)
    $detail = "$usedPct% in use ($(Format-WhcByteSize ($usedKB * 1KB)) of $(Format-WhcByteSize ($Data.TotalKB * 1KB)))"
    $status = 'PASS'; $rec = ''
    if ($usedPct -ge $t.MemoryFailPercent) { $status = 'FAIL'; $rec = 'Close unused programs or browser tabs. If this is normal for the user, add more RAM.' }
    elseif ($usedPct -ge $t.MemoryWarnPercent) { $status = 'WARN'; $rec = 'Memory is running high. Review the top memory processes.' }
    $info = [pscustomobject]@{ UsedPercent = $usedPct; TotalKB = $Data.TotalKB; FreeKB = $Data.FreeKB }
    New-WhcResult -Id 'memory' -Category 'Performance' -Name 'Memory usage' -Status $status -Detail $detail -Recommendation $rec -Weight $Script:WhcWeights.Memory -Data $info
}

function Test-WhcDisk {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] $Data)
    $t = $Script:WhcThresholds
    $drives = @($Data)
    if ($drives.Count -eq 0) {
        return New-WhcResult -Id 'disk' -Category 'Storage' -Name 'Disk space' -Status INFO -Detail 'No fixed drives found'
    }
    foreach ($d in $drives) {
        $name = "Disk space $($d.Drive)"
        if ($d.Label) { $name = "$name ($($d.Label))" }
        $weight = $Script:WhcWeights.DiskOther
        if ($d.IsSystem) { $weight = $Script:WhcWeights.DiskSystem }
        if (-not $d.SizeBytes) {
            New-WhcResult -Id "disk-$($d.Drive)" -Category 'Storage' -Name $name -Status INFO -Detail 'Drive size could not be read' -Data $d
            continue
        }
        $freePct = [math]::Round(($d.FreeBytes / $d.SizeBytes) * 100, 1)
        $detail = "$freePct% free ($(Format-WhcByteSize $d.FreeBytes) of $(Format-WhcByteSize $d.SizeBytes))"
        $status = 'PASS'; $rec = ''
        if ($freePct -lt $t.DiskFailPercent) {
            $status = 'FAIL'; $rec = 'Drive is almost full. Run Disk Cleanup, empty the Recycle Bin and move large files.'
        } elseif ($freePct -lt $t.DiskWarnPercent) {
            $status = 'WARN'; $rec = "Free space is below $($t.DiskWarnPercent)%. Run Disk Cleanup or Storage Sense."
        }
        $info = [pscustomobject]@{ Drive = $d.Drive; Label = $d.Label; FileSystem = $d.FileSystem; SizeBytes = $d.SizeBytes; FreeBytes = $d.FreeBytes; FreePercent = $freePct; IsSystem = [bool]$d.IsSystem }
        New-WhcResult -Id "disk-$($d.Drive)" -Category 'Storage' -Name $name -Status $status -Detail $detail -Recommendation $rec -Weight $weight -Data $info
    }
}

function Test-WhcWindowsUpdate {
    param([Parameter(Mandatory)] $Data, [datetime]$Now = (Get-Date))
    $t = $Script:WhcThresholds
    $parts = @(); $statuses = @(); $rec = @()

    if ($Data.LastInstalled) {
        $age = ($Now - [datetime]$Data.LastInstalled).TotalDays
        $parts += "last update installed $(([datetime]$Data.LastInstalled).ToString('yyyy-MM-dd')) ($(Format-WhcAge $age) ago)"
        if ($age -gt $t.UpdateFailDays) { $statuses += 'FAIL'; $rec += 'No updates for over two months. Check that Windows Update is working.' }
        elseif ($age -gt $t.UpdateWarnDays) { $statuses += 'WARN'; $rec += 'Updates look overdue. Open Settings > Windows Update.' }
        else { $statuses += 'PASS' }
    }

    $pending = @($Data.Pending | Where-Object { $_ })
    if ($Data.SearchStatus -eq 'OK') {
        if ($pending.Count -gt 0) {
            $parts = @("$($pending.Count) update(s) waiting to install") + $parts
            $statuses += 'WARN'
            $rec = @('Install the pending updates from Settings > Windows Update, then restart.') + $rec
        } else {
            $parts = @('no updates waiting') + $parts
            $statuses += 'PASS'
        }
    } elseif ($Data.SearchStatus -eq 'Skipped') {
        $parts += 'online update search skipped'
    } else {
        $parts += "pending updates could not be checked ($($Data.SearchError))"
    }

    if ($statuses.Count -eq 0) {
        return New-WhcResult -Id 'updates' -Category 'Updates' -Name 'Windows Update' -Status INFO -Detail ('Update status unknown: ' + ($parts -join '; ')) -Data $Data
    }
    $detail = $parts -join '; '
    $detail = $detail.Substring(0, 1).ToUpper() + $detail.Substring(1)
    $info = [pscustomobject]@{ SearchStatus = $Data.SearchStatus; LastInstalled = ConvertTo-WhcDateString $Data.LastInstalled; Pending = $pending }
    New-WhcResult -Id 'updates' -Category 'Updates' -Name 'Windows Update' -Status (Get-WhcWorstStatus $statuses) -Detail $detail `
        -Recommendation (($rec | Select-Object -Unique) -join ' ') -Weight $Script:WhcWeights.Updates -Data $info
}

function Test-WhcAntivirus {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $w = $Script:WhcWeights.Antivirus
    $d = $Data.Defender
    $products = @($Data.Products | Where-Object { $_ })
    $others = @($products | Where-Object { $_.Name -and $_.Name -notmatch 'Windows Defender|Microsoft Defender' })

    if ($d -and $d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) {
        $statuses = @('PASS'); $rec = @()
        $parts = @('Microsoft Defender on, real-time protection on', "definitions $(Format-WhcAge $d.SignatureAgeDays) old")
        if ($d.SignatureAgeDays -gt $t.SignatureFailDays) { $statuses += 'FAIL'; $rec += 'Virus definitions are out of date. Run Windows Update or update Defender.' }
        elseif ($d.SignatureAgeDays -gt $t.SignatureWarnDays) { $statuses += 'WARN'; $rec += 'Update virus definitions (Windows Security > Virus & threat protection > Protection updates).' }

        $scanAges = @(@($d.QuickScanAgeDays, $d.FullScanAgeDays) | Where-Object { $null -ne $_ })
        if ($scanAges.Count) {
            $lastScan = ($scanAges | Measure-Object -Minimum).Minimum
            $parts += "last scan $(Format-WhcAge $lastScan) ago"
            if ($lastScan -gt $t.ScanWarnDays) { $statuses += 'WARN'; $rec += 'Run a quick scan from Windows Security.' }
        } else {
            $parts += 'no scan on record'
            $statuses += 'WARN'; $rec += 'Run a quick scan from Windows Security.'
        }
        return New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status (Get-WhcWorstStatus $statuses) -Detail ($parts -join ', ') -Recommendation ($rec -join ' ') -Weight $w -Data $Data
    }

    # Defender is off or in passive mode: accept an active third-party product.
    $active = @($others | Where-Object { $_.Enabled })
    if ($active.Count) {
        $p = $active[0]
        if ($p.UpToDate) {
            return New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status PASS -Detail "$($p.Name) is active and up to date" -Weight $w -Data $Data
        }
        return New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status WARN -Detail "$($p.Name) is active but its definitions are out of date" `
            -Recommendation "Update $($p.Name)." -Weight $w -Data $Data
    }
    if ($d -and $d.AntivirusEnabled -and -not $d.RealTimeProtectionEnabled) {
        return New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status FAIL -Detail 'Microsoft Defender real-time protection is OFF' `
            -Recommendation 'Turn on real-time protection in Windows Security > Virus & threat protection.' -Weight $w -Data $Data
    }
    if (-not $d -and $products.Count -eq 0) {
        return New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status INFO -Detail 'Antivirus status could not be read on this system' -Data $Data
    }
    New-WhcResult -Id 'antivirus' -Category 'Security' -Name 'Antivirus' -Status FAIL -Detail 'No active antivirus found' `
        -Recommendation 'Turn on Microsoft Defender or install the company-approved antivirus.' -Weight $w -Data $Data
}

function Test-WhcFirewall {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] $Data)
    $w = $Script:WhcWeights.Firewall
    $profiles = @($Data | Where-Object { $_ })
    if ($profiles.Count -eq 0) {
        return New-WhcResult -Id 'firewall' -Category 'Security' -Name 'Firewall' -Status INFO -Detail 'Firewall status could not be read'
    }
    $summary = ($profiles | ForEach-Object { if ($_.Enabled) { "$($_.Name): On" } else { "$($_.Name): OFF" } }) -join ', '
    $off = @($profiles | Where-Object { -not $_.Enabled })
    if ($off.Count) {
        return New-WhcResult -Id 'firewall' -Category 'Security' -Name 'Firewall' -Status FAIL -Detail $summary `
            -Recommendation ('Turn the firewall back on for the ' + (($off | ForEach-Object { $_.Name }) -join ', ') + ' profile (Windows Security > Firewall & network protection).') `
            -Weight $w -Data $profiles
    }
    New-WhcResult -Id 'firewall' -Category 'Security' -Name 'Firewall' -Status PASS -Detail $summary -Weight $w -Data $profiles
}

function Test-WhcBitLocker {
    param([Parameter(Mandatory)] $Data)
    $w = $Script:WhcWeights.BitLocker
    $n = 'BitLocker encryption'
    $drive = $Data.Drive
    switch ($Data.Protection) {
        'On' { return New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status PASS -Detail "$drive is encrypted and protected" -Weight $w -Data $Data }
        'Encrypting' { return New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status PASS -Detail "$drive encryption in progress" -Weight $w -Data $Data }
        'Suspended' {
            return New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status WARN -Detail "$drive is encrypted but protection is suspended" `
                -Recommendation 'Resume BitLocker protection (Control Panel > BitLocker Drive Encryption).' -Weight $w -Data $Data
        }
        { $_ -eq 'Off' -or $_ -eq 'Decrypting' } {
            if ($Data.IsLaptop) {
                return New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status FAIL -Detail "$drive is not encrypted (laptop)" `
                    -Recommendation 'Enable BitLocker or device encryption. A lost laptop without encryption exposes all its data.' -Weight $w -Data $Data
            }
            return New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status WARN -Detail "$drive is not encrypted" `
                -Recommendation 'Enable BitLocker if company policy requires disk encryption.' -Weight $w -Data $Data
        }
    }
    New-WhcResult -Id 'bitlocker' -Category 'Security' -Name $n -Status INFO -Detail 'BitLocker status not available (feature missing or needs administrator rights)' -Data $Data
}

function Test-WhcFailedLogin {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $n = 'Failed logins (24h)'
    if ($Data.Status -eq 'AccessDenied') {
        return New-WhcResult -Id 'failedlogins' -Category 'Security' -Name $n -Status INFO -Detail 'The Security log needs administrator rights. Run as administrator to include this check.' -Data $Data
    }
    if ($Data.Status -ne 'OK') {
        return New-WhcResult -Id 'failedlogins' -Category 'Security' -Name $n -Status INFO -Detail 'The Security log could not be read' -Data $Data
    }
    $count = [int]$Data.Count
    $detail = "$count failed login attempt(s) in the last 24 hours"
    $tops = @($Data.TopAccounts | Where-Object { $_ })
    if ($count -gt 0 -and $tops.Count) {
        $detail += ' (' + (($tops | ForEach-Object { "$($_.Account): $($_.Count)" }) -join ', ') + ')'
    }
    $status = 'PASS'; $rec = ''
    if ($count -ge $t.FailedLoginFailCount) { $status = 'FAIL'; $rec = 'Many failed logins can mean a password-guessing attack. Check the accounts listed and report to IT security.' }
    elseif ($count -ge $t.FailedLoginWarnCount) { $status = 'WARN'; $rec = 'Confirm with the user whether these were mistyped passwords.' }
    New-WhcResult -Id 'failedlogins' -Category 'Security' -Name $n -Status $status -Detail $detail -Recommendation $rec -Weight $Script:WhcWeights.FailedLogins -Data $Data
}

function Test-WhcNetworkAdapter {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] $Data)
    $w = $Script:WhcWeights.NetworkAdapters
    $n = 'Network adapters'
    $adapters = @($Data | Where-Object { $_ })
    if ($adapters.Count -eq 0) {
        return New-WhcResult -Id 'network' -Category 'Network' -Name $n -Status FAIL -Detail 'No connected network adapter with an IP address' `
            -Recommendation 'Check the cable or Wi-Fi connection and the adapter in Device Manager.' -Weight $w -Data @()
    }
    $summary = ($adapters | ForEach-Object { "$($_.Name): $(@($_.IPv4) -join ', ')" }) -join '; '
    $apipa = @($adapters | Where-Object { @($_.IPv4 | Where-Object { $_ -like '169.254.*' }).Count -gt 0 })
    $good  = @($adapters | Where-Object { @($_.IPv4 | Where-Object { $_ -and $_ -notlike '169.254.*' }).Count -gt 0 })
    $noDns = @($good | Where-Object { @($_.DNS | Where-Object { $_ }).Count -eq 0 })
    if ($good.Count -eq 0) {
        return New-WhcResult -Id 'network' -Category 'Network' -Name $n -Status FAIL -Detail "No valid IP address ($summary)" `
            -Recommendation 'The PC did not get an address from DHCP. Reconnect, run "ipconfig /renew" or check the switch port or router.' -Weight $w -Data $adapters
    }
    if ($apipa.Count -or $noDns.Count) {
        return New-WhcResult -Id 'network' -Category 'Network' -Name $n -Status WARN -Detail $summary `
            -Recommendation 'An adapter has a self-assigned (169.254.x.x) address or no DNS server. Check its connection.' -Weight $w -Data $adapters
    }
    New-WhcResult -Id 'network' -Category 'Network' -Name $n -Status PASS -Detail $summary -Weight $w -Data $adapters
}

function Test-WhcInternet {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $w = $Script:WhcWeights.Internet
    $n = 'Internet connectivity'
    $okPings = @($Data.Pings | Where-Object { $_ -and $_.Success })
    $latency = $null
    if ($okPings.Count) { $latency = ($okPings | Measure-Object -Property LatencyMs -Minimum).Minimum }
    $parts = @()
    if ($Data.HttpOk) { $parts += 'web test OK' } else { $parts += 'web test failed' }
    if ($Data.DnsOk)  { $parts += 'DNS OK' } else { $parts += 'DNS failed' }
    if ($null -ne $latency) { $parts += "ping $latency ms" } else { $parts += 'ping blocked or failed' }
    $detail = $parts -join ', '
    $detail = $detail.Substring(0, 1).ToUpper() + $detail.Substring(1)

    if ($Data.HttpOk -or ($Data.DnsOk -and $okPings.Count)) {
        if ($null -ne $latency -and $latency -gt $t.LatencyWarnMs) {
            return New-WhcResult -Id 'internet' -Category 'Network' -Name $n -Status WARN -Detail "$detail - high latency" `
                -Recommendation 'The connection is slow. Check the Wi-Fi signal or network load.' -Weight $w -Data $Data
        }
        return New-WhcResult -Id 'internet' -Category 'Network' -Name $n -Status PASS -Detail $detail -Weight $w -Data $Data
    }
    if ($Data.DnsOk -or $okPings.Count) {
        return New-WhcResult -Id 'internet' -Category 'Network' -Name $n -Status WARN -Detail $detail `
            -Recommendation 'Partial connectivity. A proxy or firewall may be blocking web access.' -Weight $w -Data $Data
    }
    New-WhcResult -Id 'internet' -Category 'Network' -Name $n -Status FAIL -Detail $detail `
        -Recommendation 'No internet access. Check the network connection, DNS settings and proxy.' -Weight $w -Data $Data
}

function Test-WhcTopProcess {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $n = 'Top memory processes'
    $procs = @($Data.Processes | Where-Object { $_ })
    if ($procs.Count -eq 0) {
        return New-WhcResult -Id 'topprocesses' -Category 'Performance' -Name $n -Status INFO -Detail 'Process list not available' -Data $Data
    }
    $detail = ($procs | ForEach-Object { '{0} ({1:N0} MB)' -f $_.Name, $_.MemoryMB }) -join ', '
    $limitMB = $Data.TotalMemoryMB * $t.ProcessWarnPercentOfRam / 100
    $heavy = @($procs | Where-Object { $Data.TotalMemoryMB -and $_.MemoryMB -gt $limitMB })
    if ($heavy.Count) {
        return New-WhcResult -Id 'topprocesses' -Category 'Performance' -Name $n -Status WARN -Detail $detail `
            -Recommendation "$($heavy[0].Name) is using more than $($t.ProcessWarnPercentOfRam)% of RAM. Restart it if the PC feels slow." -Weight $Script:WhcWeights.TopProcesses -Data $Data
    }
    New-WhcResult -Id 'topprocesses' -Category 'Performance' -Name $n -Status PASS -Detail $detail -Weight $Script:WhcWeights.TopProcesses -Data $Data
}

function Test-WhcStartup {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $count = [int]$Data.Count
    if ($count -gt $t.StartupWarnCount) {
        return New-WhcResult -Id 'startup' -Category 'Performance' -Name 'Startup programs' -Status WARN -Detail "$count programs start with Windows" `
            -Recommendation 'Disable programs the user does not need at startup (Task Manager > Startup apps).' -Weight $Script:WhcWeights.Startup -Data $Data
    }
    New-WhcResult -Id 'startup' -Category 'Performance' -Name 'Startup programs' -Status PASS -Detail "$count programs start with Windows" -Weight $Script:WhcWeights.Startup -Data $Data
}

function Test-WhcBattery {
    param([Parameter(Mandatory)] $Data)
    $t = $Script:WhcThresholds
    $n = 'Battery health'
    if (-not $Data.Present) {
        return New-WhcResult -Id 'battery' -Category 'Hardware' -Name $n -Status INFO -Detail 'No battery detected (desktop PC)' -Data $Data
    }
    $charge = ''
    if ($null -ne $Data.ChargePercent) { $charge = "charged $($Data.ChargePercent)%" }
    if (-not $Data.DesignCapacity -or -not $Data.FullChargeCapacity) {
        $text = 'Battery present'
        if ($charge) { $text = "$text, $charge" }
        return New-WhcResult -Id 'battery' -Category 'Hardware' -Name $n -Status INFO -Detail "$text; capacity data not available (try running as administrator)" -Data $Data
    }
    $health = [math]::Round(([double]$Data.FullChargeCapacity / [double]$Data.DesignCapacity) * 100, 0)
    if ($health -gt 100) { $health = 100 }
    $detail = '{0}% of design capacity ({1:N0} / {2:N0} mWh)' -f $health, $Data.FullChargeCapacity, $Data.DesignCapacity
    if ($charge) { $detail = "$detail, $charge" }
    $status = 'PASS'; $rec = ''
    if ($health -lt $t.BatteryFailPercent) { $status = 'FAIL'; $rec = 'The battery is worn out. Plan a replacement.' }
    elseif ($health -lt $t.BatteryWarnPercent) { $status = 'WARN'; $rec = 'The battery has lost noticeable capacity. Run "powercfg /batteryreport" for its full history.' }
    $info = [pscustomobject]@{ HealthPercent = $health; ChargePercent = $Data.ChargePercent; DesignCapacity = $Data.DesignCapacity; FullChargeCapacity = $Data.FullChargeCapacity }
    New-WhcResult -Id 'battery' -Category 'Hardware' -Name $n -Status $status -Detail $detail -Recommendation $rec -Weight $Script:WhcWeights.Battery -Data $info
}

# ===========================================================================
# ORCHESTRATION
# ===========================================================================

function Get-WhcCheckList {
    # Each entry: id, display name, collector (reads the system), evaluator (scores the data).
    @(
        @{ Id = 'os';            Category = 'System';      Name = 'Operating system';      Collect = { Get-WhcOsData };                Evaluate = { param($d) Test-WhcOperatingSystem -Data $d } }
        @{ Id = 'uptime';        Category = 'System';      Name = 'Uptime / last reboot';  Collect = { Get-WhcUptimeData };            Evaluate = { param($d) Test-WhcUptime -Data $d } }
        @{ Id = 'pendingreboot'; Category = 'System';      Name = 'Pending reboot';        Collect = { Get-WhcPendingRebootData };     Evaluate = { param($d) Test-WhcPendingReboot -Data $d } }
        @{ Id = 'cpu';           Category = 'Performance'; Name = 'CPU usage';             Collect = { Get-WhcCpuData };               Evaluate = { param($d) Test-WhcCpu -Data $d } }
        @{ Id = 'memory';        Category = 'Performance'; Name = 'Memory usage';          Collect = { Get-WhcMemoryData };            Evaluate = { param($d) Test-WhcMemory -Data $d } }
        @{ Id = 'topprocesses';  Category = 'Performance'; Name = 'Top memory processes';  Collect = { Get-WhcTopProcessData };        Evaluate = { param($d) Test-WhcTopProcess -Data $d } }
        @{ Id = 'startup';       Category = 'Performance'; Name = 'Startup programs';      Collect = { Get-WhcStartupData };           Evaluate = { param($d) Test-WhcStartup -Data $d } }
        @{ Id = 'disk';          Category = 'Storage';     Name = 'Disk space';            Collect = { @(Get-WhcDiskData) };           Evaluate = { param($d) Test-WhcDisk -Data $d } }
        @{ Id = 'updates';       Category = 'Updates';     Name = 'Windows Update';        Collect = { Get-WhcUpdateData -SkipSearch:$Script:WhcSkipUpdateSearch }; Evaluate = { param($d) Test-WhcWindowsUpdate -Data $d } }
        @{ Id = 'antivirus';     Category = 'Security';    Name = 'Antivirus';             Collect = { Get-WhcAntivirusData };         Evaluate = { param($d) Test-WhcAntivirus -Data $d } }
        @{ Id = 'firewall';      Category = 'Security';    Name = 'Firewall';              Collect = { @(Get-WhcFirewallData) };       Evaluate = { param($d) Test-WhcFirewall -Data $d } }
        @{ Id = 'bitlocker';     Category = 'Security';    Name = 'BitLocker encryption';  Collect = { Get-WhcBitLockerData };         Evaluate = { param($d) Test-WhcBitLocker -Data $d } }
        @{ Id = 'failedlogins';  Category = 'Security';    Name = 'Failed logins (24h)';   Collect = { Get-WhcFailedLoginData };       Evaluate = { param($d) Test-WhcFailedLogin -Data $d } }
        @{ Id = 'network';       Category = 'Network';     Name = 'Network adapters';      Collect = { @(Get-WhcNetworkAdapterData) }; Evaluate = { param($d) Test-WhcNetworkAdapter -Data $d } }
        @{ Id = 'internet';      Category = 'Network';     Name = 'Internet connectivity'; Collect = { Get-WhcInternetData };          Evaluate = { param($d) Test-WhcInternet -Data $d } }
        @{ Id = 'battery';       Category = 'Hardware';    Name = 'Battery health';        Collect = { Get-WhcBatteryData };           Evaluate = { param($d) Test-WhcBattery -Data $d } }
    )
}

function Invoke-WhcCheck {
    # Runs one check. Any error is caught and reported as an INFO result,
    # so a single broken check never stops the rest of the report.
    param([Parameter(Mandatory)] [hashtable]$Check, [hashtable]$DemoSource)
    try {
        if ($DemoSource) { $data = $DemoSource[$Check.Id] } else { $data = & $Check.Collect }
        if ($null -eq $data) { $data = @() }
        return @(& $Check.Evaluate $data)
    } catch {
        return @(New-WhcResult -Id $Check.Id -Category $Check.Category -Name $Check.Name -Status INFO `
            -Detail ('Check could not run: ' + $_.Exception.Message))
    }
}

function Get-WhcScore {
    # Weighted score: PASS = 100%, WARN = 50%, FAIL = 0% of the check's weight.
    # INFO results (not applicable or not readable) are left out of the score.
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results)
    $total = 0.0; $earned = 0.0
    foreach ($r in $Results) {
        if ($r.Status -eq 'INFO' -or $r.Weight -le 0) { continue }
        $total += $r.Weight
        if ($r.Status -eq 'PASS') { $earned += $r.Weight }
        elseif ($r.Status -eq 'WARN') { $earned += $r.Weight * 0.5 }
    }
    $score = 0
    if ($total -gt 0) { $score = [int][math]::Round(($earned / $total) * 100, 0) }
    $grade = 'At risk'
    if ($score -ge 90) { $grade = 'Healthy' } elseif ($score -ge 70) { $grade = 'Needs attention' }
    [pscustomobject][ordered]@{
        Score = $score
        Grade = $grade
        Pass  = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count
        Warn  = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
        Fail  = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
        Info  = @($Results | Where-Object { $_.Status -eq 'INFO' }).Count
    }
}

function Get-WhcDemoData {
    # Realistic sample data for an office laptop. Used by -DemoData and by the tests.
    param([datetime]$Now = (Get-Date))
    $system = [pscustomobject][ordered]@{
        ComputerName      = 'LT-SUPPORT-042'
        UserName          = 'CORP\demo.user'
        Manufacturer      = 'Dell Inc.'
        Model             = 'Latitude 5420'
        SerialNumber      = '7XK2Q93'
        OperatingSystem   = 'Microsoft Windows 11 Pro'
        OsVersion         = '10.0.26100'
        Processor         = '11th Gen Intel(R) Core(TM) i5-1145G7 @ 2.60GHz'
        TotalMemory       = '15.7 GB'
        Domain            = 'corp.example.local'
        RunAsAdmin        = $true
        PowerShellVersion = '5.1.26100.2161'
    }
    $data = @{
        os            = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; Version = '10.0.26100'; BuildNumber = 26100; UBR = 2314; DisplayVersion = '24H2'; Architecture = '64-bit' }
        uptime        = [pscustomobject]@{ LastBootUpTime = $Now.AddDays(-18).AddHours(-3) }
        pendingreboot = [pscustomobject]@{ ComponentServicing = $false; WindowsUpdate = $false; FileRename = $false }
        cpu           = [pscustomobject]@{ LoadPercent = 23; Name = $system.Processor; Cores = 4; LogicalProcessors = 8 }
        memory        = [pscustomobject]@{ TotalKB = 16461824; FreeKB = 2650000 }
        topprocesses  = [pscustomobject]@{ TotalMemoryMB = 16076; Processes = @(
                [pscustomobject]@{ Name = 'chrome';   Id = 11234; MemoryMB = 1874; CpuSeconds = 2210 }
                [pscustomobject]@{ Name = 'ms-teams'; Id = 9876;  MemoryMB = 1102; CpuSeconds = 1540 }
                [pscustomobject]@{ Name = 'OUTLOOK';  Id = 6120;  MemoryMB = 684;  CpuSeconds = 820 }
                [pscustomobject]@{ Name = 'MsMpEng';  Id = 4012;  MemoryMB = 391;  CpuSeconds = 615 }
                [pscustomobject]@{ Name = 'explorer'; Id = 5528;  MemoryMB = 236;  CpuSeconds = 190 }
            ) }
        startup       = [pscustomobject]@{ Count = 11; Items = @() }
        disk          = @(
            [pscustomobject]@{ Drive = 'C:'; Label = 'OS';   FileSystem = 'NTFS'; SizeBytes = 255369216000; FreeBytes = 104857600000; IsSystem = $true }
            [pscustomobject]@{ Drive = 'D:'; Label = 'Data'; FileSystem = 'NTFS'; SizeBytes = 499963170816; FreeBytes = 45097156608;  IsSystem = $false }
        )
        updates       = [pscustomobject]@{
            SearchStatus = 'OK'; SearchError = $null; LastInstalled = $Now.AddDays(-34)
            Pending = @(
                [pscustomobject]@{ Title = 'Cumulative Update for Windows 11 Version 24H2 for x64-based Systems'; Severity = 'Critical'; KB = 'KB5046617' }
                [pscustomobject]@{ Title = 'Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11'; Severity = 'Important'; KB = 'KB5045934' }
                [pscustomobject]@{ Title = 'Windows Malicious Software Removal Tool x64'; Severity = $null; KB = 'KB890830' }
            )
        }
        antivirus     = [pscustomobject]@{
            Defender = [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; SignatureAgeDays = 0.6; SignatureLastUpdated = $null; QuickScanAgeDays = 2; FullScanAgeDays = 26; LastQuickScan = $null; Mode = 'Normal' }
            Products = @([pscustomobject]@{ Name = 'Windows Defender'; Enabled = $true; UpToDate = $true })
        }
        firewall      = @(
            [pscustomobject]@{ Name = 'Domain';  Enabled = $true }
            [pscustomobject]@{ Name = 'Private'; Enabled = $true }
            [pscustomobject]@{ Name = 'Public';  Enabled = $false }
        )
        bitlocker     = [pscustomobject]@{ Source = 'BitLocker cmdlet'; Drive = 'C:'; Protection = 'On'; IsLaptop = $true }
        failedlogins  = [pscustomobject]@{ Status = 'OK'; Count = 2; TopAccounts = @([pscustomobject]@{ Account = 'demo.user'; Count = 2 }) }
        network       = @(
            [pscustomobject]@{ Name = 'Intel(R) Wi-Fi 6 AX201 160MHz'; MAC = '3C:9C:0F:4A:12:7B'; DHCP = $true; IPv4 = @('192.168.10.42'); Gateway = @('192.168.10.1'); DNS = @('192.168.10.5', '8.8.8.8') }
        )
        internet      = [pscustomobject]@{ Pings = @([pscustomobject]@{ Target = '1.1.1.1'; Success = $true; LatencyMs = 18 }, [pscustomobject]@{ Target = '8.8.8.8'; Success = $true; LatencyMs = 21 }); DnsOk = $true; HttpOk = $true }
        battery       = [pscustomobject]@{ Present = $true; ChargePercent = 86; DesignCapacity = 54000; FullChargeCapacity = 41200 }
    }
    [pscustomobject]@{ System = $system; Data = $data }
}

function Invoke-WindowsHealthCheck {
    # Runs every check and returns the full report object.
    param([switch]$SkipUpdateCheck, [switch]$DemoData)
    $started = Get-Date
    $Script:WhcSkipUpdateSearch = [bool]$SkipUpdateCheck
    $demoSource = $null
    if ($DemoData) {
        $demo = Get-WhcDemoData -Now $started
        $system = $demo.System
        $demoSource = $demo.Data
    } else {
        try { $system = Get-WhcSystemInfo } catch {
            $system = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; UserName = $env:USERNAME; OperatingSystem = 'Unknown' }
        }
    }

    $checks = @(Get-WhcCheckList)
    $results = @()
    $i = 0
    foreach ($check in $checks) {
        if (-not $Script:WhcQuiet) {
            Write-Progress -Activity 'Windows Health Checker' -Status $check.Name -PercentComplete ([int]($i / $checks.Count * 100))
        }
        $results += Invoke-WhcCheck -Check $check -DemoSource $demoSource
        $i++
    }
    if (-not $Script:WhcQuiet) { Write-Progress -Activity 'Windows Health Checker' -Completed }

    [pscustomobject][ordered]@{
        Tool        = 'Windows Health Checker'
        Version     = $Script:WhcVersion
        GeneratedAt = $started.ToString('yyyy-MM-dd HH:mm:ss')
        DurationSec = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
        DemoData    = [bool]$DemoData
        System      = $system
        Summary     = Get-WhcScore -Results $results
        Results     = $results
    }
}

# ===========================================================================
# OUTPUT: console, HTML, JSON
# ===========================================================================

function Write-WhcConsoleReport {
    param([Parameter(Mandatory)] $Report)
    if ($Script:WhcQuiet) { return }
    $colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }
    $line = '-' * 76
    Write-WhcHost ''
    Write-WhcHost "  WINDOWS HEALTH CHECKER v$($Report.Version)" 'White'
    Write-WhcHost ('  {0}  |  {1}  |  {2}' -f $Report.System.ComputerName, $Report.System.OperatingSystem, $Report.GeneratedAt) 'DarkGray'
    if ($Report.DemoData) { Write-WhcHost '  DEMO MODE - sample data, not this computer' 'Magenta' }
    Write-WhcHost "  $line" 'DarkGray'
    $category = ''
    foreach ($r in $Report.Results) {
        if ($r.Category -ne $category) {
            $category = $r.Category
            Write-WhcHost "  $($category.ToUpper())" 'White'
        }
        Write-WhcHost '   [' 'DarkGray' -NoNewline
        Write-WhcHost $r.Status $colors[$r.Status] -NoNewline
        Write-WhcHost '] ' 'DarkGray' -NoNewline
        Write-WhcHost ('{0,-24} ' -f $r.Name) 'Gray' -NoNewline
        Write-WhcHost $r.Detail 'DarkGray'
        if ($r.Recommendation -and ($r.Status -eq 'WARN' -or $r.Status -eq 'FAIL')) {
            Write-WhcHost ('          -> ' + $r.Recommendation) $colors[$r.Status]
        }
    }
    Write-WhcHost "  $line" 'DarkGray'
    $s = $Report.Summary
    $scoreColor = 'Red'
    if ($s.Score -ge 90) { $scoreColor = 'Green' } elseif ($s.Score -ge 70) { $scoreColor = 'Yellow' }
    Write-WhcHost '  HEALTH SCORE: ' 'White' -NoNewline
    Write-WhcHost ('{0}/100  ({1})' -f $s.Score, $s.Grade) $scoreColor
    Write-WhcHost ('  {0} passed, {1} warnings, {2} failed, {3} info' -f $s.Pass, $s.Warn, $s.Fail, $s.Info) 'Gray'
    Write-WhcHost ''
}

function ConvertTo-WhcHtmlText {
    param($Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-WhcHtmlStyle {
    @'
:root{--bg:#f4f6fa;--card:#fff;--text:#1b2433;--muted:#667085;--line:#e4e8ef;--soft:#f7f9fc;
--pass:#15803d;--pass-bg:#dcfce7;--warn:#b45309;--warn-bg:#fef3c7;--fail:#dc2626;--fail-bg:#fee2e2;--info:#0369a1;--info-bg:#e0f2fe;--track:#e8ecf2}
[data-theme=dark]{--bg:#0d131e;--card:#151d2b;--text:#e6eaf2;--muted:#93a0b7;--line:#243046;--soft:#111826;
--pass:#4ade80;--pass-bg:#12321f;--warn:#fbbf24;--warn-bg:#3a2c0b;--fail:#f87171;--fail-bg:#3d1518;--info:#38bdf8;--info-bg:#0c2c40;--track:#243046}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:28px 20px 40px}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}
h1{font-size:22px;margin:0;font-weight:650;letter-spacing:-.01em}
h2{font-size:15px;margin:0 0 12px;font-weight:650}
.sub{color:var(--muted);font-size:13px}
button{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 12px;cursor:pointer;font:inherit;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.top{display:grid;grid-template-columns:280px 1fr;gap:16px}
.score{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.ring{position:relative;width:140px;height:140px}
.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .num b{font-size:38px;line-height:1;font-weight:700}
.ring .num span{color:var(--muted);font-size:12px}
.grade{margin-top:10px;font-weight:650;font-size:16px}
.good{color:var(--pass)}.mid{color:var(--warn)}.bad{color:var(--fail)}
.counts{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap;justify-content:center}
.counts span{font-size:12px;padding:3px 9px;border-radius:999px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid var(--line)}
.kv span{color:var(--muted);white-space:nowrap}
.kv b{font-weight:600;text-align:right;overflow-wrap:anywhere}
.pill{display:inline-block;min-width:48px;text-align:center;font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 8px;border-radius:999px}
.pill.pass,.counts .pass{background:var(--pass-bg);color:var(--pass)}
.pill.warn,.counts .warn{background:var(--warn-bg);color:var(--warn)}
.pill.fail,.counts .fail{background:var(--fail-bg);color:var(--fail)}
.pill.info,.counts .info{background:var(--info-bg);color:var(--info)}
ul.attn{list-style:none;margin:0;padding:0}
ul.attn li{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--line)}
ul.attn li:last-child{border-bottom:0}
ul.attn p{margin:2px 0 0;color:var(--muted)}
table{width:100%;border-collapse:collapse}
td,th{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
tr.cat td{background:var(--soft);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);padding:6px 10px}
td.st{width:72px}td.nm{width:200px;font-weight:600}
.rec{color:var(--muted);font-size:13px;margin-top:3px}
.num{text-align:right;white-space:nowrap}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.disk{margin-bottom:14px}.disk:last-child{margin-bottom:0}
.dh{display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px}
.dh span{color:var(--muted)}
.bar{height:9px;background:var(--track);border-radius:99px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:99px}
.bar i.pass{background:var(--pass)}.bar i.warn{background:var(--warn)}.bar i.fail{background:var(--fail)}.bar i.info{background:var(--info)}
.muted{color:var(--muted)}
.demo{background:var(--info-bg);color:var(--info);padding:8px 12px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:600}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}
@media (max-width:760px){.top,.cols,.grid{grid-template-columns:1fr}td.nm{width:auto}}
@media print{button{display:none}body{background:#fff}.card{break-inside:avoid}}
'@
}

function Get-WhcHtmlScript {
    # Light/dark theme: follows the system setting, with a toggle saved in the browser.
    @'
(function(){var k='whc-theme',r=document.documentElement,s=null;try{s=localStorage.getItem(k)}catch(e){}
var t=s||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');r.setAttribute('data-theme',t);
document.getElementById('theme').onclick=function(){t=(r.getAttribute('data-theme')==='dark')?'light':'dark';r.setAttribute('data-theme',t);try{localStorage.setItem(k,t)}catch(e){}};})();
'@
}

function ConvertTo-WhcHtml {
    # Builds a single self-contained HTML page (no external files, fonts or scripts).
    param([Parameter(Mandatory)] $Report)
    $s = $Report.Summary
    $sys = $Report.System
    function HtmlEnc($t) { ConvertTo-WhcHtmlText $t }
    function GetProp($o, $n) { if ($o -and $o.PSObject.Properties[$n]) { return $o.$n } return $null }

    $scoreClass = 'bad'
    if ($s.Score -ge 90) { $scoreClass = 'good' } elseif ($s.Score -ge 70) { $scoreClass = 'mid' }
    $dash = [math]::Round(326.73 * $s.Score / 100, 1)   # circumference of r=52

    # System information
    $admin = GetProp $sys 'RunAsAdmin'
    if ($null -ne $admin) { if ($admin) { $admin = 'Yes' } else { $admin = 'No' } }
    $model = ('{0} {1}' -f (GetProp $sys 'Manufacturer'), (GetProp $sys 'Model')).Trim()
    $sysRows = @(
        @('Computer', (GetProp $sys 'ComputerName')), @('User', (GetProp $sys 'UserName')),
        @('Model', $model), @('Serial number', (GetProp $sys 'SerialNumber')),
        @('Operating system', (GetProp $sys 'OperatingSystem')), @('Version', (GetProp $sys 'OsVersion')),
        @('Processor', (GetProp $sys 'Processor')), @('Memory', (GetProp $sys 'TotalMemory')),
        @('Domain', (GetProp $sys 'Domain')), @('Run as admin', $admin)
    )
    $sysHtml = New-Object System.Text.StringBuilder
    foreach ($row in $sysRows) {
        if ($row[1]) { [void]$sysHtml.Append("<div class=""kv""><span>$(HtmlEnc $row[0])</span><b>$(HtmlEnc $row[1])</b></div>") }
    }

    # Items that need attention, failures first
    $attention = @($Report.Results | Where-Object { $_.Status -eq 'FAIL' }) + @($Report.Results | Where-Object { $_.Status -eq 'WARN' })
    $attHtml = New-Object System.Text.StringBuilder
    if ($attention.Count -eq 0) {
        [void]$attHtml.Append('<p class="muted">Nothing needs attention. All scored checks passed.</p>')
    } else {
        [void]$attHtml.Append('<ul class="attn">')
        foreach ($r in $attention) {
            $cls = $r.Status.ToLower()
            [void]$attHtml.Append("<li><span class=""pill $cls"">$($r.Status)</span><div><b>$(HtmlEnc $r.Name)</b> <span class=""muted"">- $(HtmlEnc $r.Detail)</span><p>$(HtmlEnc $r.Recommendation)</p></div></li>")
        }
        [void]$attHtml.Append('</ul>')
    }

    # All results, grouped by category
    $rowsHtml = New-Object System.Text.StringBuilder
    $category = ''
    foreach ($r in $Report.Results) {
        if ($r.Category -ne $category) {
            $category = $r.Category
            [void]$rowsHtml.Append("<tr class=""cat""><td colspan=""3"">$(HtmlEnc $category)</td></tr>")
        }
        $cls = $r.Status.ToLower()
        $rec = ''
        if ($r.Recommendation) { $rec = "<div class=""rec"">$(HtmlEnc $r.Recommendation)</div>" }
        [void]$rowsHtml.Append("<tr><td class=""st""><span class=""pill $cls"">$($r.Status)</span></td><td class=""nm"">$(HtmlEnc $r.Name)</td><td>$(HtmlEnc $r.Detail)$rec</td></tr>")
    }

    # Disk usage bars
    $diskHtml = New-Object System.Text.StringBuilder
    foreach ($r in @($Report.Results | Where-Object { $_.Id -like 'disk-*' -and $null -ne (GetProp $_.Data 'FreePercent') })) {
        $d = $r.Data
        $usedPct = [math]::Round(100 - $d.FreePercent, 0)
        $label = $d.Drive
        if ($d.Label) { $label = "$label $($d.Label)" }
        [void]$diskHtml.Append("<div class=""disk""><div class=""dh""><b>$(HtmlEnc $label)</b><span>$(HtmlEnc (Format-WhcByteSize $d.FreeBytes)) free of $(HtmlEnc (Format-WhcByteSize $d.SizeBytes))</span></div><div class=""bar""><i class=""$($r.Status.ToLower())"" style=""width:$usedPct%""></i></div></div>")
    }
    if ($diskHtml.Length -eq 0) { [void]$diskHtml.Append('<p class="muted">No disk data.</p>') }

    # Top processes
    $procHtml = New-Object System.Text.StringBuilder
    $procResult = @($Report.Results | Where-Object { $_.Id -eq 'topprocesses' })
    if ($procResult.Count -and (GetProp $procResult[0].Data 'Processes')) {
        foreach ($p in @($procResult[0].Data.Processes)) {
            [void]$procHtml.Append("<tr><td>$(HtmlEnc $p.Name)</td><td class=""num"">$(HtmlEnc $p.Id)</td><td class=""num"">$('{0:N0}' -f $p.MemoryMB) MB</td></tr>")
        }
    }
    if ($procHtml.Length -eq 0) { [void]$procHtml.Append('<tr><td colspan="3" class="muted">No process data.</td></tr>') }

    # Network adapters
    $netHtml = New-Object System.Text.StringBuilder
    $netResult = @($Report.Results | Where-Object { $_.Id -eq 'network' })
    if ($netResult.Count -and $netResult[0].Data) {
        foreach ($a in @($netResult[0].Data)) {
            if (-not (GetProp $a 'IPv4')) { continue }
            [void]$netHtml.Append("<tr><td>$(HtmlEnc $a.Name)</td><td>$(HtmlEnc (@($a.IPv4) -join ', '))</td><td>$(HtmlEnc (@($a.Gateway) -join ', '))</td><td>$(HtmlEnc (@($a.DNS) -join ', '))</td></tr>")
        }
    }
    if ($netHtml.Length -eq 0) { [void]$netHtml.Append('<tr><td colspan="4" class="muted">No adapter data.</td></tr>') }

    # Pending updates
    $updHtml = ''
    $updResult = @($Report.Results | Where-Object { $_.Id -eq 'updates' })
    if ($updResult.Count -and @(GetProp $updResult[0].Data 'Pending').Count -gt 0) {
        $items = New-Object System.Text.StringBuilder
        foreach ($u in @($updResult[0].Data.Pending)) {
            $sev = ''
            if ((GetProp $u 'Severity')) { $sev = " <span class=""muted"">($(HtmlEnc $u.Severity))</span>" }
            [void]$items.Append("<tr><td>$(HtmlEnc $u.Title)$sev</td><td class=""num"">$(HtmlEnc (GetProp $u 'KB'))</td></tr>")
        }
        $updHtml = "<div class=""card""><h2>Pending updates</h2><table>$items</table></div>"
    }

    $demoBanner = ''
    if ($Report.DemoData) { $demoBanner = '<div class="demo">Demo report built from sample data, not from a real computer.</div>' }

    $css = Get-WhcHtmlStyle
    $js = Get-WhcHtmlScript
    $name = HtmlEnc (GetProp $sys 'ComputerName')

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Health report - $name</title>
<style>$css</style>
</head>
<body>
<div class="wrap">
<header>
  <div><h1>Windows Health Report</h1><div class="sub">$name &middot; generated $(HtmlEnc $Report.GeneratedAt) &middot; v$(HtmlEnc $Report.Version)</div></div>
  <button id="theme" type="button" title="Switch light / dark theme">Light / Dark</button>
</header>
$demoBanner
<div class="top">
  <div class="card score">
    <div class="ring">
      <svg width="140" height="140" viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--track)" stroke-width="10"/>
      <circle class="$scoreClass" cx="60" cy="60" r="52" fill="none" stroke="currentColor" stroke-width="10" stroke-linecap="round" stroke-dasharray="$dash 326.73"/></svg>
      <div class="num"><b>$($s.Score)</b><span>out of 100</span></div>
    </div>
    <div class="grade $scoreClass">$(HtmlEnc $s.Grade)</div>
    <div class="counts"><span class="pass">$($s.Pass) pass</span><span class="warn">$($s.Warn) warn</span><span class="fail">$($s.Fail) fail</span><span class="info">$($s.Info) info</span></div>
  </div>
  <div class="card"><h2>System</h2><div class="grid">$sysHtml</div></div>
</div>
<div class="card"><h2>Needs attention</h2>$attHtml</div>
<div class="card"><h2>All checks</h2><table>$rowsHtml</table></div>
<div class="cols">
  <div class="card"><h2>Disk usage</h2>$diskHtml</div>
  <div class="card"><h2>Top memory processes</h2><table><tr><th>Process</th><th class="num">PID</th><th class="num">Memory</th></tr>$procHtml</table></div>
</div>
<div class="card"><h2>Network adapters</h2><table><tr><th>Adapter</th><th>IPv4</th><th>Gateway</th><th>DNS</th></tr>$netHtml</table></div>
$updHtml
<footer>Windows Health Checker v$(HtmlEnc $Report.Version) &middot; read-only checks, no changes were made to this computer &middot; completed in $($Report.DurationSec) s</footer>
</div>
<script>$js</script>
</body>
</html>
"@
    return $html
}

function ConvertTo-WhcJson {
    param([Parameter(Mandatory)] $Report)
    return ($Report | ConvertTo-Json -Depth 8)
}

function Get-WhcDefaultOutputPath {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ($desktop -and (Test-Path -LiteralPath $desktop)) { return $desktop }
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) { return $env:TEMP }
    return (Get-Location).Path
}

function Save-WhcReport {
    # Writes the HTML and/or JSON files and returns their paths.
    param([Parameter(Mandatory)] $Report, [Parameter(Mandatory)] [string]$OutputPath, [switch]$Html, [switch]$Json)
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $safeName = ([string]$Report.System.ComputerName) -replace '[^A-Za-z0-9_-]', '_'
    if (-not $safeName) { $safeName = 'PC' }
    $stamp = ([datetime]$Report.GeneratedAt).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $OutputPath "HealthReport_$($safeName)_$stamp"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $paths = [ordered]@{ Html = $null; Json = $null }
    if ($Html) {
        $paths.Html = "$base.html"
        [System.IO.File]::WriteAllText($paths.Html, (ConvertTo-WhcHtml -Report $Report), $utf8)
    }
    if ($Json) {
        $paths.Json = "$base.json"
        [System.IO.File]::WriteAllText($paths.Json, (ConvertTo-WhcJson -Report $Report), $utf8)
    }
    [pscustomobject]$paths
}

function Get-WhcExitCode {
    param([Parameter(Mandatory)] $Summary)
    if ($Summary.Fail -gt 0) { return 2 }
    if ($Summary.Warn -gt 0) { return 1 }
    return 0
}

# ===========================================================================
# MAIN - skipped when the script is dot-sourced (for example by the tests)
# ===========================================================================

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $DemoData -and -not (Test-WhcIsWindows)) {
        Write-Error 'Windows Health Checker must run on Windows. Use -DemoData to see a sample report.'
        exit 3
    }
    if (-not $OutputPath) { $OutputPath = Get-WhcDefaultOutputPath }

    $report = Invoke-WindowsHealthCheck -SkipUpdateCheck:$SkipUpdateCheck -DemoData:$DemoData
    Write-WhcConsoleReport -Report $report

    $saved = $null
    if (-not $NoHtml -or $Json) {
        try {
            $saved = Save-WhcReport -Report $report -OutputPath $OutputPath -Html:(-not $NoHtml) -Json:$Json
            if ($saved.Html) { Write-WhcHost "  HTML report: $($saved.Html)" 'Cyan' }
            if ($saved.Json) { Write-WhcHost "  JSON report: $($saved.Json)" 'Cyan' }
            Write-WhcHost ''
        } catch {
            Write-Error "Could not save the report to '$OutputPath': $($_.Exception.Message)"
        }
    }
    if ($OpenReport -and $saved -and $saved.Html) {
        try { Invoke-Item -LiteralPath $saved.Html } catch { Write-WhcHost "  Could not open the report: $($_.Exception.Message)" 'Yellow' }
    }
    if ($PassThru) { $report }
    exit (Get-WhcExitCode -Summary $report.Summary)
}
