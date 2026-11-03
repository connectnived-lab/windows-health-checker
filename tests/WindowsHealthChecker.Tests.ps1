#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Pester tests for WindowsHealthChecker.ps1.

    The evaluation functions are tested with mock data, and the Windows-only
    cmdlets (Get-CimInstance, Get-MpComputerStatus, Get-WinEvent, ...) are mocked,
    so the suite also runs on Linux/macOS with PowerShell 7.

    Run:  Invoke-Pester -Path .\tests -Output Detailed
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot '..\src\WindowsHealthChecker.ps1'
    $script:ScriptPath = [System.IO.Path]::GetFullPath($script:ScriptPath.Replace('\', [System.IO.Path]::DirectorySeparatorChar))

    # Stubs so Pester can mock Windows-only commands on any OS.
    # On Windows the real commands exist and these are skipped.
    $stubs = @{
        'Get-CimInstance'        = 'param([string]$ClassName, [string]$Namespace, [string]$Filter)'
        'Get-MpComputerStatus'   = 'param()'
        'Get-NetFirewallProfile' = 'param()'
        'Get-WinEvent'           = 'param([hashtable]$FilterHashtable)'
        'Get-HotFix'             = 'param()'
        'Get-BitLockerVolume'    = 'param([string]$MountPoint)'
    }
    foreach ($name in $stubs.Keys) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            $body = "[CmdletBinding()] $($stubs[$name]) throw '$name is not available on this system'"
            Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create($body))
        }
    }

    . $script:ScriptPath
    $script:Now = Get-Date '2026-11-03 10:00'
}

Describe 'Script file' {
    It 'parses without errors' {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It 'contains only ASCII characters (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
        $bytes = [System.IO.File]::ReadAllBytes($script:ScriptPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'does not run the main block when dot-sourced' {
        Get-Command Invoke-WindowsHealthCheck -CommandType Function | Should -Not -BeNullOrEmpty
    }
}

Describe 'Operating system check' {
    It 'passes a current Windows 11 build' {
        $r = Test-WhcOperatingSystem -Data ([pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; BuildNumber = 26100; UBR = 2314; DisplayVersion = '24H2' })
        $r.Status | Should -Be 'PASS'
        $r.Detail | Should -Match '26100.2314'
    }
    It 'warns on an older Windows 11 feature update' {
        (Test-WhcOperatingSystem -Data ([pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; BuildNumber = 22631; UBR = $null; DisplayVersion = '23H2' })).Status | Should -Be 'WARN'
    }
    It 'warns on Windows 10' {
        $r = Test-WhcOperatingSystem -Data ([pscustomobject]@{ Caption = 'Microsoft Windows 10 Pro'; BuildNumber = 19045; UBR = 5011; DisplayVersion = '22H2' })
        $r.Status | Should -Be 'WARN'
        $r.Recommendation | Should -Match 'Windows 11'
    }
    It 'fails on Windows 7' {
        (Test-WhcOperatingSystem -Data ([pscustomobject]@{ Caption = 'Microsoft Windows 7 Professional'; BuildNumber = 7601; UBR = $null; DisplayVersion = $null })).Status | Should -Be 'FAIL'
    }
}

Describe 'Uptime check' {
    It 'returns <Expected> after <Days> days' -TestCases @(
        @{ Days = 2; Expected = 'PASS' }
        @{ Days = 20; Expected = 'WARN' }
        @{ Days = 45; Expected = 'FAIL' }
    ) {
        param($Days, $Expected)
        $r = Test-WhcUptime -Data ([pscustomobject]@{ LastBootUpTime = $script:Now.AddDays(-$Days) }) -Now $script:Now
        $r.Status | Should -Be $Expected
    }
}

Describe 'Pending reboot check' {
    It 'passes when nothing is pending' {
        (Test-WhcPendingReboot -Data ([pscustomobject]@{ ComponentServicing = $false; WindowsUpdate = $false; FileRename = $false })).Status | Should -Be 'PASS'
    }
    It 'warns and names the reason' {
        $r = Test-WhcPendingReboot -Data ([pscustomobject]@{ ComponentServicing = $false; WindowsUpdate = $true; FileRename = $false })
        $r.Status | Should -Be 'WARN'
        $r.Detail | Should -Match 'Windows Update'
    }
}

Describe 'CPU and memory checks' {
    It 'CPU <Load>% is <Expected>' -TestCases @(
        @{ Load = 20; Expected = 'PASS' }
        @{ Load = 80; Expected = 'WARN' }
        @{ Load = 97; Expected = 'FAIL' }
    ) {
        param($Load, $Expected)
        (Test-WhcCpu -Data ([pscustomobject]@{ LoadPercent = $Load; Name = 'Test CPU'; Cores = 4; LogicalProcessors = 8 })).Status | Should -Be $Expected
    }
    It 'CPU without a reading is INFO' {
        (Test-WhcCpu -Data ([pscustomobject]@{ LoadPercent = $null; Name = 'x'; Cores = 1; LogicalProcessors = 1 })).Status | Should -Be 'INFO'
    }
    It 'memory <UsedPct>% used is <Expected>' -TestCases @(
        @{ UsedPct = 50; Expected = 'PASS' }
        @{ UsedPct = 85; Expected = 'WARN' }
        @{ UsedPct = 95; Expected = 'FAIL' }
    ) {
        param($UsedPct, $Expected)
        $total = 16000000
        $r = Test-WhcMemory -Data ([pscustomobject]@{ TotalKB = $total; FreeKB = $total * (100 - $UsedPct) / 100 })
        $r.Status | Should -Be $Expected
        $r.Data.UsedPercent | Should -Be $UsedPct
    }
}

Describe 'Disk check' {
    It 'returns one result per drive with the right status' {
        $drives = @(
            [pscustomobject]@{ Drive = 'C:'; Label = 'OS'; FileSystem = 'NTFS'; SizeBytes = 100GB; FreeBytes = 40GB; IsSystem = $true }
            [pscustomobject]@{ Drive = 'D:'; Label = ''; FileSystem = 'NTFS'; SizeBytes = 100GB; FreeBytes = 10GB; IsSystem = $false }
            [pscustomobject]@{ Drive = 'E:'; Label = ''; FileSystem = 'NTFS'; SizeBytes = 100GB; FreeBytes = 3GB; IsSystem = $false }
        )
        $r = @(Test-WhcDisk -Data $drives)
        $r.Count | Should -Be 3
        $r[0].Status | Should -Be 'PASS'
        $r[1].Status | Should -Be 'WARN'
        $r[2].Status | Should -Be 'FAIL'
        $r[0].Weight | Should -BeGreaterThan $r[1].Weight
    }
    It 'treats exactly 15% free as PASS (warning is below 15%)' {
        (Test-WhcDisk -Data @([pscustomobject]@{ Drive = 'C:'; Label = ''; FileSystem = 'NTFS'; SizeBytes = 100GB; FreeBytes = 15GB; IsSystem = $true })).Status | Should -Be 'PASS'
    }
    It 'returns INFO when no drives are found' {
        (Test-WhcDisk -Data @()).Status | Should -Be 'INFO'
    }
}

Describe 'Windows Update check' {
    It 'passes when nothing is pending and patches are recent' {
        $r = Test-WhcWindowsUpdate -Data ([pscustomobject]@{ SearchStatus = 'OK'; SearchError = $null; Pending = @(); LastInstalled = $script:Now.AddDays(-10) }) -Now $script:Now
        $r.Status | Should -Be 'PASS'
    }
    It 'warns when updates are waiting' {
        $pending = @([pscustomobject]@{ Title = 'Cumulative Update'; Severity = 'Critical'; KB = 'KB1' })
        $r = Test-WhcWindowsUpdate -Data ([pscustomobject]@{ SearchStatus = 'OK'; SearchError = $null; Pending = $pending; LastInstalled = $script:Now.AddDays(-10) }) -Now $script:Now
        $r.Status | Should -Be 'WARN'
        $r.Detail | Should -Match '1 update'
    }
    It 'fails when the last update is over 60 days old' {
        (Test-WhcWindowsUpdate -Data ([pscustomobject]@{ SearchStatus = 'OK'; SearchError = $null; Pending = @(); LastInstalled = $script:Now.AddDays(-75) }) -Now $script:Now).Status | Should -Be 'FAIL'
    }
    It 'falls back to the last-installed date when the search times out' {
        $r = Test-WhcWindowsUpdate -Data ([pscustomobject]@{ SearchStatus = 'Timeout'; SearchError = 'no answer'; Pending = @(); LastInstalled = $script:Now.AddDays(-5) }) -Now $script:Now
        $r.Status | Should -Be 'PASS'
        $r.Detail | Should -Match 'could not be checked'
    }
    It 'is INFO when nothing is known' {
        (Test-WhcWindowsUpdate -Data ([pscustomobject]@{ SearchStatus = 'Skipped'; SearchError = $null; Pending = @(); LastInstalled = $null }) -Now $script:Now).Status | Should -Be 'INFO'
    }
}

Describe 'Antivirus check' {
    BeforeAll {
        function New-Defender([bool]$Av = $true, [bool]$Rtp = $true, [double]$SigAge = 0.5, $Quick = 1, $Full = 20) {
            [pscustomobject]@{ AntivirusEnabled = $Av; RealTimeProtectionEnabled = $Rtp; SignatureAgeDays = $SigAge; QuickScanAgeDays = $Quick; FullScanAgeDays = $Full }
        }
    }
    It 'passes with Defender on and fresh definitions' {
        (Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender); Products = @() })).Status | Should -Be 'PASS'
    }
    It 'warns on definitions 5 days old' {
        (Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender -SigAge 5); Products = @() })).Status | Should -Be 'WARN'
    }
    It 'fails on definitions 10 days old' {
        (Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender -SigAge 10); Products = @() })).Status | Should -Be 'FAIL'
    }
    It 'warns when no scan has run in 30 days' {
        (Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender -Quick 30 -Full 40); Products = @() })).Status | Should -Be 'WARN'
    }
    It 'fails when real-time protection is off and nothing else is active' {
        $r = Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender -Rtp $false); Products = @() })
        $r.Status | Should -Be 'FAIL'
        $r.Detail | Should -Match 'real-time'
    }
    It 'accepts an active third-party antivirus when Defender is off' {
        $p = @([pscustomobject]@{ Name = 'Sophos Endpoint'; Enabled = $true; UpToDate = $true })
        $r = Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = (New-Defender -Av $false -Rtp $false); Products = $p })
        $r.Status | Should -Be 'PASS'
        $r.Detail | Should -Match 'Sophos'
    }
    It 'is INFO when nothing can be read' {
        (Test-WhcAntivirus -Data ([pscustomobject]@{ Defender = $null; Products = @() })).Status | Should -Be 'INFO'
    }
    It 'decodes Security Center productState values' -TestCases @(
        @{ State = 397568; Enabled = $true;  UpToDate = $true }   # 0x061100
        @{ State = 397584; Enabled = $true;  UpToDate = $false }  # 0x061110
        @{ State = 393472; Enabled = $false; UpToDate = $true }   # 0x060100
    ) {
        param($State, $Enabled, $UpToDate)
        $p = ConvertFrom-WhcProductState -Name 'AV' -ProductState $State
        $p.Enabled | Should -Be $Enabled
        $p.UpToDate | Should -Be $UpToDate
    }
}

Describe 'Firewall, BitLocker and failed login checks' {
    It 'fails when any firewall profile is off' {
        $r = Test-WhcFirewall -Data @([pscustomobject]@{ Name = 'Domain'; Enabled = $true }, [pscustomobject]@{ Name = 'Public'; Enabled = $false })
        $r.Status | Should -Be 'FAIL'
        $r.Recommendation | Should -Match 'Public'
    }
    It 'passes when all profiles are on' {
        (Test-WhcFirewall -Data @([pscustomobject]@{ Name = 'Domain'; Enabled = $true }, [pscustomobject]@{ Name = 'Private'; Enabled = $true })).Status | Should -Be 'PASS'
    }
    It 'BitLocker <Protection> on laptop=<Laptop> is <Expected>' -TestCases @(
        @{ Protection = 'On'; Laptop = $true; Expected = 'PASS' }
        @{ Protection = 'Suspended'; Laptop = $true; Expected = 'WARN' }
        @{ Protection = 'Off'; Laptop = $false; Expected = 'WARN' }
        @{ Protection = 'Off'; Laptop = $true; Expected = 'FAIL' }
        @{ Protection = 'Unknown'; Laptop = $true; Expected = 'INFO' }
    ) {
        param($Protection, $Laptop, $Expected)
        (Test-WhcBitLocker -Data ([pscustomobject]@{ Source = 'test'; Drive = 'C:'; Protection = $Protection; IsLaptop = $Laptop })).Status | Should -Be $Expected
    }
    It 'failed logins: <Count> is <Expected>' -TestCases @(
        @{ Count = 0; Expected = 'PASS' }
        @{ Count = 7; Expected = 'WARN' }
        @{ Count = 40; Expected = 'FAIL' }
    ) {
        param($Count, $Expected)
        (Test-WhcFailedLogin -Data ([pscustomobject]@{ Status = 'OK'; Count = $Count; TopAccounts = @() })).Status | Should -Be $Expected
    }
    It 'failed logins without admin rights is INFO, not FAIL' {
        (Test-WhcFailedLogin -Data ([pscustomobject]@{ Status = 'AccessDenied'; Count = $null; TopAccounts = @() })).Status | Should -Be 'INFO'
    }
}

Describe 'Network, battery, process and startup checks' {
    It 'passes a normal adapter' {
        $a = @([pscustomobject]@{ Name = 'Ethernet'; IPv4 = @('10.0.0.5'); Gateway = @('10.0.0.1'); DNS = @('10.0.0.2') })
        (Test-WhcNetworkAdapter -Data $a).Status | Should -Be 'PASS'
    }
    It 'fails when the only address is self-assigned (APIPA)' {
        $a = @([pscustomobject]@{ Name = 'Ethernet'; IPv4 = @('169.254.10.20'); Gateway = @(); DNS = @() })
        (Test-WhcNetworkAdapter -Data $a).Status | Should -Be 'FAIL'
    }
    It 'fails with no adapters' {
        (Test-WhcNetworkAdapter -Data @()).Status | Should -Be 'FAIL'
    }
    It 'internet: web OK is PASS, DNS only is WARN, nothing is FAIL' {
        $ok = [pscustomobject]@{ Target = '1.1.1.1'; Success = $true; LatencyMs = 20 }
        $bad = [pscustomobject]@{ Target = '1.1.1.1'; Success = $false; LatencyMs = $null }
        (Test-WhcInternet -Data ([pscustomobject]@{ Pings = @($ok); DnsOk = $true; HttpOk = $true })).Status | Should -Be 'PASS'
        (Test-WhcInternet -Data ([pscustomobject]@{ Pings = @($bad); DnsOk = $true; HttpOk = $false })).Status | Should -Be 'WARN'
        (Test-WhcInternet -Data ([pscustomobject]@{ Pings = @($bad); DnsOk = $false; HttpOk = $false })).Status | Should -Be 'FAIL'
    }
    It 'internet: high latency is WARN' {
        $slow = [pscustomobject]@{ Target = '1.1.1.1'; Success = $true; LatencyMs = 400 }
        (Test-WhcInternet -Data ([pscustomobject]@{ Pings = @($slow); DnsOk = $true; HttpOk = $true })).Status | Should -Be 'WARN'
    }
    It 'battery health <Full>/<Design> is <Expected>' -TestCases @(
        @{ Design = 50000; Full = 47000; Expected = 'PASS' }
        @{ Design = 50000; Full = 36000; Expected = 'WARN' }
        @{ Design = 50000; Full = 25000; Expected = 'FAIL' }
    ) {
        param($Design, $Full, $Expected)
        (Test-WhcBattery -Data ([pscustomobject]@{ Present = $true; ChargePercent = 90; DesignCapacity = $Design; FullChargeCapacity = $Full })).Status | Should -Be $Expected
    }
    It 'desktop without battery is INFO' {
        (Test-WhcBattery -Data ([pscustomobject]@{ Present = $false })).Status | Should -Be 'INFO'
    }
    It 'warns when one process uses more than 25% of RAM' {
        $d = [pscustomobject]@{ TotalMemoryMB = 8000; Processes = @([pscustomobject]@{ Name = 'leaky'; Id = 1; MemoryMB = 3000 }) }
        $r = Test-WhcTopProcess -Data $d
        $r.Status | Should -Be 'WARN'
        $r.Recommendation | Should -Match 'leaky'
    }
    It 'warns on more than 15 startup programs' {
        (Test-WhcStartup -Data ([pscustomobject]@{ Count = 22; Items = @() })).Status | Should -Be 'WARN'
        (Test-WhcStartup -Data ([pscustomobject]@{ Count = 8; Items = @() })).Status | Should -Be 'PASS'
    }
}

Describe 'Scoring' {
    It 'scores PASS as full, WARN as half and FAIL as zero, ignoring INFO' {
        $results = @(
            New-WhcResult -Id a -Category x -Name a -Status PASS -Detail d -Weight 10
            New-WhcResult -Id b -Category x -Name b -Status WARN -Detail d -Weight 10
            New-WhcResult -Id c -Category x -Name c -Status FAIL -Detail d -Weight 10
            New-WhcResult -Id d -Category x -Name d -Status INFO -Detail d -Weight 50
        )
        $s = Get-WhcScore -Results $results
        $s.Score | Should -Be 50
        $s.Pass | Should -Be 1; $s.Warn | Should -Be 1; $s.Fail | Should -Be 1; $s.Info | Should -Be 1
    }
    It 'grades 100 as Healthy and 40 as At risk' {
        (Get-WhcScore -Results @(New-WhcResult -Id a -Category x -Name a -Status PASS -Detail d -Weight 5)).Grade | Should -Be 'Healthy'
        $r = @(
            New-WhcResult -Id a -Category x -Name a -Status FAIL -Detail d -Weight 6
            New-WhcResult -Id b -Category x -Name b -Status PASS -Detail d -Weight 4
        )
        (Get-WhcScore -Results $r).Grade | Should -Be 'At risk'
    }
    It 'maps the summary to exit codes 0/1/2' {
        Get-WhcExitCode -Summary ([pscustomobject]@{ Fail = 0; Warn = 0 }) | Should -Be 0
        Get-WhcExitCode -Summary ([pscustomobject]@{ Fail = 0; Warn = 3 }) | Should -Be 1
        Get-WhcExitCode -Summary ([pscustomobject]@{ Fail = 1; Warn = 3 }) | Should -Be 2
    }
}

Describe 'Error isolation' {
    It 'turns a collector error into an INFO result instead of stopping' {
        $check = @{ Id = 'boom'; Category = 'System'; Name = 'Broken check'; Collect = { throw 'WMI repository is corrupt' }; Evaluate = { param($d) throw 'not reached' } }
        $r = @(Invoke-WhcCheck -Check $check)
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'INFO'
        $r[0].Detail | Should -Match 'WMI repository is corrupt'
    }
    It 'keeps going when a check fails in the middle of a full run' {
        Mock Get-WhcFirewallData { throw 'simulated failure' }
        $report = Invoke-WindowsHealthCheck -SkipUpdateCheck
        @($report.Results).Count | Should -BeGreaterOrEqual 16
        ($report.Results | Where-Object Id -eq 'firewall').Status | Should -Be 'INFO'
    }
}

Describe 'Collectors with mocked Windows cmdlets' {
    It 'reads fixed disks from Win32_LogicalDisk' {
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' } -MockWith {
            @([pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'OS'; FileSystem = 'NTFS'; Size = 256GB; FreeSpace = 20GB })
        }
        $env:SystemDrive = 'C:'
        $d = @(Get-WhcDiskData)
        $d.Count | Should -Be 1
        $d[0].IsSystem | Should -BeTrue
        $d[0].FreeBytes | Should -Be 20GB
    }
    It 'reads memory from Win32_OperatingSystem' {
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' } -MockWith {
            [pscustomobject]@{ TotalVisibleMemorySize = 8000000; FreePhysicalMemory = 2000000 }
        }
        (Test-WhcMemory -Data (Get-WhcMemoryData)).Data.UsedPercent | Should -Be 75
    }
    It 'reads firewall profiles' {
        Mock Get-NetFirewallProfile {
            @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }, [pscustomobject]@{ Name = 'Public'; Enabled = 'False' })
        }
        $f = @(Get-WhcFirewallData)
        $f.Count | Should -Be 2
        ($f | Where-Object Name -eq 'Public').Enabled | Should -BeFalse
    }
    It 'reads Defender status and treats "never scanned" as no scan' {
        Mock Get-MpComputerStatus {
            [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1; AntivirusSignatureLastUpdated = (Get-Date); QuickScanAge = 4294967295; FullScanAge = 4294967295; QuickScanEndTime = $null }
        }
        Mock Get-CimInstance -ParameterFilter { $Namespace -eq 'root/SecurityCenter2' } -MockWith {
            @([pscustomobject]@{ displayName = 'Windows Defender'; productState = 397568 })
        }
        $data = Get-WhcAntivirusData
        $data.Defender.QuickScanAgeDays | Should -BeNullOrEmpty
        @($data.Products).Count | Should -Be 1
        (Test-WhcAntivirus -Data $data).Status | Should -Be 'WARN'
    }
    It 'reports AccessDenied when the Security log cannot be read' {
        Mock Get-WinEvent { throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.') }
        (Get-WhcFailedLoginData).Status | Should -Be 'AccessDenied'
    }
    It 'counts failed logon events and groups them by account' {
        Mock Get-WinEvent {
            $mk = { param($u) [pscustomobject]@{ Properties = @(0, 1, 2, 3, 4, [pscustomobject]@{ Value = $u }) } }
            @((& $mk 'admin'), (& $mk 'admin'), (& $mk 'guest'))
        }
        $d = Get-WhcFailedLoginData
        $d.Count | Should -Be 3
        $d.TopAccounts[0].Account | Should -Be 'admin'
        $d.TopAccounts[0].Count | Should -Be 2
    }
}

Describe 'Demo report and output files' {
    BeforeAll {
        $script:Report = Invoke-WindowsHealthCheck -DemoData
    }
    It 'produces a result for every check' {
        @($script:Report.Results).Count | Should -Be 17   # 16 checks, two disks
        $script:Report.Results.Status | ForEach-Object { $_ | Should -BeIn @('PASS', 'WARN', 'FAIL', 'INFO') }
    }
    It 'gives the demo laptop a score of 77 (Needs attention)' {
        $script:Report.Summary.Score | Should -Be 77
        $script:Report.Summary.Grade | Should -Be 'Needs attention'
    }
    It 'builds self-contained HTML with no external resources' {
        $html = ConvertTo-WhcHtml -Report $script:Report
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match 'LT-SUPPORT-042'
        $html | Should -Not -Match '(src|href)="https?://'
        $html | Should -Not -Match '@import'
    }
    It 'HTML-encodes text taken from the system' {
        $r = $script:Report.PSObject.Copy()
        $r.Results = @(New-WhcResult -Id x -Category System -Name 'Evil <b>' -Status PASS -Detail '<script>alert(1)</script>' -Weight 1)
        $html = ConvertTo-WhcHtml -Report $r
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match '&lt;script&gt;alert'
    }
    It 'produces valid JSON' {
        $obj = ConvertTo-WhcJson -Report $script:Report | ConvertFrom-Json
        $obj.Summary.Score | Should -Be 77
        @($obj.Results).Count | Should -Be 17
    }
    It 'writes the HTML and JSON files' {
        $out = Join-Path $TestDrive 'reports'
        $paths = Save-WhcReport -Report $script:Report -OutputPath $out -Html -Json
        Test-Path $paths.Html | Should -BeTrue
        Test-Path $paths.Json | Should -BeTrue
        $paths.Html | Should -Match 'HealthReport_LT-SUPPORT-042_\d{8}-\d{6}\.html$'
    }
    It 'runs end to end as a script with -DemoData -Quiet and returns exit code 2' {
        $out = Join-Path $TestDrive 'e2e'
        $exe = (Get-Process -Id $PID).Path
        & $exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath -DemoData -Quiet -Json -OutputPath $out
        $LASTEXITCODE | Should -Be 2
        @(Get-ChildItem $out -Filter *.html).Count | Should -Be 1
        @(Get-ChildItem $out -Filter *.json).Count | Should -Be 1
    }
}
