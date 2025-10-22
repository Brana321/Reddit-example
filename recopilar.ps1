<#
recopilar.ps1
Recopila info de sistema y escribe JSON en un share UNC (si es posible) y en %TEMP% siempre.
Uso: .\recopilar.ps1 -SharePath "\\miIP\InventarioRed"
#>

param(
    [string]$SharePath = ""
)

function SafeWriteJson {
    param(
        [object]$Obj,
        [string]$Filename
    )
    try {
        $json = $Obj | ConvertTo-Json -Depth 8 -Compress
    } catch {
        # si ConvertTo-Json falla por profundidad, intentar sin compresión
        $json = $Obj | ConvertTo-Json -Depth 8
    }

    $wroteShare = $false
    $wroteLocal = $false

    if ($SharePath -and ($SharePath -ne "")) {
        try {
            $resultsDir = Join-Path $SharePath "resultados"
            if (-not (Test-Path $resultsDir)) {
                New-Item -Path $resultsDir -ItemType Directory -Force | Out-Null
            }
            $shareOut = Join-Path $resultsDir $Filename
            $json | Out-File -FilePath $shareOut -Encoding UTF8 -Force
            Write-Host "WROTE_SHARE:$shareOut"
            $wroteShare = $true
        } catch {
            Write-Host "WARN: No se pudo escribir en share: $($_.Exception.Message)"
        }
    }

    try {
        $localOut = Join-Path $env:TEMP $Filename
        $json | Out-File -FilePath $localOut -Encoding UTF8 -Force
        Write-Host "WROTE_LOCAL:$localOut"
        $wroteLocal = $true
    } catch {
        Write-Host "ERROR: No se pudo escribir local: $($_.Exception.Message)"
    }

    return @{ share = $wroteShare; local = $wroteLocal }
}

function Get-InstalledPrograms {
    # Intenta varias rutas para programas instalados (x86/x64 registry + Uninstall)
    $items = @()
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($k in $keys) {
        try {
            Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $items += [PSCustomObject]@{
                        Name = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                        InstallDate = $_.InstallDate
                    }
                }
        } catch {}
    }
    return $items
}

function Collect-SystemInfo {
    $result = [ordered]@{}
    $result.ComputerName = $env:COMPUTERNAME
    $result.Timestamp = (Get-Date).ToString("o")

    try {
        $os = Get-CimInstance -ClassName CIM_OperatingSystem -ErrorAction Stop
        $result.OperatingSystem = @{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            InstallDate = ($os.InstallDate).ToString("o")
            LastBootUpTime = ($os.LastBootUpTime).ToString("o")
            Manufacturer = $os.Manufacturer
            OSArchitecture = $os.OSArchitecture
        }
    } catch {
        $result.OperatingSystem = @{ Error = $_.Exception.Message }
    }

    try {
        $cpu = Get-CimInstance -ClassName CIM_Processor | Select-Object -First 1
        $result.CPU = @{
            Name = $cpu.Name
            Cores = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            MaxClockSpeedMHz = $cpu.MaxClockSpeed
            Manufacturer = $cpu.Manufacturer
        }
    } catch {
        $result.CPU = @{ Error = $_.Exception.Message }
    }

    try {
        $mem = Get-CimInstance -ClassName Win32_ComputerSystem
        $result.Memory = @{
            TotalPhysicalMB = [math]::Round($mem.TotalPhysicalMemory / 1MB, 2)
        }
    } catch {
        $result.Memory = @{ Error = $_.Exception.Message }
    }

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
            [PSCustomObject]@{
                DeviceID = $_.DeviceID
                SizeGB = if ($_.Size) { [math]::Round($_.Size/1GB,2) } else { $null }
                FreeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace/1GB,2) } else { $null }
                FileSystem = $_.FileSystem
                VolumeName = $_.VolumeName
            }
        }
        $result.Disks = $disks
    } catch {
        $result.Disks = @{ Error = $_.Exception.Message }
    }

    try {
        $net = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object {
            [PSCustomObject]@{
                Description = $_.Description
                MAC = $_.MACAddress
                IPAddresses = $_.IPAddress
                DefaultIPGateway = $_.DefaultIPGateway
                DNSServers = $_.DNSServerSearchOrder
                DHCPEnabled = $_.DHCPEnabled
            }
        }
        $result.Network = $net
    } catch {
        $result.Network = @{ Error = $_.Exception.Message }
    }

    try {
        $procs = Get-Process | Select-Object -First 200 | ForEach-Object {
            [PSCustomObject]@{
                ProcessName = $_.ProcessName
                Id = $_.Id
                CPU = $_.CPU
                WorkingSetMB = [math]::Round($_.WorkingSet/1MB,2)
                Path = ($_.Path -as [string])
            }
        }
        $result.Processes = $procs
    } catch {
        $result.Processes = @{ Error = $_.Exception.Message }
    }

    try {
        $services = Get-Service | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='${($_.Name)}'" -ErrorAction SilentlyContinue).StartMode
            }
        }
        $result.Services = $services
    } catch {
        $result.Services = @{ Error = $_.Exception.Message }
    }

    try {
        $installed = Get-InstalledPrograms
        $result.InstalledPrograms = $installed
    } catch {
        $result.InstalledPrograms = @{ Error = $_.Exception.Message }
    }

    try {
        # Small network tests
        $result.NetTest = @{
            Hostname = (hostname)
            DNS = (Resolve-DnsName -Name (hostname) -ErrorAction SilentlyContinue | Select-Object -First 1 | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue)
        }
    } catch {}

    return $result
}

# --- Main ---
try {
    $collected = Collect-SystemInfo
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostname = $env:COMPUTERNAME
    $filename = "${hostname}_${timestamp}.json"

    $wr = SafeWriteJson -Obj $collected -Filename $filename

    # For debugging: print summary
    Write-Host "SUMMARY: Host=$hostname; ShareWrite=$($wr.share); LocalWrite=$($wr.local)"
} catch {
    $errObj = @{
        Success = $false
        Computer = $env:COMPUTERNAME
        Error = $_.Exception.Message
        Timestamp = (Get-Date).ToString("o")
    }
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $filename = "${env:COMPUTERNAME}_ERROR_${timestamp}.json"
    SafeWriteJson -Obj $errObj -Filename $filename
    Write-Host "ERROR_GLOBAL: $($_.Exception.Message)"
}
