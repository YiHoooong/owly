#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Standalone Windows demo launcher for owly + mtkradio.exe (MT7922, VHT 80 MHz).

.DESCRIPTION
  1. Ensures owly.exe is built (using VS 2022 BuildTools + cargo if needed).
  2. Opens Windows Firewall for owly.exe (TCP 8771 AirDrop + UDP 5353 mDNS).
  3. Starts mtkradio.exe on the chosen channel (default: ch 149, 80 MHz, --no-block-ack --verbose)
     as SYSTEM (for SeLockMemoryPrivilege on Windows 11) serving \\.\pipe\winawdl-radio,
     streaming mtkradio's log live to this console.
  4. Runs owly.exe in `receive`, `send`, `browse`, or `radio` mode with full visible logs.
  5. Cleanly stops mtkradio.exe and removes the temporary scheduled task on exit / Ctrl-C.

.EXAMPLE
  .\run-demo.ps1 -Mode receive
  .\run-demo.ps1 -Mode send -Files .\tests\photo.png
  .\run-demo.ps1 -Mode send -Files .\tests\photo.png -To "iPhone"
  .\run-demo.ps1 -Mode browse
  .\run-demo.ps1 -Mode radio
#>
param(
    [ValidateSet('receive', 'send', 'browse', 'radio')]
    [string]$Mode = 'receive',

    [ValidateSet(6, 44, 149)]
    [int]$Channel = 149,

    [ValidateSet(20, 40, 80)]
    [int]$Width = 80,

    [string]$Name = 'owly-MT7922',

    [string]$Dir = (Join-Path $PSScriptRoot 'received'),

    [string[]]$Files = @(),

    [string]$To = '',

    [switch]$Prompt,

    [switch]$SkipRadio,

    [switch]$NoSystem,

    [switch]$Direct,

    [switch]$Build
)

$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
$parent = Split-Path $repo -Parent
$pipe = '\\.\pipe\winawdl-radio'
$taskName = 'OwlyMtkRadioDemo'
$radioLog = Join-Path $repo 'mtkradio-demo.log'

# 1. Locate or build owly.exe
$owlyExe = Join-Path $repo 'target\release\owly.exe'
if ($Build -or -not (Test-Path $owlyExe)) {
    $env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found on PATH. Install Rustup + VS 2022 Build Tools, then re-run."
    }
    $toolchain = Join-Path $parent 'nekodrop\scripts\toolchain.ps1'
    if (Test-Path $toolchain) {
        . $toolchain
        Initialize-Toolchain | Out-Null
    }
    Write-Host "[demo] Building owly-cli (release)..." -ForegroundColor Cyan
    Push-Location $repo
    try {
        & cargo build -p owly-cli --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
}

# 2. Locate wintun.dll & airdrop-beacon.ps1
$wintunCandidates = @(
    (Join-Path $repo 'wintun.dll'),
    (Join-Path (Split-Path $owlyExe -Parent) 'wintun.dll'),
    (Join-Path $parent 'nekodrop-0.1.21-windows-x64\awdl\wintun.dll')
)
$wintun = $wintunCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $wintun) {
    throw "wintun.dll not found. Place wintun.dll in $repo or next to owly.exe."
}
$env:OWLY_WINTUN_DLL = $wintun
Write-Host "[demo] Using wintun.dll: $wintun" -ForegroundColor DarkGray

$beacon = Join-Path $repo 'scripts\airdrop-beacon.ps1'
if (Test-Path $beacon) {
    $env:OWLY_BEACON_SCRIPT = $beacon
}

# 3. Ensure Windows Firewall allows AirDrop (TCP 8771) and mDNS (UDP 5353)
$ruleName = 'Owly-AirDrop-Demo'
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    Write-Host "[demo] Adding Windows Firewall rule '$ruleName' for $owlyExe..." -ForegroundColor Cyan
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Program $owlyExe -Protocol Any | Out-Null
}

# 4. Locate and start mtkradio.exe (unless -SkipRadio or -Direct)
$radioProc = $null
$usedSystemTask = $false
$directDll = ''
$directFwDir = ''
if ($Direct) {
    $dllCandidates = @(
        (Join-Path $parent 'nekodrop\mtkradio\build\mtkradio_core.dll'),
        (Join-Path $repo 'mtkradio_core.dll')
    )
    $directDll = $dllCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $directDll) { throw "mtkradio_core.dll not found under $parent" }
    $fwCandidates = @(
        (Join-Path (Split-Path $directDll -Parent) 'firmware'),
        (Join-Path $parent 'nekodrop\mtkradio\firmware'),
        (Join-Path $parent 'nekodrop-0.1.21-windows-x64\radio\firmware')
    )
    $directFwDir = $fwCandidates | Where-Object {
        (Test-Path (Join-Path $_ 'WIFI_MT7922_patch_mcu_1_1_hdr.bin')) -and
        (Test-Path (Join-Path $_ 'WIFI_RAM_CODE_MT7922_1.bin'))
    } | Select-Object -First 1
    if (-not $directFwDir) { throw "MT7922 firmware (.bin) files not found under $parent" }
    Get-Process -Name mtkradio,owly -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $pipe = 'direct'
    $env:OWLY_MTKRADIO_DLL = $directDll
    $env:OWLY_MTK_FW_DIR = $directFwDir
    Write-Host "[demo] Single-process DIRECT mode: dll=$directDll fw=$directFwDir" -ForegroundColor Green
} elseif (-not $SkipRadio) {
    $radioCandidates = @(
        (Join-Path $parent 'nekodrop\mtkradio\build\mtkradio.exe'),
        (Join-Path $parent 'nekodrop-0.1.21-windows-x64\radio\mtkradio.exe'),
        (Join-Path $parent 'mtkradio-win-pkg\mtkradio\mtkradio.exe')
    )
    $radioExe = $radioCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $radioExe) {
        throw "mtkradio.exe not found in any expected location under $parent"
    }

    $fwCandidates = @(
        (Join-Path (Split-Path $radioExe -Parent) 'firmware'),
        (Join-Path $parent 'nekodrop\mtkradio\firmware'),
        (Join-Path $parent 'nekodrop-0.1.21-windows-x64\radio\firmware')
    )
    $fwDir = $fwCandidates | Where-Object {
        (Test-Path (Join-Path $_ 'WIFI_MT7922_patch_mcu_1_1_hdr.bin')) -and
        (Test-Path (Join-Path $_ 'WIFI_RAM_CODE_MT7922_1.bin'))
    } | Select-Object -First 1
    if (-not $fwDir) {
        throw "MT7922 firmware (.bin) files not found under $parent"
    }

    # Stop any stale mtkradio instance first
    Get-Process -Name mtkradio -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $effWidth = if ($Channel -le 14) { 20 } else { $Width }
    Write-Host "[demo] Radio: $radioExe (ch=$Channel, width=${effWidth}MHz, fw=$fwDir)" -ForegroundColor Green

    if (-not $NoSystem) {
        # Launch as SYSTEM via a short .cmd wrapper so schtasks /TR stays well under
        # its 261-character limit and full mtkradio logs (including HW TX/RX BA) are captured.
        if (Test-Path $radioLog) { Remove-Item $radioLog -Force }
        $radioCmd = Join-Path $repo 'run-mtkradio.cmd'
        @(
            '@echo off'
            "`"$radioExe`" $Channel --width $effWidth --firmware `"$fwDir`" --no-block-ack --verbose > `"$radioLog`" 2>&1"
        ) | Set-Content -Path $radioCmd -Encoding ASCII
        schtasks /Create /F /RU SYSTEM /SC ONCE /ST 00:00 /TN $taskName /TR "cmd.exe /c `"$radioCmd`"" | Out-Null
        schtasks /Run /TN $taskName | Out-Null
        $usedSystemTask = $true
        Write-Host "[demo] Started mtkradio.exe as SYSTEM (log: $radioLog)" -ForegroundColor Cyan
    } else {
        $radioArgs = @("$Channel", '--width', "$effWidth", '--firmware', $fwDir, '--no-block-ack', '--verbose')
        $radioProc = Start-Process -FilePath $radioExe -ArgumentList $radioArgs -PassThru -NoNewWindow
    }

    # Wait up to 20s for mtkradio firmware boot and pipe creation, printing new log lines live
    Write-Host "[demo] Waiting for $pipe ..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(20)
    $printedLines = 0
    $pipeReady = $false
    while ((Get-Date) -lt $deadline) {
        if ($usedSystemTask -and (Test-Path $radioLog)) {
            $lines = @(Get-Content $radioLog -ErrorAction SilentlyContinue)
            if ($lines.Count -gt $printedLines) {
                $lines[$printedLines..($lines.Count - 1)] | ForEach-Object { Write-Host "[mtkradio] $_" -ForegroundColor DarkCyan }
                $printedLines = $lines.Count
            }
        }
        if ([System.IO.Directory]::GetFiles('\\.\pipe\', 'winawdl-radio').Length -gt 0) {
            $pipeReady = $true
            break
        }
        if ($radioProc -and $radioProc.HasExited) {
            throw "mtkradio.exe exited early with code $($radioProc.ExitCode)"
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $pipeReady) {
        if ($usedSystemTask -and (Test-Path $radioLog)) {
            Write-Host "[demo] mtkradio.exe log:" -ForegroundColor Yellow
            Get-Content $radioLog | ForEach-Object { Write-Host "[mtkradio] $_" -ForegroundColor Yellow }
        }
        throw "Timed out waiting for $pipe (check that MT7922 is bound to winawdl_regproxy)"
    }
    Write-Host "[demo] Pipe $pipe is ready." -ForegroundColor Green
}

# 5. Build owly.exe arguments and run with full logs
if (-not $env:RUST_LOG) { $env:RUST_LOG = 'info' }
# Default to single-MPDU TX under MT7922 firmware RA (zero-loss 5.4 MB/s TX; set OWLY_NO_AMSDU=0 to test A-MSDU).
if (-not $env:OWLY_NO_AMSDU) { $env:OWLY_NO_AMSDU = '1' }
$owlyArgs = @()
switch ($Mode) {
    'radio' {
        $owlyArgs = @('radio', 'up', '--pipe', $pipe, '--channel', "$Channel")
    }
    'receive' {
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        $owlyArgs = @('receive', '--pipe', $pipe, '--channel', "$Channel", '--name', $Name, '--dir', $Dir)
        if (-not $Prompt) { $owlyArgs += '--accept' }
    }
    'browse' {
        $owlyArgs = @('browse', '--pipe', $pipe, '--channel', "$Channel", '--name', $Name, '--seconds', '20')
    }
    'send' {
        if ($Files.Count -eq 0) {
            $defaultPhoto = Join-Path $repo 'tests\photo.png'
            if (Test-Path $defaultPhoto) {
                $Files = @($defaultPhoto)
            } else {
                throw "Specify -Files <path> when using -Mode send"
            }
        }
        $owlyArgs = @('send', '--pipe', $pipe, '--channel', "$Channel", '--name', $Name)
        if ($To) { $owlyArgs += @('--to', $To) }
        $owlyArgs += $Files
    }
}

Write-Host "[demo] Running: $owlyExe $($owlyArgs -join ' ')" -ForegroundColor Green
if ($Direct -and -not $NoSystem) {
    $directLog = Join-Path $repo 'owly-direct.log'
    $directCmd = Join-Path $repo 'run-owly-direct.cmd'
    if (Test-Path $directLog) { Remove-Item $directLog -Force }
    $quotedArgs = ($owlyArgs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    @(
        '@echo off'
        "set `"OWLY_WINTUN_DLL=$wintun`""
        "set `"OWLY_MTKRADIO_DLL=$directDll`""
        "set `"OWLY_MTK_FW_DIR=$directFwDir`""
        "set `"OWLY_NO_AMSDU=$($env:OWLY_NO_AMSDU)`""
        "set `"RUST_LOG=$($env:RUST_LOG)`""
        if ($env:OWLY_BEACON_SCRIPT) { "set `"OWLY_BEACON_SCRIPT=$($env:OWLY_BEACON_SCRIPT)`"" }
        "`"$owlyExe`" $quotedArgs > `"$directLog`" 2>&1"
    ) | Set-Content -Path $directCmd -Encoding ASCII
    schtasks /Create /F /RU SYSTEM /SC ONCE /ST 00:00 /TN $taskName /TR "cmd.exe /c `"$directCmd`"" | Out-Null
    schtasks /Run /TN $taskName | Out-Null
    $usedSystemTask = $true
    Write-Host "[demo] Started single-process owly.exe as SYSTEM (log: $directLog)" -ForegroundColor Cyan
    try {
        # Wait briefly for owly.exe to spawn, then stream its log until it exits.
        $waitSpawn = (Get-Date).AddSeconds(10)
        while (-not (Get-Process -Name owly -ErrorAction SilentlyContinue) -and (Get-Date) -lt $waitSpawn) {
            Start-Sleep -Milliseconds 100
        }
        $printed = 0
        while ($true) {
            if (Test-Path $directLog) {
                $lines = @(Get-Content $directLog -ErrorAction SilentlyContinue)
                if ($lines.Count -gt $printed) {
                    $lines[$printed..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
                    $printed = $lines.Count
                }
            }
            if (-not (Get-Process -Name owly -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Milliseconds 200
        }
        if (Test-Path $directLog) {
            $lines = @(Get-Content $directLog -ErrorAction SilentlyContinue)
            if ($lines.Count -gt $printed) {
                $lines[$printed..($lines.Count - 1)] | ForEach-Object { Write-Host $_ }
            }
        }
    } finally {
        Write-Host "[demo] Stopping SYSTEM owly.exe and cleaning up task '$taskName'..." -ForegroundColor Yellow
        Get-Process -Name owly -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        schtasks /Delete /F /TN $taskName 2>$null | Out-Null
    }
} else {
    try {
        & $owlyExe @owlyArgs
    } finally {
        if ($radioProc -and -not $radioProc.HasExited) {
            Write-Host "[demo] Stopping mtkradio.exe (PID $($radioProc.Id))..." -ForegroundColor Yellow
            Stop-Process -Id $radioProc.Id -Force -ErrorAction SilentlyContinue
        }
        if ($usedSystemTask) {
            Write-Host "[demo] Stopping SYSTEM mtkradio.exe and cleaning up task '$taskName'..." -ForegroundColor Yellow
            Get-Process -Name mtkradio -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            schtasks /Delete /F /TN $taskName 2>$null | Out-Null
        }
    }
}
