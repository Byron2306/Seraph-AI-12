@echo off
REM ============================================================================
REM  SERAPH AI UNIFIED AGENT  -  Windows Installer
REM  Bootstraps PowerShell, auto-elevates, then runs the full install routine.
REM
REM  Usage:
REM    Double-click  OR  run from an Administrator command prompt:
REM      install_seraph_windows.bat
REM    To target a custom server:
REM      install_seraph_windows.bat --server http://165.22.41.184:8001
REM
REM  What this script does:
REM    1. Requests Administrator privileges (UAC prompt)
REM    2. Verifies / installs Python 3 silently if missing
REM    3. Downloads the Unified Agent package from the Seraph server
REM    4. Installs Python dependencies in a private venv
REM    5. Registers a Windows Scheduled Task to run the agent at system startup
REM    6. Starts the agent immediately
REM
REM  Requires: Windows 10 / Server 2016 or later, internet access to server
REM ============================================================================

setlocal enabledelayedexpansion

REM ── Capture command-line arguments ──────────────────────────────────────────
set "SERAPH_SERVER=http://165.22.41.184:8001"

:parse
if "%~1"=="" goto :endparse
if /i "%~1"=="--server" (
    set "SERAPH_SERVER=%~2"
    shift & shift & goto :parse
)
shift
goto :parse
:endparse

REM ── Auto-elevate to Administrator via PowerShell ─────────────────────────────
>nul 2>&1 net session
if %errorlevel% neq 0 (
    echo [INFO] Requesting Administrator privileges...
    powershell -NoProfile -Command ^
        "Start-Process -FilePath '%~f0' -ArgumentList '--server','%SERAPH_SERVER%' -Verb RunAs -Wait"
    exit /b %errorlevel%
)

REM ── Hand off to embedded PowerShell installer ────────────────────────────────
echo.
echo  ============================================================
echo   SERAPH AI UNIFIED AGENT  -  Windows Installer
echo  ============================================================
echo.
echo  Server : %SERAPH_SERVER%
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"& { ^
$ErrorActionPreference = 'Stop'; ^
$ProgressPreference = 'SilentlyContinue'; ^
$SERAPH_SERVER  = '%SERAPH_SERVER%'; ^
$INSTALL_DIR    = 'C:\ProgramData\SeraphAgent'; ^
$VENV_DIR       = Join-Path $INSTALL_DIR 'venv'; ^
$ZIP_PATH       = Join-Path $INSTALL_DIR 'agent.zip'; ^
$LOG_PATH       = Join-Path $INSTALL_DIR 'install.log'; ^
$TASK_NAME      = 'SeraphUnifiedAgent'; ^
$MIN_PY_MAJOR   = 3; ^
$MIN_PY_MINOR   = 9; ^
^
function Write-Step { param([string]$Msg) Write-Host \"[STEP] $Msg\" -ForegroundColor Cyan }; ^
function Write-OK   { param([string]$Msg) Write-Host \"  [OK] $Msg\" -ForegroundColor Green }; ^
function Write-Warn { param([string]$Msg) Write-Host \"  [WARN] $Msg\" -ForegroundColor Yellow }; ^
function Write-Fail { param([string]$Msg) Write-Host \"  [FAIL] $Msg\" -ForegroundColor Red }; ^
^
try { ^
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null; ^
    Start-Transcript -Path $LOG_PATH -Append | Out-Null; ^
    ^
    Write-Step 'Checking Python installation...'; ^
    $pyCmd = $null; ^
    foreach ($candidate in @('py','python3','python')) { ^
        try { ^
            $ver = (& $candidate --version 2>^&1); ^
            if ($ver -match '(\d+)\.(\d+)') { ^
                $maj = [int]$Matches[1]; $min = [int]$Matches[2]; ^
                if ($maj -ge $MIN_PY_MAJOR -and ($maj -gt $MIN_PY_MAJOR -or $min -ge $MIN_PY_MINOR)) { ^
                    $pyCmd = $candidate; Write-OK \"Found Python: $ver\"; break ^
                } ^
            } ^
        } catch {} ^
    }; ^
    if (-not $pyCmd) { ^
        Write-Warn 'Python 3.9+ not found - attempting silent install via winget...'; ^
        try { ^
            winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements 2>^&1 | Out-Null; ^
            $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('PATH','User'); ^
            $pyCmd = 'python'; ^
            Write-OK 'Python installed via winget' ^
        } catch { ^
            Write-Warn 'winget install failed - downloading Python installer...'; ^
            $pyInstaller = Join-Path $env:TEMP 'python-installer.exe'; ^
            Invoke-WebRequest -UseBasicParsing 'https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe' -OutFile $pyInstaller; ^
            Start-Process -FilePath $pyInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0' -Wait; ^
            Remove-Item $pyInstaller -Force -ErrorAction SilentlyContinue; ^
            $env:PATH = [System.Environment]::GetEnvironmentVariable('PATH','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('PATH','User'); ^
            $pyCmd = 'python'; ^
            Write-OK 'Python installed from python.org' ^
        } ^
    }; ^
    ^
    Write-Step 'Downloading unified agent package from server...'; ^
    Invoke-WebRequest -UseBasicParsing -Uri \"$SERAPH_SERVER/api/unified/agent/download/windows\" -OutFile $ZIP_PATH; ^
    Write-OK \"Downloaded agent package\"; ^
    ^
    Write-Step 'Extracting agent package...'; ^
    Expand-Archive -Path $ZIP_PATH -DestinationPath $INSTALL_DIR -Force; ^
    Remove-Item $ZIP_PATH -Force -ErrorAction SilentlyContinue; ^
    Write-OK 'Extracted'; ^
    ^
    Write-Step 'Creating Python virtual environment...'; ^
    & $pyCmd -m venv $VENV_DIR; ^
    $pipExe = Join-Path $VENV_DIR 'Scripts\pip.exe'; ^
    $pyExe  = Join-Path $VENV_DIR 'Scripts\python.exe'; ^
    Write-OK 'Virtual environment ready'; ^
    ^
    Write-Step 'Installing dependencies...'; ^
    & $pipExe install --quiet --upgrade pip | Out-Null; ^
    if (Test-Path (Join-Path $INSTALL_DIR 'requirements.txt')) { ^
        & $pipExe install --quiet -r (Join-Path $INSTALL_DIR 'requirements.txt') | Out-Null ^
    } else { ^
        & $pipExe install --quiet psutil requests netifaces watchdog pyyaml aiohttp | Out-Null ^
    }; ^
    Write-OK 'Dependencies installed'; ^
    ^
    Write-Step 'Creating startup script...'; ^
    $startScript = Join-Path $INSTALL_DIR 'start_agent.ps1'; ^
    @\"
\$env:SERAPH_SERVER = '$SERAPH_SERVER'
Set-Location '$INSTALL_DIR'
& '$pyExe' core/agent.py --server \$env:SERAPH_SERVER --ui-port 5000
\"@ | Set-Content -Path $startScript -Encoding UTF8; ^
    Write-OK \"Startup script: $startScript\"; ^
    ^
    Write-Step 'Registering scheduled task for auto-start...'; ^
    \$action    = New-ScheduledTaskAction -Execute \$pyExe -Argument "core\\agent.py --server $SERAPH_SERVER --ui-port 5000" -WorkingDirectory \$INSTALL_DIR; ^
    \$trigger   = New-ScheduledTaskTrigger -AtStartup; ^
    \$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; ^
    \$settings  = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0; ^
    if (Get-ScheduledTask -TaskName \$TASK_NAME -ErrorAction SilentlyContinue) { ^
        Unregister-ScheduledTask -TaskName \$TASK_NAME -Confirm:\$false | Out-Null ^
    }; ^
    Register-ScheduledTask -TaskName \$TASK_NAME -Action \$action -Trigger \$trigger -Principal \$principal -Settings \$settings -Description 'Seraph AI Unified Security Agent' -Force | Out-Null; ^
    Write-OK 'Scheduled task registered'; ^
    ^
    Write-Step 'Starting agent...'; ^
    Start-ScheduledTask -TaskName \$TASK_NAME; ^
    Write-OK 'Agent started'; ^
    ^
    try { Stop-Transcript | Out-Null } catch {}; ^
    ^
    Write-Host ''; ^
    Write-Host '  ============================================================' -ForegroundColor Green; ^
    Write-Host '   INSTALLATION COMPLETE' -ForegroundColor Green; ^
    Write-Host '  ============================================================' -ForegroundColor Green; ^
    Write-Host ''; ^
    Write-Host \"  Install dir : $INSTALL_DIR\" -ForegroundColor White; ^
    Write-Host \"  Server      : $SERAPH_SERVER\" -ForegroundColor White; ^
    Write-Host \"  Local UI    : http://localhost:5000\" -ForegroundColor Cyan; ^
    Write-Host \"  Task name   : $TASK_NAME\" -ForegroundColor White; ^
    Write-Host \"  Log file    : $LOG_PATH\" -ForegroundColor White; ^
    Write-Host ''; ^
    Write-Host '  Verify task : Get-ScheduledTask -TaskName SeraphUnifiedAgent' -ForegroundColor Gray; ^
    Write-Host '  View logs   : Get-Content C:\ProgramData\SeraphAgent\install.log' -ForegroundColor Gray; ^
    Write-Host '' ^
} catch { ^
    try { Stop-Transcript | Out-Null } catch {}; ^
    Write-Host ''; ^
    Write-Host '  ============================================================' -ForegroundColor Red; ^
    Write-Host \"  INSTALLATION FAILED: $($_.Exception.Message)\" -ForegroundColor Red; ^
    Write-Host '  ============================================================' -ForegroundColor Red; ^
    Write-Host ''; ^
    Write-Host \"  Log file: $LOG_PATH\" -ForegroundColor Yellow; ^
    Write-Host '  Please check the log file and re-run this installer.' -ForegroundColor Yellow; ^
    Write-Host '' ^
} ^
}"

echo.
pause
exit /b 0
