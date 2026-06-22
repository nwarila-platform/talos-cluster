@echo off
setlocal EnableExtensions

set "TASK_NAME=WSL-NFS-Backup-Server"

net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo Requesting elevated privileges to register %TASK_NAME%...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$content = Get-Content -Raw -LiteralPath '%~f0'; $script = ($content -split '(?m)^:PowerShellScript\r?$', 2)[1]; Invoke-Expression $script"
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
    echo FAILED: Scheduled task registration failed with exit code %RC%.
    pause
    exit /b %RC%
)

echo SUCCESS: Scheduled task %TASK_NAME% registered.
pause
exit /b 0

:PowerShellScript
$ErrorActionPreference = 'Stop'

$taskName = 'WSL-NFS-Backup-Server'
$distro = 'Ubuntu-24.04'
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$wslExe = Join-Path $env:WINDIR 'System32\wsl.exe'

$nfsStart = @"
if [ -x /usr/local/sbin/nwarila-nfs-interim-start ]; then /usr/local/sbin/nwarila-nfs-interim-start; else mkdir -p /proc/fs/nfsd /run/rpcbind /srv/nfs/backup; chmod 1777 /srv/nfs/backup; printf '%s\n' '/srv/nfs/backup 10.69.112.0/24(rw,async,no_subtree_check,no_root_squash)' > /etc/exports; mountpoint -q /proc/fs/nfsd || mount -t nfsd nfsd /proc/fs/nfsd; pgrep -x rpcbind >/dev/null 2>&1 || rpcbind -w; exportfs -ra; rpc.nfsd 8; pgrep -x rpc.mountd >/dev/null 2>&1 || rpc.mountd; fi; exec sleep infinity
"@
$nfsStart = ($nfsStart -replace '\r?\n', ' ').Trim()
$arguments = '-d {0} -u root -- bash -lc "{1}"' -f $distro, $nfsStart

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute $wslExe -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description 'Pins Ubuntu-24.04 WSL and starts the interim DR Stage 1 NFS backup server at owner logon.' `
    | Out-Null

Write-Host "Task: $taskName"
Write-Host "User: $user"
Write-Host "Trigger: AtLogon"
Write-Host "Action: $wslExe $arguments"
Write-Host "Settings: highest privileges, no execution time limit, restart every 1 minute on failure, do not stop on idle end."