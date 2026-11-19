# Windows scheduled task: starts TR4P when you log on, as you (no administrator needed).
# Run in a normal PowerShell window:   powershell -ExecutionPolicy Bypass -File packaging\tr4p-task.ps1
# Remove with:                         Unregister-ScheduledTask -TaskName TR4P -Confirm:$false
$python = (Get-Command python -ErrorAction Stop).Source
$action = New-ScheduledTaskAction -Execute $python -Argument "-m tr4p run"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName TR4P -Action $action -Trigger $trigger -Settings $settings `
    -Description "TR4P deception layer" | Out-Null
Write-Host "Registered. Start it now with: Start-ScheduledTask -TaskName TR4P"
