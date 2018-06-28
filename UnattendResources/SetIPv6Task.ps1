
function Set-Task {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\SetIPv6.ps1`""
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType S4U
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SetIPv6" -Principal $principal
}

Set-Task