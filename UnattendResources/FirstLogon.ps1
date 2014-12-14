$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"

function getHypervisor() {
    $hypervisor = & "$resourcesDir\checkhypervisor.exe"

    if ($LastExitCode -eq 1) {
        Write-Host "No hypervisor detected."
    } else {
        return $hypervisor
    }
}

try
{
    $hypervisorStr = getHypervisor
    Write-Host "Hypervisor: $hypervisorStr"
    # TODO: Add XenServer / XCP
    switch($hypervisorStr)
    {
        "VMwareVMware"
        {
            # Note: this command will generate a reboot.
            # "/qn REBOOT=ReallySuppress" does not seem to work properly
            $Host.UI.RawUI.WindowTitle = "Installing VMware tools..."
            E:\setup64.exe `/s `/v `/qn `/l `"$ENV:Temp\vmware_tools_install.log`"
            if (!$?) { throw "VMware tools setup failed" }
        }
        "KVMKVMKVM"
        {
            # Nothing to do as VirtIO drivers have already been provisioned
        }
        "Microsoft Hv"
        {
            # Nothing to do
        }
    }
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    # Prevents the setup from proceeding

    $logonScriptPath = "$resourcesDir\Logon.ps1"
    if ( Test-Path $logonScriptPath ) { del $logonScriptPath }
    throw
}
