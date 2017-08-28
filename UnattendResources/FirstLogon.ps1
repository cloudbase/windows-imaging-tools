$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"

function getHypervisor() {
    $hypervisor = & "$resourcesDir\checkhypervisor.exe"

    if ($LastExitCode -eq 1) {
        Write-Host "No hypervisor detected."
    } else {
        return $hypervisor
    }
}

function installVMwareTools() {
    $Host.UI.RawUI.WindowTitle = "Installing VMware tools..."
    $vmwareToolsInstallArgs = "/s /v /qn REBOOT=R /l $ENV:Temp\vmware_tools_install.log"
    $vmwareToolsPath = Join-Path $resourcesDir "VMware-tools.exe"
    Start-Process -FilePath $vmwareToolsPath -ArgumentList $vmwareToolsInstallArgs -wait
    if (!$?) { throw "VMware tools setup failed" }
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
            installVMwareTools
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
