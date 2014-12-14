$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"

function getOSVersion(){
    $v = (Get-WmiObject Win32_OperatingSystem).Version.Split('.')

    return New-Object psobject -Property @{
        Major = [int]::Parse($v[0])
        Minor = [int]::Parse($v[1])
        Build = [int]::Parse($v[2])
    }
}

function getVirtioDriversFolder(){
    $architectureMapping = @{}
    $architectureMapping['32-bit']='X86'
    $architectureMapping['64-bit']='AMD64'
    $osVersionMapping = @{}
    $osVersionMapping[0]='VISTA'
    $osVersionMapping[1]='WIN7'
    $osVersionMapping[2]='WIN8'
    $osVersionMapping[3]='WIN8'

    $osArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    $archFolder = $architectureMapping[$osArchitecture]

    $osVersion = getOSVersion
    $versionFolder = $osVersionMapping[$osVersion.Minor]
    if (($osVersion.Major -ne 6) -or !$versionFolder) { throw "Unsupported Windows version" }

    $virtIOPath = Join-Path -Path $versionFolder -ChildPath $archFolder
    $drive = (gwmi Win32_CDROMDrive | where {(Test-Path (join-path -Path $_.Drive -ChildPath $virtIOPath ))}).Drive
    if (! $drive) { throw "VirtIO drivers not found" }

    return join-path -Path $drive -ChildPath $virtIOPath | join-path -ChildPath "*.inf"
}

function installVirtIOTools2012($virtioDriversPath) {
    Write-Host "Installing VirtIO drivers from: $virtioDriversPath"
    & cscript "$resourcesDir\InstallVirtIODrivers.js" $virtioDriversPath
    if (!$?) { throw "InstallVirtIO failed" }
}

function installVirtIOToolsPre2012($virtioDriversPath) {
    $Host.UI.RawUI.WindowTitle = "Installing VirtIO certificate..."
    $cacert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$resourcesDir\VirtIO.cer")
    $castore = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher,`
                     [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $castore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $castore.Add($cacert)

    Write-Host "Installing VirtIO drivers from: $virtioDriversPath"
    Start-process -Wait pnputil "-i -a $virtioDriversPath"
    if (!$?) { throw "InstallVirtIO failed" }

    $castore.Remove($cacert)
}

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
            $virtioDriversPath = getVirtioDriversFolder
            $osVersion = getOSVersion

            if (($osVersion.Major -ge 6) -and ($osVersion.Minor -ge 2)) {
                installVirtIOTools2012 $virtioDriversPath
            }
            else {
                installVirtIOToolsPre2012 $virtioDriversPath
            }

            shutdown /r /t 0
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
