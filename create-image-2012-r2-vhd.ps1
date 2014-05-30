$ErrorActionPreference = "Stop"

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

$vmname = "OpenStack WS 2012 R2 Standard Evaluation"

# Set the extension to VHD instead of VHDX only if you plan to deploy
# this image on Grizzly or on Windows / Hyper-V Server 2008 R2
$vhdpath = "C:\VM\windows-server-2012-r2.vhdx"

$isoPath = "C:\ISO\9600.16384.WINBLUE_RTM.130821-1623_X64FRE_SERVER_EVAL_EN-US-IRM_SSS_X64FREE_EN-US_DV5.ISO"
$floppyPath = "$scriptPath\Autounattend.vfd"

# Set the vswitch accordingly with your configuration
$vmSwitch = "external"

$vm = Get-VM | where { $_.Name -eq $vmname }
if ($vm) {
    if ($vm.State -eq "Running") {
        $vm | Stop-VM -Force
    }
    $vm | Remove-VM -Force
}

if (Test-Path $vhdpath) {
    del -Force $vhdpath
}

New-VHD $vhdpath -Dynamic -SizeBytes (16 * 1024 * 1024 * 1024)
$vm = New-VM $vmname -MemoryStartupBytes (2048 * 1024 *1024)
$vm | Set-VM -ProcessorCount 2
$vm.NetworkAdapters | Connect-VMNetworkAdapter -SwitchName $vmSwitch
$vm | Add-VMHardDiskDrive -ControllerType IDE -Path $vhdpath
$vm | Add-VMDvdDrive -Path $isopath
$vm | Set-VMFloppyDiskDrive -Path $floppyPath

$vm | Start-Vm