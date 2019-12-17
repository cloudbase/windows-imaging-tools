$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$moduleName = "WinImageBuilder"
$moduleHome = Split-Path -Parent $here
$fakeConfigPath = Join-Path $here "fake-config.ini"
$modulePath = Join-Path $moduleHome "${moduleName}.psm1"

class PathShouldExist : System.Management.Automation.ValidateArgumentsAttribute {
    [void] Validate([object]$arguments, [System.Management.Automation.EngineIntrinsics]$engineIntrinsics) {
    }
}

if (Get-Module $moduleName -ErrorAction SilentlyContinue) {
    Remove-Module $moduleName
}

function Compare-Objects ($first, $last) {
    (Compare-Object $first $last -SyncWindow 0).Length -eq 0
}

function Compare-ScriptBlocks {
    Param(
        [System.Management.Automation.ScriptBlock]$scrBlock1,
        [System.Management.Automation.ScriptBlock]$scrBlock2
    )

    $sb1 = $scrBlock1.ToString()
    $sb2 = $scrBlock2.ToString()

    return ($sb1.CompareTo($sb2) -eq 0)
}

function Add-FakeObjProperty ([ref]$obj, $name, $value) {
    Add-Member -InputObject $obj.value -MemberType NoteProperty `
        -Name $name -Value $value
}

function Add-FakeObjProperties ([ref]$obj, $fakeProperties, $value) {
    foreach ($prop in $fakeProperties) {
        Add-Member -InputObject $obj.value -MemberType NoteProperty `
            -Name $prop -Value $value
    }
}

function Add-FakeObjMethod ([ref]$obj, $name) {
    Add-Member -InputObject $obj.value -MemberType ScriptMethod `
        -Name $name -Value { return 0 }
}

function Add-FakeObjMethods ([ref]$obj, $fakeMethods) {
    foreach ($method in $fakeMethods) {
        Add-Member -InputObject $obj.value -MemberType ScriptMethod `
            -Name $method -Value { return 0 }
    }
}

function Compare-Arrays ($arr1, $arr2) {
    return (((Compare-Object $arr1 $arr2).InputObject).Length -eq 0)
}

function Compare-HashTables ($tab1, $tab2) {
    if ($tab1.Count -ne $tab2.Count) {
        return $false
    }
    foreach ($i in $tab1.Keys) {
        if (($tab2.ContainsKey($i) -eq $false) -or ($tab1[$i] -ne $tab2[$i])) {
            return $false
        }
    }
    return $true
}

function Get-VMSwitch {}

function Optimize-VHD {}

Import-Module $modulePath

Describe "Test New-WindowsCloudImage" {
    Mock Write-Host -Verifiable -ModuleName $moduleName { return 0 }
    Mock Validate-WindowsImageConfig -Verifiable -ModuleName $moduleName { return 0 }
    Mock Set-DotNetCWD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Is-Administrator -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-WimFileImagesInfo -Verifiable -ModuleName $moduleName `
        {
            return @{
                "ImageName"="Windows Server 2012 R2 SERVERSTANDARD"
                "ImageInstallationType"="ImageInstallationType"
                "ImageArchitecture"="ImageArchitecture"
                "ImageIndex"=1
            }
        }
    Mock Check-DismVersionForImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Test-Path -Verifiable -ModuleName $moduleName { return $false }
    Mock Create-ImageVirtualDisk -Verifiable -ModuleName $moduleName `
        {
            return @("C:", "D:")
        }
    Mock Generate-UnattendXml -Verifiable -ModuleName $moduleName { return 0 }
    Mock Copy-UnattendResources -Verifiable -ModuleName $moduleName { return 0 }
    Mock Copy-CustomResources -Verifiable -ModuleName $moduleName { return 0 }
    Mock Copy-Item -Verifiable -ModuleName $moduleName { return 0 }
    Mock Download-CloudbaseInit -Verifiable -ModuleName $moduleName { return 0 }
    Mock Download-ZapFree -Verifiable -ModuleName $moduleName { return 0 }
    Mock Apply-Image -Verifiable -ModuleName $moduleName { return 0 }
    Mock Create-BCDBootConfig -Verifiable -ModuleName $moduleName { return 0 }
    Mock Check-EnablePowerShellInImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Set-WindowsWallpaper -Verifiable -ModuleName $moduleName { return 0 }
    Mock Enable-FeaturesInImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Clean-WindowsUpdates -Verifiable -ModuleName $moduleName { return 0 }
    Mock Optimize-Volume -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-PathWithoutExtension -Verifiable -ModuleName $moduleName { return "test" }
    Mock Compress-Image -Verifiable -ModuleName $moduleName { return 0 }

    It "Should create a windows image" {
        New-WindowsCloudImage -ConfigFilePath $fakeConfigPath | Should -Contain 0
    }

    It "should run all mocked commands" {
        Assert-VerifiableMock
    }
}


Describe "Test Get-WimFileImagesInfo" {

    Mock Get-WimInteropObject -Verifiable -ModuleName $moduleName {
        $imagesMock = New-Object -TypeName PSObject
        Add-Member -InputObject ([ref]$imagesMock).value `
            -MemberType NoteProperty -Name "Images" -Value @{"Win"=1}
        return $imagesMock
    }

    It "Should return fake images" {
        Compare-HashTables (Get-WimFileImagesInfo "FakePath") @{
            "Win"=1
        } | Should Be $true
    }
}

Describe "Test Resize-VHDImage" {
    function Get-VHD { }
    function Mount-VHD { }
    function Resize-VHD { }
    function Dismount-VHD { }
    Mock Write-Host -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-VHD -Verifiable -ModuleName $moduleName { return @{"Size" = 100; "MinimumSize" = 10} }
    Mock Mount-VHD -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "Number" -Value 1 -Force
        return $b
    }
    Mock Get-Disk -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "DiskId" -Value 1 -Force
        return $b
    }
    Mock Get-Partition -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "DriveLetter" -Value "L" -Force
        $b | Add-Member -MemberType NoteProperty -Name "Size" -Value 90 -Force
       return $b
    }
    Mock Get-Volume -Verifiable -ModuleName $moduleName { return @{"DriveLetter" = "F"} }
    Mock Optimize-Volume -Verifiable -ModuleName $moduleName { return }
    Mock Get-PartitionSupportedSize -Verifiable -ModuleName $moduleName { return @{"SizeMin" = 100; "SizeMax" = 1000} }
    Mock Resize-Partition -Verifiable -ModuleName $moduleName { return 0 }
    Mock Resize-VHD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Dismount-VHD -Verifiable -ModuleName $moduleName { return 0 }

    It "Should resize a vhd image" {
        Resize-VHDImage -VirtualDiskPath "fakePath" `
            -FreeSpace 100 | Should -Contain 0
    }

    It "should run all mocked commands" {
        Assert-VerifiableMock
    }
}

Describe "Test Resize-VHDImage with binary search" {
    function Get-VHD { }
    function Mount-VHD { }
    function Resize-VHD { }
    function Dismount-VHD { }
    Mock Write-Host -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-VHD -Verifiable -ModuleName $moduleName { return @{"Size" = 100; "MinimumSize" = 10} }
    Mock Mount-VHD -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "Number" -Value 1 -Force
        return $b
    }
    Mock Get-Disk -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "DiskId" -Value 1 -Force
        return $b
    }
    Mock Get-Partition -Verifiable -ModuleName $moduleName {
        $b = New-Object System.Management.Automation.PSObject
        $b | Add-Member -MemberType NoteProperty -Name "DriveLetter" -Value "L" -Force
        $b | Add-Member -MemberType NoteProperty -Name "Size" -Value 90 -Force
       return $b
    }
    Mock Get-Volume -Verifiable -ModuleName $moduleName { return @{"DriveLetter" = "F"} }
    Mock Optimize-Volume -Verifiable -ModuleName $moduleName { return }
    Mock Get-PartitionSupportedSize -Verifiable -ModuleName $moduleName { return @{"SizeMin" = 10GB; "SizeMax" = 1000GB} }
    Mock Resize-Partition -Verifiable -ModuleName $moduleName { throw "Failure to resize" }
    Mock Resize-VHD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Dismount-VHD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Start-Sleep -Verifiable -ModuleName $moduleName { return }

    It "Should resize a vhd image" {
        Resize-VHDImage -VirtualDiskPath "fakePath" `
            -FreeSpace 100 | Should -Contain 0
    }

    It "should run all mocked commands" {
        Assert-MockCalled -Times 10 -CommandName "Resize-Partition" -ModuleName $moduleName
    }
}


Describe "Test New-WindowsOnlineImage" {
    Mock Write-Host -Verifiable -ModuleName $moduleName { return 0 }
    Mock Is-Administrator -Verifiable -ModuleName $moduleName { return 0 }
    Mock Check-Prerequisites -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-PathWithoutExtension -Verifiable -ModuleName $moduleName { return "fakePath" }
    Mock New-WindowsCloudImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Run-Sysprep -Verifiable -ModuleName $moduleName  { return 0 }
    Mock Resize-VHDImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Convert-VirtualDisk -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-Random -Verifiable -ModuleName $moduleName { return 1 }
    Mock Remove-Item -Verifiable -ModuleName $moduleName { return 0 }
    Mock Compress-Image -Verifiable -ModuleName $moduleName { return 0 }
    Mock Optimize-VHD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-VMSwitch -Verifiable -ModuleName $moduleName { return @{"Name"="external";"SwitchType"="External"} }

    It "Should create an online image" {
        New-WindowsOnlineImage -ConfigFilePath $fakeConfigPath | Should -Contain 0
        Remove-Item -Force -ErrorAction SilentlyContinue "${fakeConfigPath}.offline"
    }

    It "should run all mocked commands" {
        Assert-VerifiableMock
    }
}
