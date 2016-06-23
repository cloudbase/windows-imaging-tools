$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$moduleName = "WinImageBuilder"
$moduleHome = Split-Path -Parent $here

echo $moduleHome
$modulePath = Join-Path $moduleHome "${moduleName}.psm1"

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

Import-Module $modulePath

Describe "Test Get-WimFileImagesInfo" {

    Mock Get-WimInteropObject -Verifiable -ModuleName $moduleName `
        {
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

Describe "Test New-WindowsCloudImage" {
    Mock Set-DotNetCWD -Verifiable -ModuleName $moduleName { return 0 }
    Mock Is-Administrator -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-WimFileImagesInfo -Verifiable -ModuleName $moduleName `
        {
            return @{
                "ImageName"="fakeImageName"
                "ImageInstallationType"="ImageInstallationType"
                "ImageArchitecture"="ImageArchitecture"
                "ImageIndex"=1
            }
        }
    Mock Check-DismVersionForImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Test-Path -Verifiable -ModuleName $moduleName { return $false }
    Mock Create-ImageVirtualDisk -Verifiable -ModuleName $moduleName `
        {
            return @("drive1")
        }
    Mock Generate-UnattendXml -Verifiable -ModuleName $moduleName { return 0 }
    Mock Copy-UnattendResources -Verifiable -ModuleName $moduleName { return 0 }
    Mock Generate-ConfigFile -Verifiable -ModuleName $moduleName { return 0 }
    Mock Download-CloudbaseInit -Verifiable -ModuleName $moduleName { return 0 }
    Mock Apply-Image -Verifiable -ModuleName $moduleName { return 0 }
    Mock Create-BCDBootConfig -Verifiable -ModuleName $moduleName { return 0 }
    Mock Check-EnablePowerShellInImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Enable-FeaturesInImage -Verifiable -ModuleName $moduleName { return 0 }

    It "Should create a windows image" {
        New-WindowsCloudImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -ExtraFeatures @("Windows-Hyper-V") `
                    -SizeBytes 1 -VirtualDiskPath "fakeVirtualDiskPath" | Should Be 0
    }

    It "Should accept valid product key" {
        New-WindowsCloudImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -ProductKey "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" `
                    -SizeBytes 1 -VirtualDiskPath "fakeVirtualDiskPath" | Should Be 0
    }

    It "Should throw on invalid product key" {
        { New-WindowsCloudImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -ProductKey "foo" `
                    -SizeBytes 1 -VirtualDiskPath "fakeVirtualDiskPath" } | Should Throw
    }

    It "should run all mocked commands" {
        Assert-VerifiableMocks
    }
}

Describe "Test New-MaaSImage" {
    Mock Is-Administrator -Verifiable -ModuleName $moduleName { return 0 }
    Mock Check-Prerequisites -Verifiable -ModuleName $moduleName { return 0 }
    Mock GetOrCreate-Switch -Verifiable -ModuleName $moduleName `
        {
            return @{
                "Name" = "fakeswitch"
            }
        }
    Mock Get-PathWithoutExtension -Verifiable -ModuleName $moduleName { return "fakePath" }
    Mock New-WindowsCloudImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Run-Sysprep -Verifiable -ModuleName $moduleName  { return 0 }
    Mock Resize-VHDImage -Verifiable -ModuleName $moduleName { return 0 }
    Mock Convert-VirtualDisk -Verifiable -ModuleName $moduleName { return 0 }
    Mock Get-Random -Verifiable -ModuleName $moduleName { return 1 }
    Mock Remove-Item -Verifiable -ModuleName $moduleName { return 0 }
    Mock Compress-Image -Verifiable -ModuleName $moduleName { return 0 }

    It "Should create a maas image" {
        New-MaaSImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -SizeBytes 1 -MaaSImagePath "fakeMAASPath" | Should Be 0


                    }

    It "Should accept valid product key" {
        New-MaaSImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -ProductKey "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx" `
                    -SizeBytes 1 -MaaSImagePath "fakeMAASPath" | Should Be 0
    }

    It "Should throw on invalid product key" {
        { New-MaaSImage -Wimfilepath "fakeWimFilepath" `
                    -ImageName "fakeImageName" `
                    -ProductKey "foo" `
                    -SizeBytes 1 -MaaSImagePath "fakeMAASPath" } | Should Throw
    }

    It "should run all mocked commands" {
        Assert-VerifiableMocks
    }
}