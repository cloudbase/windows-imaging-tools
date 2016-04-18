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