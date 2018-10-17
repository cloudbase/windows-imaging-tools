param (
    [parameter(Mandatory=$true)]
    [String]$Image,
    [parameter(Mandatory=$true)]
    [String]$ConfigFile
)

$ErrorActionPreference = "Stop"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$resourcesDir = "$scriptPath\UnattendResources"

function Get-ImageType {
    <#
    .SYNOPSIS
    Gets the image type from the config file
    #>
    param($ConfigFile)

    Import-Module "$resourcesDir\ini.psm1"
    $type = Get-IniFileValue -Path $ConfigFile -Section "DEFAULT" -Key "image_type"
    return $type
}

function Extract-File {
    <#
    .SYNOPSIS
    Extracts a tar or tgz file and returns the path to the extracted file
    #>
    param($File)

    $imageFilePath = Split-Path -Path $File
    $imageFilePath = Join-Path -Path $imageFilePath -ChildPath "extracted"

    Write-Host "Image is being extracted to $imageFilePath"
    & 7z.exe e $File "-o$imageFilePath" | Out-Null
    if ($LastExitCode -ne 0) {
        Write-Host "Something went wrong while extracting"
        exit
    }
    $tarPath = Join-Path -Path $imageFilePath -ChildPath "*.tar"
    $img = Get-ChildItem $tarPath
    & 7z.exe x -aoa -ttar $img "-o$imageFilePath" | Out-Null
    if ($LastExitCode -eq 0) {
        Write-Host "Done extracting"
    } else {
        Write-Host "Something went wrong while extracting"
        exit
    }
    Remove-Item $tarPath -ErrorAction $ErrorActionPreference
    $imageFilePath = Join-Path -Path $imageFilePath -ChildPath "*.*"
    $imgExtracted = Get-ChildItem $imageFilePath
    return $imgExtracted
}

function Get-VHDXImage {
    <#
    .SYNOPSIS
    Converts and mounts the given Image
    .DESCRIPTION
    The given image is converted with qemu to a vhdx format
    that will be mounted later. After that it returns the vhdx image
    and it also returns the mounting point for futher checks
    .PARAMETER Image
    The image that must be converted
    .PARAMETER Extension
    The format of the image from which it will be converted to a vhdx
    #>
    param($Image, $Extension)

    [String]$qemuPath = "$scriptPath\bin\qemu-img.exe"
    $converted = $Image.split(".")[0]
    $converted = -join ($converted, ".vhdx")
    Write-Host "Converting $Image to $converted..."
    & $qemuPath convert -f $Extension -O vhdx $Image $converted
    if ($LastExitCode -ne 0) {
        Write-Host "Error while converting"
        exit
    }
    Write-Host "Mounting $converted..."
    $volume = (Mount-VHD -Path $converted -Passthru | Get-Disk | Get-Partition | Get-Volume).DriveLetter
    $volume = -join ($volume, ":\")
    if (Test-Path $volume) {
        Write-Host "Mounting point: $volume"
    } else {
        Write-Host "Something wrong with the path of the mounting point"
        exit
    }
    return $converted, $volume
}

function Check-ImageFormat {
    <#
    .SYNOPSIS
    Checks the format of an image for the given type
    .DESCRIPTION
    This function checks the format of an image to see if it corresponds to the given type,
    by looking at its extension. After this, based on the type it proceeds
    with further checks, for MAAS checking that the image has curtin,
    for KVM looking for VirtIO drivers
    .PARAMETER Type
    The image type, it will be taken from the config file
    .PARAMETER Image
    The image that will be checked
    #>
    param($Type, $Image)

    $extension = [IO.Path]::GetExtension($Image)
    $extension = $extension.split(".")[1]

    if ($Type -eq "Hyper-V") {
        if ($extension -eq "VHDX" -Or $extension -eq "VHD") {
            Write-Host "OK"
        } else {
            throw "Wrong format for Hyper-V"
        }
    } elseif ($Type -eq "MAAS") {
        if ($extension -eq "raw") {
            $convertedMounted = Get-VHDXImage $Image $extension
            Write-Host "Checking for curtin..."
            $curtin = Get-ChildItem $convertedMounted[1] | Select-String -Quiet "curtin"
            if ($curtin) {
                Write-Host "OK"
            } else {
                Write-Host "$Image doesn't have curtin"
            }
            Dismount-VHD $convertedMounted[0]
            Remove-Item $convertedMounted[0] -ErrorAction $ErrorActionPreference
        } else {
            throw "Wrong format for MAAS"
        }
    } elseif ($Type -eq "KVM") {
        if ($extension -eq "raw" -Or $extension -eq "qcow2") {
            $convertedMounted = Get-VHDXImage $Image $extension
            Write-Host "Checking for VirtIO..."
            $virtio = Get-ChildItem -Recurse -Force $convertedMounted[1] -ErrorAction SilentlyContinue `
                        | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "vio*") }
            if ($virtio) {
                Write-Host "OK"
            } else {
                Write-Host "$Image doesn't have VirtIO"
            }
            Dismount-VHD $convertedMounted[0]
            Remove-Item $convertedMounted[0] -ErrorAction $ErrorActionPreference
        } else {
            throw "Wrong format for KVM"
        }
    } else {
        throw "Wrong type"
    }
}

function Validate-Image {
    <#
    .SYNOPSIS
    Checks what type of file was given and after that checks its format
    .DESCRIPTION
    At first checks to see if the given file must be extracted or not,
    after that it proceeds with checking its format and
    in the end it deletes the extracted file if it's the case
    #>
    param (
    [String]$Image,
    [String]$ConfigFile
    )

    $extension=[IO.Path]::GetExtension($Image)
    $extension=$extension.split(".")[1]
    if ($extension -eq "tgz" -or $extension -eq "gz" -or $extension -eq "tar") {
        $Image = Extract-File $Image
        $imgExtracted = $Image
    }
    $type = Get-ImageType $ConfigFile
    try {
        Check-ImageFormat $type $Image
    } catch {
            Write-Host $_
    }
    if ($imgExtracted) {
        Write-Host "Deleting $imgExtracted..."
        $imageFilePath = Split-Path -Path $imgExtracted
        Remove-Item -Recurse $imageFilePath -ErrorAction $ErrorActionPreference
    }
}

Validate-Image $Image $ConfigFile
