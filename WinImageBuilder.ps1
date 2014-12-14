$ErrorActionPreference = "Stop"
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

. "$scriptPath\Interop.ps1"

function CheckIsAdmin()
{
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = $prp.IsInRole($adm)
    if(!$isAdmin)
    {
        throw "This cmdlet must be executed in an elevated administrative shell"
    }
}

function Get-WimFileImagesInfo
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim"
    )
    PROCESS
    {
        $w = new-object WIMInterop.WimFile -ArgumentList $WimFilePath
        return $w.Images
    }
}

function CreateImageVirtualDisk($vhdPath, $size)
{
<#
$VHDXFile = $vhdPath
$v = New-VHD -Path $VHDXFile -Dynamic -SizeBytes $size -Verbose
$z = Mount-DiskImage -ImagePath $VHDXFile -Verbose
$VHDXDisk = Get-DiskImage -ImagePath $VHDXFile | Get-Disk -Verbose
$VHDXDiskNumber = [string]$VHDXDisk.Number
Initialize-Disk -Number $VHDXDiskNumber -PartitionStyle MBR -Verbose
$VHDXDrive = New-Partition -DiskNumber $VHDXDiskNumber -UseMaximumSize -IsActive -Verbose
$k = $VHDXDrive | Format-Volume -FileSystem NTFS -NewFileSystemLabel OSDisk -Confirm:$false -Verbose
$a = Add-PartitionAccessPath -DiskNumber $VHDXDiskNumber -PartitionNumber $VHDXDrive.PartitionNumber -AssignDriveLetter
$VHDXDrive = Get-Partition -DiskNumber $VHDXDiskNumber -PartitionNumber $VHDXDrive.PartitionNumber

return $VHDXDrive.DriveLetter
#>


    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($vhdPath, $size)
    try
    {
        $v.AttachVirtualDisk()
        $path = $v.GetVirtualDiskPhysicalPath()

        $m = $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)"
        $diskNum = $matches["num"]

        Initialize-Disk -Number $diskNum -PartitionStyle MBR
        $part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter -IsActive
        $driveLetter = $part.DriveLetter
        $format = Format-Volume -DriveLetter $driveLetter -FileSystem NTFS -NewFileSystemLabel $volumeLabel -Force -Confirm:$false
        return $driveLetter
    }
    finally
    {
        $v.Close()
    }
}

function ApplyImage($driveLetter, $wimFilePath, $imageIndex)
{
    #Expand-WindowsImage -ImagePath $wimFilePath -Index $imageIndex -ApplyPath ${driveLetter}:\
    write-warning "Dism /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${driveLetter}:\"

    & Dism /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${driveLetter}:\
    if($LASTEXITCODE) { throw "Dism apply-image failed" }
}

function CreateBCDBootConfig($driveLetter)
{
    $bcdbootPath = "${driveLetter}:\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath))
    {
        Write-Warning '"$bcdbootPath" not found'
        $bcdbootPath = "bcdboot.exe"
    }

    & $bcdbootPath ${driveLetter}:\windows /s ${driveLetter}: /v
    if($LASTEXITCODE) { throw "BCDBoot failed" }

    & ${driveLetter}:\Windows\System32\bcdedit.exe /store ${driveLetter}:\boot\BCD
    if($LASTEXITCODE) { throw "BCDEdit failed" }
}

function TransformXml($xsltPath, $inXmlPath, $outXmlPath, $args)
{
    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform($false)
    $xsltSettings = New-Object System.Xml.Xsl.XsltSettings($false, $true)
    $xslt.Load($xsltPath, $xsltSettings, (New-Object System.Xml.XmlUrlResolver))
    $outXmlFile = New-Object System.IO.FileStream($outXmlPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $argList = new-object System.Xml.Xsl.XsltArgumentList

    foreach($k in $args.Keys)
    {
        $argList.AddParam($k, "", $args[$k])
    }

    $xslt.Transform($inXmlPath, $argList, $outXmlFile)
}

function ApplyUnattendXml($inUnattendXmlPath, $outUnattendXmlPath, $image, $productKey, $administratorPassword)
{
    $args = @{}
    $args["processorArchitecture"] = $image.ImageArchitecture.ToLow
    $args["imageName"] = $image.ImageName
    $args["versionMajor"] = $image.ImageVersion.Major
    $args["versionMinor"] = $image.ImageVersion.Minor
    $args["installationType"] = $image.ImageInstallationType
    $args["administratorPassword"] = $administratorPassword

    if($productKey) {
        $args["productKey"] =$productKey
    }

    TransformXml "$scriptPath\Unattend.xslt" $inUnattendXmlPath $outUnattendXmlPath $args
}

function DetachVirtualDisk($vhdPath)
{
    try
    {
        $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($vhdPath)
        $v.DetachVirtualDisk()
    }
    finally
    {
        $v.Close()
    }
}

function GetDismVersion()
{
    return new-Object System.Version (gcm dism.exe).FileVersionInfo.ProductVersion
}

function CheckDismVersionForImage($image)
{
    $dismVersion = GetDismVersion
    if ($image.ImageVersion.CompareTo($dismVersion) -gt 0)
    {
        Write-Warning "The installed version of DISM is older than the Windows image"
    }
}

function ConvertVirtualDisk($vhdPath, $outPath, $format)
{
    Write-Output "Converting virtual disk image from $vhdPath to $outPath..."
    & $scriptPath\bin\qemu-img.exe convert -O $format.ToLower() $vhdPath $outPath
    if($LASTEXITCODE) { throw "qemu-img failed to convert the virtual disk" }
}

function New-WindowsCloudImage()
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$WimFilePath = "D:\Sources\install.wim",
        [parameter(Mandatory=$true)]
        [string]$ImageName,
        [parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [parameter(Mandatory=$true)]
        [Uint64]$SizeBytes,
        [parameter(Mandatory=$false)]
        [string]$ProductKey,
        [parameter(Mandatory=$false)]
        [ValidateSet("VHD", "QCow2", "VMDK", "RAW", ignorecase=$false)]
        [string]$VirtualDiskFormat = "VHD",
        [parameter(Mandatory=$false)]
        [string]$AdministratorPassword = "Pa`$`$w0rd",
        [parameter(Mandatory=$false)]
        [string]$UnattendXmlPath = "$scriptPath\Autounattend.xml"
    )
    PROCESS
    {
        CheckIsAdmin

        $image = Get-WimFileImagesInfo -WimFilePath $wimFilePath | where {$_.ImageName -eq $ImageName }
        if(!$image) { throw 'Image "$ImageName" not found in WIM file "$WimFilePath"'}
        CheckDismVersionForImage $image

        if (Test-Path $VirtualDiskPath) { Remove-Item -Force $VirtualDiskPath }

        if ($VirtualDiskFormat -in @("VHD", "VHDX"))
        {
            $VHDPath = $VirtualDiskPath
        }
        else
        {
            $VHDPath = "{0}.vhd" -f [System.IO.Path]::GetFileNameWithoutExtension($VirtualDiskPath)
            if (Test-Path $VHDPath) { Remove-Item -Force $VHDPath }
        }

        try
        {
            $driveLetter = CreateImageVirtualDisk $VHDPath $SizeBytes
            ApplyImage $driveLetter $wimFilePath $image.ImageIndex
            CreateBCDBootConfig $driveLetter
            ApplyUnattendXml $UnattendXmlPath ${driveLetter}:\Unattend.xml $image $ProductKey $AdministratorPassword
        }
        finally
        {
            if (Test-Path $VHDPath)
            {
                DetachVirtualDisk $VHDPath
            }
        }

        if ($VHDPath -ne $VirtualDiskPath)
        {
            ConvertVirtualDisk $VHDPath $VirtualDiskPath $VirtualDiskFormat
            del -Force $VHDPath
        }
    }
}
