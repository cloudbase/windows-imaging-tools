Param()

#ps1
set-psdebug -trace 2

pushd "C:\Users\avlad\work\windows-openstack-imaging-tools - Copy" 
try {



    if (Get-module WinImageBuilder -erroraction silentlycontinue) {
    remove-module WinImageBuilder
    }
    Import-Module .\WinImageBuilder.psm1

    # The disk format can be: VHD, VHDX, QCow2, VMDK or RAW
    $virtualDiskPath = "F:\Images\win2008r2-61-z.vhdx"
    # This is the content of your Windows ISO
    $wimFilePath = "T:\sources\install.wim"
    # Optionally, if you target KVM
    $virtIOISOPath = "D:\ISO\windows\virtio-win-0.1.102.iso"

    # Check what images are supported in this Windows ISO
    $images = Get-WimFileImagesInfo -WimFilePath $wimFilePath
    # Select the first one
    $image = $images[0]
    $images
    #exit
    New-WindowsOnlineImage -WimFilePath $wimFilePath -ImageName $image.ImageName `
        -WindowsImagePath $virtualDiskPath `
        -memory 4GB -Force -switchname external -cpucores 4 `
        -SizeBytes 36GB -ExtraFeatures @() -installUpdates:$false `
        -virtIOISOPath $virtIOISOPath `
        -purgeupdates:$true -disableswap:$true -disklayout "BIOS" `
        -Type HYPER-V
        
} catch {
    Write-Host $_
}
finally {
    popd
}
