# How a Windows image is created (step by step)

## New-WindowsCloudImage

The steps to create an image that has to be instantiated on a hypervisor before use:

  1. Validate that the image configuration is correct:
      * compression_format needs to be supported
  2. Validate host requirements:
      * DISM version
      * Running as administrator
      * Image exists in the WIM file
      * Remove the image path or the VHD path
  3. Create VHD(X) and mount it
  4. Create the Unattend XML used for the first boot and move it to the mount point root
  5. Copy resources to the mounted point:
      * VMware tools
      * MAAS hooks
      * UnattendResources folder from the repo
      * Custom resources defined by the user
      * Configuration file
      * Windows wallpaper GPO
      * zapfree
      * cloudbase-init
  6. Expand the WIM file to the mount point
  7. Apply boot configuration according to the disk layout (BIOS or UEFI)
  8. Customization:
      * Enable extra features or capabilites
      * Add extra packages
      * Apply VirtIO drivers from Fedora or other drivers
  9. Unmount VHD and convert it to the desired disk format
  10. Compress the image file

## New-WindowsOnlineImage

The steps to create a fully functional image:
  1. Validate that the image configuration is correct:
      * If the desired image is a golden, the path should be a VHD(X)
  2. Validate host requirements:
      * Running as administrator
      * If sysprep is not run then force flag needs to set to true
      * Checks if HyperV is installed
      * An external switch exists and is external
      * If there are enough CPUs
      * Remove the image path or the VHD path
  3. Create a different config file from the initial one for running New-WindowsCloudImage:
      * image_path is changed to the VHDx one
      * zip_password is removed
      * virtual_disk_format is set to VHDX
  4. Run New-WindowsCloudImage with the config file generated at the previous step
  5. Create a Windows HyperV virtual machine with the VHDx generated at the previous step
  6. Start the VM and wait for it to stop running and remove the VM
  7. Shrink the VHD to the minimum size
  8. Convert VHD to the desired format using qemu-img bundled in the repo
  9. Compress the image file