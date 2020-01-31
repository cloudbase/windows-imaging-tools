## How to create a Windows image for Azure

### Install and import WindowsImageBuilder

```powershell
    Install-Module WindowsImageBuilder
    Import-Module WindowsImageBuilder
```

### Create custom config for WindowsImageBuilder

```powershell
    New-WindowsImageConfig -ConfigFilePath "azure-image-config.ini"
```

Use Cloudbase-Init beta installer and custom config files in "azure-image-config.ini":

```ini
    [cloudbase_init]
    cloudbase_init_config_path=<full path of cloudbase-init.conf from this folder>
    cloudbase_init_unattended_config_path=<full path of cloudbase-init-unattend.conf from this folder>
    beta_release=True
```

### Create the image

```powershell
    New-WindowsOnlineImage -ConfigFilePath "azure-image-config.ini"
```

### Convert the image VHDX to a fixed one

```powershell
    Convert-VHD -Path <path_to_vhdx> -VHDType Fixed -DestinationPath <path_to_vhd>
```

### Upload the fixed VHD to Azure and create the VM

The remaining steps are very well explained at:

https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sa-upload-generalized
