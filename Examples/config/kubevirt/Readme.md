## How to deploy a Windows virtual machine on Kubevirt

### Requirements

For Kubernetes and KubeVirt, we need a baremetal machine or a virtual machine that supports nested Windows instances.
Windows does **NOT** boot on emulated environments.

Operating system: Ubuntu 18.04, as there is good support for Kubernetes.
Make sure that KVM / libvirt / docker.io are all supported and installed on the host.

To debug Windows VMs, is recommended to install an Ubuntu GUI, like ubuntu-desktop.

In PoC environments, disable apparmor for libvirtd. Do **NOT** do this in production.
```bash
    sudo ln -s /etc/apparmor.d/usr.sbin.libvirtd /etc/apparmor.d/disable/usr.sbin.libvirtd
    reboot
```

### Install Kubernetes using Kind
```bash
    KUBEVIRT_VERSION="v0.26.0"
    KUBEVIRT_DOWNLOAD_ROOT_URL="https://github.com/kubevirt/kubevirt/releases/download"

    # download kind
    curl -Lo ./kind https://github.com/kubernetes-sigs/kind/releases/download/v0.7.0/kind-$(uname)-amd64
    chmod +x ./kind && sudo mv ./kind /usr/bin

    # download virtctl
    curl -Lo ./virtctl https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/virtctl-${KUBEVIRT_VERSION}-$(uname)-amd64
    chmod +x ./virtctl && sudo mv ./virtctl /usr/bin

    # needed for the current user to be able to create docker containers
    sudo adduser $(whoami) docker

    kind create cluster

    sudo snap install kubectl --classic

    kubectl cluster-info --context kind-kind
    kubectl create namespace kubevirt

    kubectl apply -f "${KUBEVIRT_DOWNLOAD_ROOT_URL}/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"
    kubectl apply -f "${KUBEVIRT_DOWNLOAD_ROOT_URL}/${KUBEVIRT_VERSION}/kubevirt-cr.yaml"

    kubectl -n kubevirt wait kv kubevirt --for condition=Available
    # run it again if it times out until the condition is met
```

More information here: https://kubevirt.io/quickstart_kind/.

Now Kubernetes and KubeVirt should be properly installed and working.

### Create the Windows Image

The Windows image should be a RAW tar.gz, with the custom configuration files for Cloudbase-Init.

Cloudbase-Init custom config files enable the ConfigDrive and NoCloud metadata sources, which are supported by KubeVirt.

As the target hypervisor is QEMU-KVM, the VirtIO are required.

In this folder, you have a `kubevirt-image-config.ini`, where you need to set the following values manually:

    * wim_file_path (The local path of the Windows ISO. The ISO will be mounted by the image builder.)
    * image_name (The full name of the SKU from the mounted Windows ISO. Example: Windows Server 2019 SERVERSTANDARDCORE)
    * image_path (local path where the image will be generated. Example: C:\winimage.raw)
    * virtio_iso_path (local path of the Fedora VirtIO drivers ISO)
    * msi_path (local path of Cloudbase-Init installer with patch https://review.opendev.org/#/c/478515.
      An already built zipped installer can be downloaded from the Artifacts tab here:
      https://github.com/ader1990/cloudbase-init-installer-1/runs/450692211?check_suite_focus=true)
    * cloudbase_init_config_path - full path to the cloudbase-init.conf file from this folder
    * cloudbase_init_unattended_config_path - full path to the cloudbase-init-unattend.conf file from this folder

This step is performed on the Windows Image builder environments, which is required to be a Windows machine with Hyper-V support.
```powershell
    New-WindowsOnlineImage -ConfigFilePath "kubevirt-image-config.ini"
```

### Upload the image to KubeVirt

KubeVirt has a nice add-on, called Containerized Data Importer (CDI), which helps a lot with importing the Windows image.
It imports the image as a Persistent Volume. This volume can be used to create only one Windows image (the volume is similar to an
OpenStack Cinder volume).
```bash
    # create the storage setup where the Windows backing disks are uploaded
    wget https://raw.githubusercontent.com/kubevirt/kubevirt.github.io/master/labs/manifests/storage-setup.yml
    kubectl create -f storage-setup.yml

    # install Containerized Data Importer service inside Kubernetes
    CDI_VERSION="v1.12.0"
    CDI_DOWNLOAD_ROOT_URL="https://github.com/kubevirt/containerized-data-importer/releases/download"
    kubectl create -f "${CDI_DOWNLOAD_ROOT_URL}/${CDI_VERSION}/cdi-operator.yaml"
    kubectl create -f "${CDI_DOWNLOAD_ROOT_URL}/${CDI_VERSION}/cdi-cr.yaml"

    # download the spec for Windows disk upload
    wget https://raw.githubusercontent.com/ader1990/kubevirt.github.io/source/labs/manifests/pvc_windows.yml

    # MANUAL STEP
    # Replace WINDOWS_IMAGE_ENDPOINT from the pvc_windows.yml spec with the path where your Windows image resides
    # The WINDOWS_IMAGE_ENDPOINT should be in the format: http://my-webserver/my-windows-image.raw.tar.gz
    # For obvious legal reasons, the WINDOWS_IMAGE_ENDPOINT should not be publicly available

    # import the Windows Persistent Volume
    kubectl create -f pvc_windows.yml
    # wait for the volume to be imported
    kubectl logs -f importer-windows

    # get details on the volume
    kubectl describe pvc windows
```
More information here: https://kubevirt.io/labs/kubernetes/lab2.html.

### Start a Windows VM in KubeVirt

Start the Windows instance using the persistent volume uploaded at the previous step.

```bash
    VM_NAME="windowsvm1"

    # create the machine
    # if you want to change the VM name, you need to manually modify this resource file
    kubectl apply -f https://raw.githubusercontent.com/ader1990/kubevirt.github.io/source/labs/manifests/windowsvm1_pvc.yml

    # start machine
    virtctl start $VM_NAME

    # Disconnect from the virtual machine console by typing: ctrl+]
    # At each boot, you should see the Cloudbase-Init logs at the console
    virtctl console $VM_NAME

    # if running from a GUI terminal, you can open the VNC console
    virtctl vnc $VM_NAME

    # Get the VM IP
    kubectl get vmis

    # connect to the Windows VM using WinRM
    # You first need to manually enter the Kind control plane container
    # docker exec -it <container id of Kind control plane> /bin/bash

    # Inside the Kind container run:
    VM_IP="the IP shown in the output of the previous command: kubectl get vmis"
    VM_USERNAME="Administrator"
    VM_PASSWORD="StrongPassw0rd"

    apt update && apt install python python-pip -y
    pip install pywinrm

    curl -o wsmancmd.py https://raw.githubusercontent.com/ader1990/winrm-scripts/master/wsmancmd.py
    python wsmancmd.py -U "https://$VM_IP:5986/wsman" -v ignore -u "$VM_USERNAME" -p "$VM_PASSWORD" 'dir D:'
    # exit from the Kind control plane
    exit

    # remove the VM
    kubectl delete vm $VM_NAME
```