param(
[String]$Image,
[String]$ConfigFile
)

#needed for extracted file
[String]$imgExtracted

#see what kind of file was given as Image param
$extension=[IO.Path]::GetExtension($Image)
$extension=$extension.split(".")[1]

#get the Type from the config file
$Type = cat $ConfigFile | Select-String "image_type" | cut -f 2 -d "="

function extractTarGz($file) {

    $extension = [IO.Path]::GetExtension($file)
    $path = Split-Path -Path $file
    $path = $path + "\extracted"

    Write-Host "Image is being extracted to $path"
    7z e $file "-o$path"
    $img = Get-ChildItem $path\*.tar
    7z x -aoa -ttar $img "-o$path"
    rm $path\*.tar
    $global:imgExtracted = Get-ChildItem $path\*.*

    Write-Host "Done extracting"
	
}

function deleteExtracted($file) {

    $path = Split-Path -Path $file
    rm -r $path
	
}

function checkFormat($Type, $Image) {

    $img_name = $Image.split(".")[0]
    $extension=[IO.Path]::GetExtension($Image)
    $extension=$extension.split(".")[1]

    If($Type -eq "Hyper-V") {

        If($extension -eq "VHDX") {
            Write-Host "OK"	
        }
        
		Else {
            Write-Host "Wrong format for Hyper-V"
            exit	
        }
    }

    ElseIf($Type -eq "MAAS") {

        If($extension -eq "raw") {
		
            $converted = $Image.split(".")[0]+".vhdx"
            Write-Host "Converting $Image to $converted..."
            qemu-img convert -f $extension -O vhdx $Image $converted
            Write-Host "Mounting $converted..."
            Mount-VHD -Path $converted
		    Write-Host "Checking for curtin..."
            $curtin = ls D:\ | Select-String -Quiet "curtin"
			
			If($curtin) {
                Write-Host "OK"
            }
            
			Else {
                Write-Host "WRONG format: $Image doesn't have curtin"	
            }
			
		Dismount-VHD $converted
        Remove-Item $converted
		exit
        }
		
        Else {
            Write-Host "Wrong format for MAAS"	
			exit
        }		
		
    }

    ElseIf($Type -eq "KVM") {

        If($extension -eq "raw" -Or $extension -eq "qcow2") {
		
            $converted = $Image.split(".")[0]+".vhdx"
            Write-Host "Converting $Image to $converted..."
            qemu-img convert -f $extension -O vhdx $Image $converted
        
            Write-Host "Mounting $converted..."
            Mount-VHD -Path $converted
		    Write-Host "Checking for VirtIO..."
            $virtio = Get-ChildItem -Recurse -Force D:\ -ErrorAction SilentlyContinue | Where-Object { ($_.PSIsContainer -eq $false) -and  ( $_.Name -like "vio*") }

            If ($virtio) {
                Write-Host "OK"
            }
            
			Else {
                Write-Host "$Image doesn't have VirtIO"
            }

        Dismount-VHD $converted
        Remove-Item $converted
        exit
        }
        
		Else {
            Write-Host "Wrong format for KVM"
			exit
        }
    }

    Else {
        Write-Host "Wrong type"
        exit
    }
}


#check to see if the file given as Image param has to be extracted or not, then check format
If($extension -eq "tgz" -Or $extension -eq "gz" -Or $extension -eq "tar") {

    extractTarGz $Image
	$Image = $imgExtracted
	checkFormat $Type $Image
	deleteExtracted $imgExtracted	
}

Else {
    checkFormat $Type $Image
}

