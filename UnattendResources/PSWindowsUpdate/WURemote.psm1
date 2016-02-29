Function Update-WUModule
{
	<#
	.SYNOPSIS
		Invoke Get-WUInstall remotely.

	.DESCRIPTION
		Use Invoke-WUInstall to invoke Windows Update install remotly. It Based on TaskScheduler because 
		CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
		
		Note:
		Because we do not have the ability to interact, is recommended use -AcceptAll with WUInstall filters in script block.
	
	.PARAMETER ComputerName
		Specify computer name.

	.PARAMETER PSWUModulePath	
		Destination of PSWindowsUpdate module. Default is C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate
	
	.PARAMETER OnlinePSWUSource
		Link to online source on TechNet Gallery.
		
	.PARAMETER LocalPSWUSource	
		Path to local source on your machine. If you cant use [System.IO.Compression.ZipFile] you must manualy unzip source and set path to it.
			
	.PARAMETER CheckOnly
		Only check current version of PSWindowsUpdate module. Don't update it.
		
	.EXAMPLE
		PS C:\> Update-WUModule

	.EXAMPLE
		PS C:\> Update-WUModule -LocalPSWUSource "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate" -ComputerName PC2,PC3,PC4
		
	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/

	.LINK
		Get-WUInstall
	#>
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]
	param
	(
		[Parameter(ValueFromPipeline=$True,
					ValueFromPipelineByPropertyName=$True)]
		[String[]]$ComputerName = "localhost",
		[String]$PSWUModulePath = "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate",
		[String]$OnlinePSWUSource = "http://gallery.technet.microsoft.com/2d191bcd-3308-4edd-9de2-88dff796b0bc",
		[String]$SourceFileName = "PSWindowsUpdate.zip",
		[String]$LocalPSWUSource,
		[Switch]$CheckOnly,
		[Switch]$Debuger
	)

	Begin 
	{
		If($PSBoundParameters['Debuger'])
		{
			$DebugPreference = "Continue"
		} #End If $PSBoundParameters['Debuger']
		
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role
		
		if($LocalPSWUSource -eq "")
		{
			Write-Debug "Prepare temp location"
			$TEMPDentination = [environment]::GetEnvironmentVariable("Temp")
			#$SourceFileName = $OnlinePSWUSource.Substring($OnlinePSWUSource.LastIndexOf("/")+1)
			$ZipedSource = Join-Path -Path $TEMPDentination -ChildPath $SourceFileName
			$TEMPSource = Join-Path -Path $TEMPDentination -ChildPath "PSWindowsUpdate"
			
			Try
			{
				$WebClient = New-Object System.Net.WebClient
				$WebSite = $WebClient.DownloadString($OnlinePSWUSource)
				$WebSite -match "/file/41459/\d*/PSWindowsUpdate.zip" | Out-Null
				
				$OnlinePSWUSourceFile = $OnlinePSWUSource + $matches[0]
				Write-Debug "Download latest PSWindowsUpdate module from website: $OnlinePSWUSourceFile"	
				#Start-BitsTransfer -Source $OnlinePSWUSource -Destination $TEMPDentination
				
				$WebClient.DownloadFile($OnlinePSWUSourceFile,$ZipedSource)
			} #End Try
			catch
			{
				Write-Error "Can't download the latest PSWindowsUpdate module from website: $OnlinePSWUSourceFile" -ErrorAction Stop
			} #End Catch
			
			Try
			{
				if(Test-Path $TEMPSource)
				{
					Write-Debug "Cleanup old PSWindowsUpdate source"
					Remove-Item -Path $TEMPSource -Force -Recurse
				} #End If Test-Path $TEMPSource
				
				Write-Debug "Unzip the latest PSWindowsUpdate module"
				[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
				[System.IO.Compression.ZipFile]::ExtractToDirectory($ZipedSource,$TEMPDentination)
				$LocalPSWUSource = Join-Path -Path $TEMPDentination -ChildPath "PSWindowsUpdate"
			} #End Try
			catch
			{
				Write-Error "Can't unzip the latest PSWindowsUpdate module" -ErrorAction Stop
			} #End Catch
			
			Write-Debug "Unblock the latest PSWindowsUpdate module"
			Get-ChildItem -Path $LocalPSWUSource | Unblock-File
		} #End If $LocalPSWUSource -eq ""

		$ManifestPath = Join-Path -Path $LocalPSWUSource -ChildPath "PSWindowsUpdate.psd1"
		$TheLatestVersion = (Test-ModuleManifest -Path $ManifestPath).Version
		Write-Verbose "The latest version of PSWindowsUpdate module is $TheLatestVersion"
	}
	
	Process
	{
		ForEach($Computer in $ComputerName)
		{
			if($Computer -eq [environment]::GetEnvironmentVariable("COMPUTERNAME") -or $Computer -eq ".")
			{
				$Computer = "localhost"
			} #End If $Computer -eq [environment]::GetEnvironmentVariable("COMPUTERNAME") -or $Computer -eq "."
			
			if($Computer -eq "localhost")
			{
				$ModuleTest = Get-Module -ListAvailable -Name PSWindowsUpdate
			} #End if $Computer -eq "localhost"
			else
			{
				if(Test-Connection $Computer -Quiet)
				{
					Write-Debug "Check if PSWindowsUpdate module exist on $Computer"
					Try
					{
						$ModuleTest = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Module -ListAvailable -Name PSWindowsUpdate} -ErrorAction Stop
					} #End Try
					Catch
					{
						Write-Warning "Can't access to machine $Computer. Try use: winrm qc"
						Continue
					} #End Catch
				} #End If Test-Connection $Computer -Quiet
				else
				{
					Write-Warning "Machine $Computer is not responding."
				} #End Else Test-Connection -ComputerName $Computer -Quiet
			} #End Else $Computer -eq "localhost"
			
			If ($pscmdlet.ShouldProcess($Computer,"Update PSWindowsUpdate module from $($ModuleTest.Version) to $TheLatestVersion")) 
			{
				if($Computer -eq "localhost")
				{
					if($ModuleTest.Version -lt $TheLatestVersion)
					{
						if($CheckOnly)
						{
							Write-Verbose "Current version of PSWindowsUpdate module is $($ModuleTest.Version)"
						} #End If $CheckOnly
						else
						{
							Write-Verbose "Copy source files to PSWindowsUpdate module path"
							Get-ChildItem -Path $LocalPSWUSource | Copy-Item -Destination $ModuleTest.ModuleBase -Force
							
							$AfterUpdateVersion = [String]((Get-Module -ListAvailable -Name PSWindowsUpdate).Version)
							Write-Verbose "$($Computer): Update completed: $AfterUpdateVersion" 
						}#End Else $CheckOnly
					} #End If $ModuleTest.Version -lt $TheLatestVersion
					else
					{
						Write-Verbose "The newest version of PSWindowsUpdate module exist"
					} #ed Else $ModuleTest.Version -lt $TheLatestVersion
				} #End If $Computer -eq "localhost"
				else
				{
					Write-Debug "Connection to $Computer"
					if($ModuleTest -eq $null)
					{
						$PSWUModulePath = $PSWUModulePath -replace ":","$"
						$DestinationPath = "\\$Computer\$PSWUModulePath"

						if($CheckOnly)
						{
							Write-Verbose "PSWindowsUpdate module on machine $Computer doesn't exist"
						} #End If $CheckOnly
						else
						{
							Write-Verbose "PSWindowsUpdate module on machine $Computer doesn't exist. Installing: $DestinationPath"
							Try
							{
								New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
								Get-ChildItem -Path $LocalPSWUSource | Copy-Item -Destination $DestinationPath -Force
								
								$AfterUpdateVersion = [string](Invoke-Command -ComputerName $Computer -ScriptBlock {(Get-Module -ListAvailable -Name PSWindowsUpdate).Version} -ErrorAction Stop)
								Write-Verbose "$($Computer): Update completed: $AfterUpdateVersion" 								
							} #End Try	
							Catch
							{
								Write-Warning "Can't install PSWindowsUpdate module on machine $Computer."
							} #End Catch
						} #End Else $CheckOnly
					} #End If $ModuleTest -eq $null
					elseif($ModuleTest.Version -lt $TheLatestVersion)
					{
						$PSWUModulePath = $ModuleTest.ModuleBase -replace ":","$"
						$DestinationPath = "\\$Computer\$PSWUModulePath"
						
						if($CheckOnly)
						{
							Write-Verbose "Current version of PSWindowsUpdate module on machine $Computer is $($ModuleTest.Version)"
						} #End If $CheckOnly
						else
						{
							Write-Verbose "PSWindowsUpdate module version on machine $Computer is ($($ModuleTest.Version)) and it's older then downloaded ($TheLatestVersion). Updating..."							
							Try
							{
								Get-ChildItem -Path $LocalPSWUSource | Copy-Item -Destination $DestinationPath -Force	
								
								$AfterUpdateVersion = [string](Invoke-Command -ComputerName $Computer -ScriptBlock {(Get-Module -ListAvailable -Name PSWindowsUpdate).Version} -ErrorAction Stop)
								Write-Verbose "$($Computer): Update completed: $AfterUpdateVersion" 
							} #End Try
							Catch
							{
								Write-Warning "Can't updated PSWindowsUpdate module on machine $Computer"
							} #End Catch
						} #End Else $CheckOnly
					} #End ElseIf $ModuleTest.Version -lt $TheLatestVersion
					else
					{
						Write-Verbose "Current version of PSWindowsUpdate module on machine $Computer is $($ModuleTest.Version)"
					} #End Else $ModuleTest.Version -lt $TheLatestVersion
				} #End Else $Computer -eq "localhost"
			} #End If $pscmdlet.ShouldProcess($Computer,"Update PSWindowsUpdate module")
		} #End ForEach $Computer in $ComputerName
	}
	
	End 
	{
		if($LocalPSWUSource -eq "")
		{
			Write-Debug "Cleanup PSWindowsUpdate source"
			if(Test-Path $ZipedSource -ErrorAction SilentlyContinue)
			{
				Remove-Item -Path $ZipedSource -Force
			} #End If Test-Path $ZipedSource
			if(Test-Path $TEMPSource -ErrorAction SilentlyContinue)
			{
				Remove-Item -Path $TEMPSource -Force -Recurse
			} #End If Test-Path $TEMPSource	
		}
	}

}
Function Invoke-WUInstall
{
	<#
	.SYNOPSIS
		Invoke Get-WUInstall remotely.

	.DESCRIPTION
		Use Invoke-WUInstall to invoke Windows Update install remotly. It Based on TaskScheduler because 
		CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
		
		Note:
		Because we do not have the ability to interact, is recommended use -AcceptAll with WUInstall filters in script block.
	
	.PARAMETER ComputerName
		Specify computer name.

	.PARAMETER TaskName
		Specify task name. Default is PSWindowsUpdate.
		
	.PARAMETER Script
		Specify PowerShell script block that you what to run. Default is {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log}
		
	.EXAMPLE
		PS C:\> $Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll -AutoReboot | Out-File C:\PSWindowsUpdate.log}
		PS C:\> Invoke-WUInstall -ComputerName pc1.contoso.com -Script $Script
		...
		PS C:\> Get-Content \\pc1.contoso.com\c$\PSWindowsUpdate.log
		
	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/

	.LINK
		Get-WUInstall
	#>
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]
	param
	(
		[Parameter(ValueFromPipeline=$True,
					ValueFromPipelineByPropertyName=$True)]
		[String[]]$ComputerName,
		[String]$TaskName = "PSWindowsUpdate",
		[ScriptBlock]$Script = {ipmo PSWindowsUpdate; Get-WUInstall -AcceptAll | Out-File C:\PSWindowsUpdate.log},
		[Switch]$OnlineUpdate
	)

	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role
		
		$PSWUModule = Get-Module -Name PSWindowsUpdate -ListAvailable
		
		Write-Verbose "Create schedule service object"
		$Scheduler = New-Object -ComObject Schedule.Service
			
		$Task = $Scheduler.NewTask(0)

		$RegistrationInfo = $Task.RegistrationInfo
		$RegistrationInfo.Description = $TaskName
		$RegistrationInfo.Author = $User.Name

		$Settings = $Task.Settings
		$Settings.Enabled = $True
		$Settings.StartWhenAvailable = $True
		$Settings.Hidden = $False

		$Action = $Task.Actions.Create(0)
		$Action.Path = "powershell"
		$Action.Arguments = "-Command $Script"
		
		$Task.Principal.RunLevel = 1	
	}
	
	Process
	{
		ForEach($Computer in $ComputerName)
		{
			If ($pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")) 
			{
				if(Test-Connection -ComputerName $Computer -Quiet)
				{
					Write-Verbose "Check PSWindowsUpdate module on $Computer"
					Try
					{
						$ModuleTest = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Module -ListAvailable -Name PSWindowsUpdate} -ErrorAction Stop
					} #End Try
					Catch
					{
						Write-Warning "Can't access to machine $Computer. Try use: winrm qc"
						Continue
					} #End Catch
					$ModulStatus = $false
					
					if($ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version)
					{
						if($OnlineUpdate)
						{
							Update-WUModule -ComputerName $Computer
						} #End If $OnlineUpdate
						else
						{
							Update-WUModule -ComputerName $Computer	-LocalPSWUSource (Get-Module -ListAvailable -Name PSWindowsUpdate).ModuleBase
						} #End Else $OnlineUpdate
					} #End If $ModuleTest -eq $null -or $ModuleTest.Version -lt $PSWUModule.Version
					
					#Sometimes can't connect at first time
					$Info = "Connect to scheduler and register task on $Computer"
					for ($i=1; $i -le 3; $i++)
					{
						$Info += "."
						Write-Verbose $Info
						Try
						{
							$Scheduler.Connect($Computer)
							Break
						} #End Try
						Catch
						{
							if($i -ge 3)
							{
								Write-Error "Can't connect to Schedule service on $Computer" -ErrorAction Stop
							} #End If $i -ge 3
							else
							{
								sleep -Seconds 1
							} #End Else $i -ge 3
						} #End Catch					
					} #End For $i=1; $i -le 3; $i++
					
					$RootFolder = $Scheduler.GetFolder("\")
					$SendFlag = 1
					if($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
					{
						$CurrentTask = $RootFolder.GetTask($TaskName)
						$Title = "Task $TaskName is curretly running: $($CurrentTask.Definition.Actions | Select-Object -exp Path) $($CurrentTask.Definition.Actions | Select-Object -exp Arguments)"
						$Message = "What do you want to do?"

						$ChoiceContiniue = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue Current Task"
						$ChoiceStart = New-Object System.Management.Automation.Host.ChoiceDescription "Stop and Start &New Task"
						$ChoiceStop = New-Object System.Management.Automation.Host.ChoiceDescription "&Stop Task"
						$Options = [System.Management.Automation.Host.ChoiceDescription[]]($ChoiceContiniue, $ChoiceStart, $ChoiceStop)
						$SendFlag = $host.ui.PromptForChoice($Title, $Message, $Options, 0)
					
						if($SendFlag -ge 1)
						{
							($RootFolder.GetTask($TaskName)).Stop(0)
						} #End If $SendFlag -eq 1	
						
					} #End If !($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
						
					if($SendFlag -eq 1)
					{
						$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
						$RootFolder.GetTask($TaskName).Run(0) | Out-Null
					} #End If $SendFlag -eq 1
					
					#$RootFolder.DeleteTask($TaskName,0)
				} #End If Test-Connection -ComputerName $Computer -Quiet
				else
				{
					Write-Warning "Machine $Computer is not responding."
				} #End Else Test-Connection -ComputerName $Computer -Quiet
			} #End If $pscmdlet.ShouldProcess($Computer,"Invoke WUInstall")
		} #End ForEach $Computer in $ComputerName
		Write-Verbose "Invoke-WUInstall complete."
	}
	
	End {}

}

Export-ModuleMember -Function *