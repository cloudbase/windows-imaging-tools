Function Get-WUHistory
{
	<#
	.SYNOPSIS
	    Get list of updates history.

	.DESCRIPTION
	    Use function Get-WUHistory to get list of installed updates on current machine. It works similar like Get-Hotfix.
	       
	.PARAMETER ComputerName	
	    Specify the name of the computer to the remote connection.
 	       
	.PARAMETER Debuger	
	    Debug mode.
		
	.EXAMPLE
		Get updates histry list for sets of remote computers.
		
		PS C:\> "G1","G2" | Get-WUHistory

		ComputerName Date                KB        Title
		------------ ----                --        -----
		G1           2011-12-15 13:26:13 KB2607047 Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2607047)
		G1           2011-12-15 13:25:02 KB2553385 Aktualizacja dla programu Microsoft Office 2010 (KB2553385) wersja 64-bitowa
		G1           2011-12-15 13:24:26 KB2618451 Zbiorcza aktualizacja zabezpieczeñ funkcji Killbit formantów ActiveX w sy...
		G1           2011-12-15 13:23:57 KB890830  Narzêdzie Windows do usuwania z³oœliwego oprogramowania dla komputerów z ...
		G1           2011-12-15 13:17:20 KB2589320 Aktualizacja zabezpieczeñ dla programu Microsoft Office 2010 (KB2589320) ...
		G1           2011-12-15 13:16:30 KB2620712 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G1           2011-12-15 13:15:52 KB2553374 Aktualizacja zabezpieczeñ dla programu Microsoft Visio 2010 (KB2553374) w...      
		G2           2011-12-17 13:39:08 KB2563227 Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2563227)
		G2           2011-12-17 13:37:51 KB2425227 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:37:23 KB2572076 Aktualizacja zabezpieczeñ dla programu Microsoft .NET Framework 3.5.1 w s...
		G2           2011-12-17 13:36:53 KB2560656 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:36:26 KB979482  Aktualizacja zabezpieczeñ dla systemu Windows 7 dla systemów opartych na ...
		G2           2011-12-17 13:36:05 KB2535512 Aktualizacja zabezpieczeñ systemu Windows 7 dla systemów opartych na proc...
		G2           2011-12-17 13:35:41 KB2387530 Aktualizacja dla systemu Windows 7 dla systemów opartych na procesorach x...
	
	.EXAMPLE  
		Get information about specific installed updates.
	
		PS C:\> $WUHistory = Get-WUHistory
		PS C:\> $WUHistory | Where-Object {$_.Title -match "KB2607047"} | Select-Object *


		KB                  : KB2607047
		ComputerName        : G1
		Operation           : 1
		ResultCode          : 1
		HResult             : -2145116140
		Date                : 2011-12-15 13:26:13
		UpdateIdentity      : System.__ComObject
		Title               : Aktualizacja systemu Windows 7 dla komputerów z procesorami x64 (KB2607047)
		Description         : Zainstalowanie tej aktualizacji umo¿liwia rozwi¹zanie problemów w systemie Windows. Aby uzyskaæ p
		                      e³n¹ listê problemów, które zosta³y uwzglêdnione w tej aktualizacji, nale¿y zapoznaæ siê z odpowi
		                      ednim artyku³em z bazy wiedzy Microsoft Knowledge Base w celu uzyskania dodatkowych informacji. P
		                      o zainstalowaniu tego elementu mo¿e byæ konieczne ponowne uruchomienie komputera.
		UnmappedResultCode  : 0
		ClientApplicationID : AutomaticUpdates
		ServerSelection     : 1
		ServiceID           :
		UninstallationSteps : System.__ComObject
		UninstallationNotes : Tê aktualizacjê oprogramowania mo¿na usun¹æ, wybieraj¹c opcjê Wyœwietl zainstalowane aktualizacje
		                       w aplecie Programy i funkcje w Panelu sterowania.
		SupportUrl          : http://support.microsoft.com
		Categories          : System.__ComObject

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
		Get-WUList
		
	#>
	[OutputType('PSWindowsUpdate.WUHistory')]
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="Low"
	)]
	Param
	(
		#Mode options
		[Switch]$Debuger,
		[parameter(ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true)]
		[String[]]$ComputerName	
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
	}
	
	Process
	{
		#region STAGE 0
		Write-Debug "STAGE 0: Prepare environment"
		######################################
		# Start STAGE 0: Prepare environment #
		######################################
		
		Write-Debug "Check if ComputerName in set"
		If($ComputerName -eq $null)
		{
			Write-Debug "Set ComputerName to localhost"
			[String[]]$ComputerName = $env:COMPUTERNAME
		} #End If $ComputerName -eq $null

		####################################
		# End STAGE 0: Prepare environment #
		####################################
		#endregion
		
		$UpdateCollection = @()
		Foreach($Computer in $ComputerName)
		{
			If(Test-Connection -ComputerName $Computer -Quiet)
			{
				#region STAGE 1
				Write-Debug "STAGE 1: Get history list"
				###################################
				# Start STAGE 1: Get history list #
				###################################
		
				If ($pscmdlet.ShouldProcess($Computer,"Get updates history")) 
				{
					Write-Verbose "Get updates history for $Computer"
					If($Computer -eq $env:COMPUTERNAME)
					{
						Write-Debug "Create Microsoft.Update.Session object for $Computer"
						$objSession = New-Object -ComObject "Microsoft.Update.Session" #Support local instance only
					} #End If $Computer -eq $env:COMPUTERNAME
					Else
					{
						Write-Debug "Create Microsoft.Update.Session object for $Computer"
						$objSession =  [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computer))
					} #End Else $Computer -eq $env:COMPUTERNAME

					Write-Debug "Create Microsoft.Update.Session.Searcher object for $Computer"
					$objSearcher = $objSession.CreateUpdateSearcher()
					$TotalHistoryCount = $objSearcher.GetTotalHistoryCount()

					If($TotalHistoryCount -gt 0)
					{
						$objHistory = $objSearcher.QueryHistory(0, $TotalHistoryCount)
						$NumberOfUpdate = 1
						Foreach($obj in $objHistory)
						{
							Write-Progress -Activity "Get update histry for $Computer" -Status "[$NumberOfUpdate/$TotalHistoryCount] $($obj.Title)" -PercentComplete ([int]($NumberOfUpdate/$TotalHistoryCount * 100))

							Write-Debug "Get update histry: $($obj.Title)"
							Write-Debug "Convert KBArticleIDs"
							$matches = $null
							$obj.Title -match "KB(\d+)" | Out-Null
							
							If($matches -eq $null)
							{
								Add-Member -InputObject $obj -MemberType NoteProperty -Name KB -Value ""
							} #End If $matches -eq $null
							Else
							{							
								Add-Member -InputObject $obj -MemberType NoteProperty -Name KB -Value ($matches[0])
							} #End Else $matches -eq $null
							
							Add-Member -InputObject $obj -MemberType NoteProperty -Name ComputerName -Value $Computer
							
							$obj.PSTypeNames.Clear()
							$obj.PSTypeNames.Add('PSWindowsUpdate.WUHistory')
						
							$UpdateCollection += $obj
							$NumberOfUpdate++
						} #End Foreach $obj in $objHistory
						Write-Progress -Activity "Get update histry for $Computer" -Status "Completed" -Completed
					} #End If $TotalHistoryCount -gt 0
					Else
					{
						Write-Warning "Probably your history was cleared. Alternative please run 'Get-WUList -IsInstalled'"
					} #End Else $TotalHistoryCount -gt 0
				} #End If $pscmdlet.ShouldProcess($Computer,"Get updates history")
				
				################################
				# End PASS 1: Get history list #
				################################
				#endregion
				
			} #End If Test-Connection -ComputerName $Computer -Quiet
		} #End Foreach $Computer in $ComputerName	
		
		Return $UpdateCollection
	} #End Process

	End{}	
} #In The End :)

Function Get-WUInstallerStatus
{
    <#
	.SYNOPSIS
	    Show Windows Update Installer status.

	.DESCRIPTION
	    Use Get-WUInstallerStatus to show Windows Update Installer status.

	.PARAMETER Silent
	    Get only status True/False without any more comments on screen.
		
	.EXAMPLE
		Check if Windows Update Installer is busy.
		
		PS C:\> Get-WUInstallerStatus
		Installer is ready.

	.EXAMPLE
		Check if Windows Update Installer is busy in silent mode. Return only True (isBusy) or False (isFree).
		
		PS C:\> Get-WUInstallerStatus -Silent
		False

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Get-WURebootStatus
	#>
	
	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
    Param
	(
		[Switch]$Silent
	)
	
	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role	
	}
	
	Process
	{
        If ($pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Check that Windows Installer is ready to install next updates")) 
		{	    
			$objInstaller=New-Object -ComObject "Microsoft.Update.Installer"
			
			Switch($objInstaller.IsBusy)
			{
				$true	{ If($Silent) {Return $true} Else {Write-Output "Installer is busy."}}
				$false	{ If($Silent) {Return $false} Else {Write-Output "Installer is ready."}}
			} #End Switch $objInstaller.IsBusy
			
		} #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Check that Windows Installer is ready to install next updates")
	} #End Process
	
	End{}	
} #In The End :)

Function Get-WURebootStatus
{
    <#
	.SYNOPSIS
	    Show Windows Update Reboot status.

	.DESCRIPTION
	    Use Get-WURebootStatus to check if reboot is needed.
		
	.PARAMETER Silent
	    Get only status True/False without any more comments on screen. 
	
	.EXAMPLE
        Check whether restart is necessary. If yes, ask to do this or don't.
		
		PS C:\> Get-WURebootStatus
		Reboot is required. Do it now ? [Y/N]: Y
		
	.EXAMPLE
		Silent check whether restart is necessary. It return only status True or False without restart machine.
	
        PS C:\> Get-WURebootStatus -Silent
		True
		
	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/
		
	.LINK
		http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc

	.LINK
        Get-WUInstallerStatus
	#>    

	[CmdletBinding(
    	SupportsShouldProcess=$True,
        ConfirmImpact="Low"
    )]
    Param
	(
		[Alias("StatusOnly")]
		[Switch]$Silent,
		[String[]]$ComputerName = "localhost",
		[Switch]$AutoReboot
	)
	
	Begin
	{
		$User = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

		if(!$Role)
		{
			Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."	
		} #End If !$Role
	}
	
	Process
	{
        ForEach($Computer in $ComputerName)
		{
			If ($pscmdlet.ShouldProcess($Computer,"Check that Windows update needs to restart system to install next updates")) 
			{				
				if($Env:COMPUTERNAME,"localhost","." -contains $Computer)
				{
				    Write-Verbose "$($Computer): Using WUAPI"
					$objSystemInfo= New-Object -ComObject "Microsoft.Update.SystemInfo"
					$RebootRequired = $objSystemInfo.RebootRequired
				} #End if $Computer -eq $Env:COMPUTERNAME
				else
				{
					Write-Verbose "$($Computer): Using Registry"
					$RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$Computer) 
					$RegistrySubKey = $RegistryKey.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
					$RegistrySubKeyNames = $RegistrySubKey.GetSubKeyNames() 
					$RebootRequired = $RegistrySubKeyNames -contains "RebootRequired" 

				} #End else $Computer -eq $Env:COMPUTERNAME
				
				Switch($RebootRequired)
				{
					$true	{
						If($Silent) 
						{
							Return $true
						} #End If $Silent
						Else 
						{
							if($AutoReboot -ne $true)
							{
								$Reboot = Read-Host "$($Computer): Reboot is required. Do it now ? [Y/N]"
							} #End If $AutoReboot -ne $true
							Else
							{
								$Reboot = "Y"
							} #End else $AutoReboot -ne $true
							
							If($Reboot -eq "Y")
							{
								Write-Verbose "Rebooting $($Computer)"
								Restart-Computer -ComputerName $Computer -Force
							} #End If $Reboot -eq "Y"
						} #End Else $Silent
					} #End Switch $true
						
					$false	{ 
						If($Silent) 
						{
							Return $false
						} #End If $Silent
						Else 
						{
							Write-Output "$($Computer): Reboot is not Required."
						} #End Else $Silent
					} #End Switch $false
				} #End Switch $objSystemInfo.RebootRequired
				
			} #End If $pscmdlet.ShouldProcess($Env:COMPUTERNAME,"Check that Windows update needs to restart system to install next updates")
		} #End ForEach $Computer in $ComputerName
	} #End Process
	
	End{}				
} #In The End :)

Function Hide-WUUpdate
{
	<#
	.SYNOPSIS
	    Get list of available updates meeting the criteria and try to hide/unhide it.

	.DESCRIPTION
	    Use Hide-WUUpdate to get list of available updates meeting specific criteria. In next step script try to hide (or unhide) updates.
		There are two types of filtering update: Pre search criteria, Post search criteria.
		- Pre search works on server side, like example: ( IsInstalled = 0 and IsHidden = 0 and CategoryIds contains '0fa1201d-4330-4fa8-8ae9-b877473b6441' )
		- Post search work on client side after downloading the pre-filtered list of updates, like example $KBArticleID -match $Update.KBArticleIDs

		Status list:
        D - IsDownloaded, I - IsInstalled, M - IsMandatory, H - IsHidden, U - IsUninstallable, B - IsBeta
		
	.PARAMETER UpdateType
		Pre search criteria. Finds updates of a specific type, such as 'Driver' and 'Software'. Default value contains all updates.

	.PARAMETER UpdateID
		Pre search criteria. Finds updates of a specific UUID (or sets of UUIDs), such as '12345678-9abc-def0-1234-56789abcdef0'.

	.PARAMETER RevisionNumber
		Pre search criteria. Finds updates of a specific RevisionNumber, such as '100'. This criterion must be combined with the UpdateID param.

	.PARAMETER CategoryIDs
		Pre search criteria. Finds updates that belong to a specified category (or sets of UUIDs), such as '0fa1201d-4330-4fa8-8ae9-b877473b6441'.

	.PARAMETER IsInstalled
		Pre search criteria. Finds updates that are installed on the destination computer.

	.PARAMETER IsHidden
		Pre search criteria. Finds updates that are marked as hidden on the destination computer.
	
	.PARAMETER IsNotHidden
		Pre search criteria. Finds updates that are not marked as hidden on the destination computer. Overwrite IsHidden param.
			
	.PARAMETER Criteria
		Pre search criteria. Set own string that specifies the search criteria.

	.PARAMETER ShowSearchCriteria
		Show choosen search criteria. Only works for pre search criteria.
		
	.PARAMETER Category
		Post search criteria. Finds updates that contain a specified category name (or sets of categories name), such as 'Updates', 'Security Updates', 'Critical Updates', etc...
		
	.PARAMETER KBArticleID
		Post search criteria. Finds updates that contain a KBArticleID (or sets of KBArticleIDs), such as 'KB982861'.
	
	.PARAMETER Title
		Post search criteria. Finds updates that match part of title, such as ''

	.PARAMETER NotCategory
		Post search criteria. Finds updates that not contain a specified category name (or sets of categories name), such as 'Updates', 'Security Updates', 'Critical Updates', etc...
		
	.PARAMETER NotKBArticleID
		Post search criteria. Finds updates that not contain a KBArticleID (or sets of KBArticleIDs), such as 'KB982861'.
	
	.PARAMETER NotTitle
		Post search criteria. Finds updates that not match part of title.
		
	.PARAMETER IgnoreUserInput
		Post search criteria. Finds updates that the installation or uninstallation of an update can't prompt for user input.
	
	.PARAMETER IgnoreRebootRequired
		Post search criteria. Finds updates that specifies the restart behavior that not occurs when you install or uninstall the update.
	
	.PARAMETER ServiceID
		Set ServiceIS to change the default source of Windows Updates. It overwrite ServerSelection parameter value.

	.PARAMETER WindowsUpdate
		Set Windows Update Server as source. Default update config are taken from computer policy.
		
	.PARAMETER MicrosoftUpdate
		Set Microsoft Update Server as source. Default update config are taken from computer policy.

	.PARAMETER HideStatus
		Status used in script. Default is $True = hide update.
		
	.PARAMETER ComputerName	
	    Specify the name of the computer to the remote connection.

	.PARAMETER Debuger	
	    Debug mode.

	.EXAMPLE
		Get list of available updates from Microsoft Update Server and hide it.
	
		PS C:\> Hide-WUList -MicrosoftUpdate

		Confirm
		Are you sure you want to perform this action?
		Performing the operation "Hide Windows Malicious Software Removal Tool x64 - December 2013 (KB890830)?" on target
		"TEST".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

		ComputerName Status KB          Size Title
		------------ ------ --          ---- -----
		TEST         D--H-- KB890830    8 MB Windows Malicious Software Removal Tool x64 - December 2013 (KB890830)


	.EXAMPLE
		Unhide update
	
		PS C:\> Hide-WUUpdate -Title 'Windows Malicious*' -HideStatus:$false

		Confirm
		Are you sure you want to perform this action?
		Performing the operation "Unhide Windows Malicious Software Removal Tool x64 - December 2013 (KB890830)?" on target
		"TEST".
		[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y

		ComputerName Status KB          Size Title
		------------ ------ --          ---- -----
		TEST         D----- KB890830    8 MB Windows Malicious Software Removal Tool x64 - December 2013 (KB890830)

	.NOTES
		Author: Michal Gajda
		Blog  : http://commandlinegeeks.com/


	.LINK
		Get-WUServiceManager
		Get-WUInstall
	#>

	[OutputType('PSWindowsUpdate.WUList')]
	[CmdletBinding(
		SupportsShouldProcess=$True,
		ConfirmImpact="High"
	)]	
	Param
	(
		#Pre search criteria
		[ValidateSet("Driver", "Software")]
		[String]$UpdateType = "",
		[String[]]$UpdateID,
		[Int]$RevisionNumber,
		[String[]]$CategoryIDs,
		[Switch]$IsInstalled,
		[Switch]$IsHidden,
		[Switch]$IsNotHidden,
		[String]$Criteria,
		[Switch]$ShowSearchCriteria,		
		
		#Post search criteria
		[String[]]$Category="",
		[String[]]$KBArticleID,
		[String]$Title,
		
		[String[]]$NotCategory="",
		[String[]]$NotKBArticleID,
		[String]$NotTitle,	
		
		[Alias("Silent")]
		[Switch]$IgnoreUserInput,
		[Switch]$IgnoreRebootRequired,
		
		#Connection options
		[String]$ServiceID,
		[Switch]$WindowsUpdate,
		[Switch]$MicrosoftUpdate,
		[Switch]$HideStatus = $true,
		
		#Mode options
		[Switch]$Debuger,
		[parameter(ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true)]
		[String[]]$ComputerName
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
	}

	Process
	{
		Write-Debug "STAGE 0: Prepare environment"
		######################################
		# Start STAGE 0: Prepare environment #
		######################################
		
		Write-Debug "Check if ComputerName in set"
		If($ComputerName -eq $null)
		{
			Write-Debug "Set ComputerName to localhost"
			[String[]]$ComputerName = $env:COMPUTERNAME
		} #End If $ComputerName -eq $null
		
		####################################			
		# End STAGE 0: Prepare environment #
		####################################
		
		$UpdateCollection = @()
		Foreach($Computer in $ComputerName)
		{
			If(Test-Connection -ComputerName $Computer -Quiet)
			{
				Write-Debug "STAGE 1: Get updates list"
				###################################
				# Start STAGE 1: Get updates list #
				###################################			

				If($Computer -eq $env:COMPUTERNAME)
				{
					Write-Debug "Create Microsoft.Update.ServiceManager object"
					$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager" #Support local instance only
					Write-Debug "Create Microsoft.Update.Session object for $Computer"
					$objSession = New-Object -ComObject "Microsoft.Update.Session" #Support local instance only
				} #End If $Computer -eq $env:COMPUTERNAME
				Else
				{
					Write-Debug "Create Microsoft.Update.Session object for $Computer"
					$objSession =  [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computer))
				} #End Else $Computer -eq $env:COMPUTERNAME
				
				Write-Debug "Create Microsoft.Update.Session.Searcher object for $Computer"
				$objSearcher = $objSession.CreateUpdateSearcher()

				If($WindowsUpdate)
				{
					Write-Debug "Set source of updates to Windows Update"
					$objSearcher.ServerSelection = 2
					$serviceName = "Windows Update"
				} #End If $WindowsUpdate
				ElseIf($MicrosoftUpdate)
				{
					Write-Debug "Set source of updates to Microsoft Update"
					$serviceName = $null
					Foreach ($objService in $objServiceManager.Services) 
					{
						If($objService.Name -eq "Microsoft Update")
						{
							$objSearcher.ServerSelection = 3
							$objSearcher.ServiceID = $objService.ServiceID
							$serviceName = $objService.Name
							Break
						}#End If $objService.Name -eq "Microsoft Update"
					}#End ForEach $objService in $objServiceManager.Services
					
					If(-not $serviceName)
					{
						Write-Warning "Can't find registered service Microsoft Update. Use Get-WUServiceManager to get registered service."
						Return
					}#Enf If -not $serviceName
				} #End Else $WindowsUpdate If $MicrosoftUpdate
				ElseIf($Computer -eq $env:COMPUTERNAME) #Support local instance only
				{
					Foreach ($objService in $objServiceManager.Services) 
					{
						If($ServiceID)
						{
							If($objService.ServiceID -eq $ServiceID)
							{
								$objSearcher.ServiceID = $ServiceID
								$objSearcher.ServerSelection = 3
								$serviceName = $objService.Name
								Break
							} #End If $objService.ServiceID -eq $ServiceID
						} #End If $ServiceID
						Else
						{
							If($objService.IsDefaultAUService -eq $True)
							{
								$serviceName = $objService.Name
								Break
							} #End If $objService.IsDefaultAUService -eq $True
						} #End Else $ServiceID
					} #End Foreach $objService in $objServiceManager.Services
				} #End Else $MicrosoftUpdate If $Computer -eq $env:COMPUTERNAME
				ElseIf($ServiceID)
				{
					$objSearcher.ServiceID = $ServiceID
					$objSearcher.ServerSelection = 3
					$serviceName = $ServiceID
				}
				Else #End Else $Computer -eq $env:COMPUTERNAME If $ServiceID
				{
					$serviceName = "default (for $Computer) Windows Update"
				} #End Else $ServiceID
				Write-Debug "Set source of updates to $serviceName"
				
				Write-Verbose "Connecting to $serviceName server. Please wait..."
				Try
				{
					$search = ""
					If($Criteria)
					{
						$search = $Criteria
					} #End If $Criteria
					Else
					{
						If($IsInstalled) 
						{
							$search = "IsInstalled = 1"
							Write-Debug "Set pre search criteria: IsInstalled = 1"
						} #End If $IsInstalled
						Else
						{
							$search = "IsInstalled = 0"	
							Write-Debug "Set pre search criteria: IsInstalled = 0"
						} #End Else $IsInstalled
						
						If($UpdateType -ne "")
						{
							Write-Debug "Set pre search criteria: Type = $UpdateType"
							$search += " and Type = '$UpdateType'"
						} #End If $UpdateType -ne ""					
						
						If($UpdateID)
						{
							Write-Debug "Set pre search criteria: UpdateID = '$([string]::join(", ", $UpdateID))'"
							$tmp = $search
							$search = ""
							$LoopCount = 0
							Foreach($ID in $UpdateID)
							{
								If($LoopCount -gt 0)
								{
									$search += " or "
								} #End If $LoopCount -gt 0
								If($RevisionNumber)
								{
									Write-Debug "Set pre search criteria: RevisionNumber = '$RevisionNumber'"	
									$search += "($tmp and UpdateID = '$ID' and RevisionNumber = $RevisionNumber)"
								} #End If $RevisionNumber
								Else
								{
									$search += "($tmp and UpdateID = '$ID')"
								} #End Else $RevisionNumber
								$LoopCount++
							} #End Foreach $ID in $UpdateID
						} #End If $UpdateID

						If($CategoryIDs)
						{
							Write-Debug "Set pre search criteria: CategoryIDs = '$([string]::join(", ", $CategoryIDs))'"
							$tmp = $search
							$search = ""
							$LoopCount =0
							Foreach($ID in $CategoryIDs)
							{
								If($LoopCount -gt 0)
								{
									$search += " or "
								} #End If $LoopCount -gt 0
								$search += "($tmp and CategoryIDs contains '$ID')"
								$LoopCount++
							} #End Foreach $ID in $CategoryIDs
						} #End If $CategoryIDs
						
						If($IsNotHidden) 
						{
							Write-Debug "Set pre search criteria: IsHidden = 0"
							$search += " and IsHidden = 0"	
						} #End If $IsNotHidden
						ElseIf($IsHidden) 
						{
							Write-Debug "Set pre search criteria: IsHidden = 1"
							$search += " and IsHidden = 1"	
						} #End ElseIf $IsHidden

						#Don't know why every update have RebootRequired=false which is not always true
						If($IgnoreRebootRequired) 
						{
							Write-Debug "Set pre search criteria: RebootRequired = 0"
							$search += " and RebootRequired = 0"	
						} #End If $IgnoreRebootRequired
					} #End Else $Criteria
					
					Write-Debug "Search criteria is: $search"
					
					If($ShowSearchCriteria)
					{
						Write-Output $search
					} #End If $ShowSearchCriteria
			
					$objResults = $objSearcher.Search($search)
				} #End Try
				Catch
				{
					If($_ -match "HRESULT: 0x80072EE2")
					{
						Write-Warning "Probably you don't have connection to Windows Update server"
					} #End If $_ -match "HRESULT: 0x80072EE2"
					Return
				} #End Catch

				$NumberOfUpdate = 1
				$PreFoundUpdatesToDownload = $objResults.Updates.count
				Write-Verbose "Found [$PreFoundUpdatesToDownload] Updates in pre search criteria"				
				
				If($PreFoundUpdatesToDownload -eq 0)
				{
					Continue
				} #End If $PreFoundUpdatesToDownload -eq 0 
				
				Foreach($Update in $objResults.Updates)
				{	
					$UpdateAccess = $true
					Write-Progress -Activity "Post search updates for $Computer" -Status "[$NumberOfUpdate/$PreFoundUpdatesToDownload] $($Update.Title) $size" -PercentComplete ([int]($NumberOfUpdate/$PreFoundUpdatesToDownload * 100))
					Write-Debug "Set post search criteria: $($Update.Title)"
					
					If($Category -ne "")
					{
						$UpdateCategories = $Update.Categories | Select-Object Name
						Write-Debug "Set post search criteria: Categories = '$([string]::join(", ", $Category))'"	
						Foreach($Cat in $Category)
						{
							If(!($UpdateCategories -match $Cat))
							{
								Write-Debug "UpdateAccess: false"
								$UpdateAccess = $false
							} #End If !($UpdateCategories -match $Cat)
							Else
							{
								$UpdateAccess = $true
								Break
							} #End Else !($UpdateCategories -match $Cat)
						} #End Foreach $Cat in $Category	
					} #End If $Category -ne ""

					If($NotCategory -ne "" -and $UpdateAccess -eq $true)
					{
						$UpdateCategories = $Update.Categories | Select-Object Name
						Write-Debug "Set post search criteria: NotCategories = '$([string]::join(", ", $NotCategory))'"	
						Foreach($Cat in $NotCategory)
						{
							If($UpdateCategories -match $Cat)
							{
								Write-Debug "UpdateAccess: false"
								$UpdateAccess = $false
								Break
							} #End If $UpdateCategories -match $Cat
						} #End Foreach $Cat in $NotCategory	
					} #End If $NotCategory -ne "" -and $UpdateAccess -eq $true					
					
					If($KBArticleID -ne $null -and $UpdateAccess -eq $true)
					{
						Write-Debug "Set post search criteria: KBArticleIDs = '$([string]::join(", ", $KBArticleID))'"
						If(!($KBArticleID -match $Update.KBArticleIDs -and "" -ne $Update.KBArticleIDs))
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If !($KBArticleID -match $Update.KBArticleIDs)								
					} #End If $KBArticleID -ne $null -and $UpdateAccess -eq $true

					If($NotKBArticleID -ne $null -and $UpdateAccess -eq $true)
					{
						Write-Debug "Set post search criteria: NotKBArticleIDs = '$([string]::join(", ", $NotKBArticleID))'"
						If($NotKBArticleID -match $Update.KBArticleIDs -and "" -ne $Update.KBArticleIDs)
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If$NotKBArticleID -match $Update.KBArticleIDs -and "" -ne $Update.KBArticleIDs					
					} #End If $NotKBArticleID -ne $null -and $UpdateAccess -eq $true
					
					If($Title -and $UpdateAccess -eq $true)
					{
						Write-Debug "Set post search criteria: Title = '$Title'"
						If($Update.Title -notmatch $Title)
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If $Update.Title -notmatch $Title
					} #End If $Title -and $UpdateAccess -eq $true

					If($NotTitle -and $UpdateAccess -eq $true)
					{
						Write-Debug "Set post search criteria: NotTitle = '$NotTitle'"
						If($Update.Title -match $NotTitle)
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If $Update.Title -notmatch $NotTitle
					} #End If $NotTitle -and $UpdateAccess -eq $true
					
					If($IgnoreUserInput -and $UpdateAccess -eq $true)
					{
						Write-Debug "Set post search criteria: CanRequestUserInput"
						If($Update.InstallationBehavior.CanRequestUserInput -eq $true)
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If $Update.InstallationBehavior.CanRequestUserInput -eq $true
					} #End If $IgnoreUserInput -and $UpdateAccess -eq $true

					If($IgnoreRebootRequired -and $UpdateAccess -eq $true) 
					{
						Write-Debug "Set post search criteria: RebootBehavior"
						If($Update.InstallationBehavior.RebootBehavior -ne 0)
						{
							Write-Debug "UpdateAccess: false"
							$UpdateAccess = $false
						} #End If $Update.InstallationBehavior.RebootBehavior -ne 0	
					} #End If $IgnoreRebootRequired -and $UpdateAccess -eq $true

					If($UpdateAccess -eq $true)
					{
						Write-Debug "Convert size"
						Switch($Update.MaxDownloadSize)
						{
							{[System.Math]::Round($_/1KB,0) -lt 1024} { $size = [String]([System.Math]::Round($_/1KB,0))+" KB"; break }
							{[System.Math]::Round($_/1MB,0) -lt 1024} { $size = [String]([System.Math]::Round($_/1MB,0))+" MB"; break }  
							{[System.Math]::Round($_/1GB,0) -lt 1024} { $size = [String]([System.Math]::Round($_/1GB,0))+" GB"; break }    
							{[System.Math]::Round($_/1TB,0) -lt 1024} { $size = [String]([System.Math]::Round($_/1TB,0))+" TB"; break }
							default { $size = $_+"B" }
						} #End Switch
					
						Write-Debug "Convert KBArticleIDs"
						If($Update.KBArticleIDs -ne "")    
						{
							$KB = "KB"+$Update.KBArticleIDs
						} #End If $Update.KBArticleIDs -ne ""
						Else 
						{
							$KB = ""
						} #End Else $Update.KBArticleIDs -ne ""
						
						if($Update.IsHidden -ne $HideStatus)
						{
							if($HideStatus)
							{
								$StatusName = "Hide"
							} #$HideStatus
							else
							{
								$StatusName = "Unhide"
							} #Else $HideStatus
							
							If($pscmdlet.ShouldProcess($Computer,"$StatusName $($Update.Title)?")) 
							{
								Try
								{
									$Update.IsHidden = $HideStatus
								}
								Catch
								{
									Write-Warning "You haven't privileges to make this. Try start an eleated Windows PowerShell console."
								}
								
							} #$pscmdlet.ShouldProcess($Computer,"Hide $($Update.Title)?")
						} #End $Update.IsHidden -ne $HideStatus
						
						$Status = ""
				        If($Update.IsDownloaded)    {$Status += "D"} else {$status += "-"}
				        If($Update.IsInstalled)     {$Status += "I"} else {$status += "-"}
				        If($Update.IsMandatory)     {$Status += "M"} else {$status += "-"}
				        If($Update.IsHidden)        {$Status += "H"} else {$status += "-"}
				        If($Update.IsUninstallable) {$Status += "U"} else {$status += "-"}
				        If($Update.IsBeta)          {$Status += "B"} else {$status += "-"} 
		
						Add-Member -InputObject $Update -MemberType NoteProperty -Name ComputerName -Value $Computer
						Add-Member -InputObject $Update -MemberType NoteProperty -Name KB -Value $KB
						Add-Member -InputObject $Update -MemberType NoteProperty -Name Size -Value $size
						Add-Member -InputObject $Update -MemberType NoteProperty -Name Status -Value $Status
					
						$Update.PSTypeNames.Clear()
						$Update.PSTypeNames.Add('PSWindowsUpdate.WUList')
						$UpdateCollection += $Update
					} #End If $UpdateAccess -eq $true
					
					$NumberOfUpdate++
				} #End Foreach $Update in $objResults.Updates				
				Write-Progress -Activity "Post search updates for $Computer" -Status "Completed" -Completed
				
				$FoundUpdatesToDownload = $UpdateCollection.count
				Write-Verbose "Found [$FoundUpdatesToDownload] Updates in post search criteria"
				
				#################################
				# End STAGE 1: Get updates list #
				#################################
				
			} #End If Test-Connection -ComputerName $Computer -Quiet
		} #End Foreach $Computer in $ComputerName

		Return $UpdateCollection
		
	} #End Process
	
	End{}		
} #In The End :)

Export-ModuleMember -Function *