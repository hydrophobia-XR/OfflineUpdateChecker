
<#
	.NOTES
    ===========================================================================
    Created on:   	12.2023
    Created by:   	Hydrophobia
    Filename:     	OfflineUpdateChecker.ps1
    Last Modified Date: 3.22.2024
    ===========================================================================

    .DISCLAIMER:
    By using this content you agree to the following: This script may be used for legal purposes only. Users take full responsibility 
    for any actions performed using this script. The author accepts no liability for any damage caused by this script.  

    .SYNOPSIS
    This Script can be used to scan for Windows updates on computers that don't have access to the internet. 

    .DESCRIPTION
    This script utilizes built in Windows tools and the wsusscn2.cab file provided my Microsoft here: 
    https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline to check what updates are missing on a Windows endpoint.
    The script will both display and log the available updates including: Update Name, Criticality and KB Number. 
    The signing certificate is also verified for the wsusscn2.cab file to help ensure it is valid and from Microsoft to prevent potentially malicious cab files being used. 
    Logs will be generated and added to the directory that the script is run from ex: C:\currentdirectory\logs\year\month\Results and C:\currentdirectory\logs\year\month\RunLogs

    After you have a list of missing updates you can use the Microsoft update catalog to download the patches necessary. 
    https://www.catalog.update.microsoft.com/Home.aspx
	
    .PARAMETER cabpath
    -cabpath {pathtocabfile}: Enter the path where you are storing the most recent wsusscn2.cab file. it's best to have this file local since it is relatively large.

    .PARAMETER LogBackupPath
    -LogBackupPath {remotepathtobackuplogs}: if you want to backup your log files to a remote server for consolidation/review use this parameter

    .EXAMPLE
    Open an administrator powershell terminal and either navigate to the location of the script or copy the full path to the script and run it in the powershell terminal.
    C:\Path\to\updatescript\OfflineUpdateChecker.ps1 -cabpath c:\Updates\wsusscn2.cab
    In this example logs would be created here: C:\Path\to\updatescript\Logs\2024\01\Results and C:\Path\to\updatescript\Logs\2024\01\RunLogs

    .EXAMPLE
    Open an administrator powershell terminal and either navigate to the location of the script or copy the full path to the script and run it in the powershell terminal.
    C:\Updates\OfflineUpdateChecker.ps1 -cabpath c:\Updates\wsusscn2.cab -LogBackupPath \\server01\logs\UpdateScans
    In this example logs would be created here: C:\Updates\logs\2024\01\Results\ and C:\Updates\logs\2024\01\RunLogs\
    Then logs will be backed up here: \\server01\logs\UpdateScans\2024\01\Computername\

    .CHANGELOG
    3.22.2024 - switched script to use parameters rather than editable variables in the script. Simplified some repetative path usage.
    1.3.2024 - Added the ability to copy logs and results to a network location
    1.3.2024 - Added additional notes and descriptions

    .TO-DO 
    Setup to allow script to auto grab the most recent wsusscn2.cab file from a network location and copy it locally.        
    Information for automating with Task Scheduler
#>

#################################### Parameters ###################################

[CmdletBinding()]
param (
	[Parameter(Mandatory)]
	[String]$CabPath,
	[Parameter()]
	[String]$LogBackupPath
)
################################# EDITABLE VARIABLES #################################
#N/A for this script
#################################### SET COMMON VARIABLES ###################################
$CertificateIssuer = "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
$User = $Env:UserName
$Computer = $Env:ComputerName
$CurrentDate = Get-Date
$global:CurrentPath = split-path -Parent $PSCommandPath
$ResultPath = $CurrentPath + "\Logs\$($CurrentDate.ToString("yyyy"))\$($CurrentDate.ToString("MM"))\Results\"
$RunPath = $CurrentPath + "\Logs\$($CurrentDate.ToString("yyyy"))\$($CurrentDate.ToString("MM"))\RunLogs\"
$logfile = $RunPath + "UpdateCheck-RunLog-$($CurrentDate.ToString("yyyy-MM-dd_HH.mm.ss")).txt"
$ResultLog = $ResultPath + "MissingUpdates-$($CurrentDate.ToString("yyyy-MM-dd_HH.mm.ss")).txt"
$sw = [Diagnostics.Stopwatch]::StartNew()

#################################### FUNCTIONS #######################################
#Function allows a detail log to be created for troubleshooting purposes and review. 
Function Write-Log{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","WARN","ERROR","FATAL","DEBUG")]
        [string]
        $level = "INFO",

        [Parameter(Mandatory=$true)]
        [string]
        $Message,

        [Parameter(Mandatory=$true)]
        [string]
        $logfile
    )
    $Stamp = (Get-Date).ToString($TimeStampFormat)
    $Line = "$Stamp | $Level | $Message"
    Add-content $logfile -Value $Line -Force
}
#Function used to verify if the CAB file is legitimately signed by microsoft
Function Get-CABSignature{
	Write-Log -level INFO -message "Verifying the cab file is signed by Microsoft with a valid signature." -logfile $logfile
    try{
        $Signature = Get-AuthenticodeSignature -FilePath $CabPath
		Write-Log -level INFO -message "Cab file signature is: $($Signature.SignerCertificate.Issuer) and status is $($Signature.Status)" -logfile $logfile
    }
    catch{
        Write-Error "Error $_ while trying to get cab signature"
		Write-Log -level ERROR -message "Error getting cab file signature: $_" -logfile $logfile
    }
    $SignatureCheck = $Signature.SignerCertificate.Issuer -eq $CertificateIssuer -and $Signature.Status -eq "Valid"
    if(!$SignatureCheck){
        Write-Warning "File signature of $CabPath file is invalid. This may mean it is malicious, Please verify it was downloaded from microsoft before use."
		Write-Log -level WARN -message "File signature of $CabPath file is invalid. This may mean it is malicious, Please verify it was downloaded from microsoft before use." -logfile $logfile
        exit
    }
    if($SignatureCheck){
        Write-Output "File signature of $CabPath file is verified as: Valid"
		Write-Log -level INFO -message "File signature of $CabPath file is verified as: Valid" -logfile $logfile

    }
}

Function Get-MissingUpdates{
    #Create Update Session
    Write-Log -level INFO -message "Creating Update Session" -logfile $logfile
    $UpdatesSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service",$CabPath, 1)
    #Creating Windows Update Searcher
    Write-Log -level INFO -message "Creating Windows Update Searcher" -logfile $logfile
    $UpdateSearcher = $UpdatesSession.CreateUpdateSearcher()
    $UpdateSearcher.ServerSelection = 3
    $UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString()
    #Check for missing updates on the system
    Write-Warning "Checking for updates, please be patient this may take a while..."
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
	Write-Log -level INFO -message "Update scan started..." -logfile $logfile
    $Updates = $SearchResult.updates
    Write-Output "$($Updates.Count) updates missing on $Computer : Run Date $CurrentDate" | Tee-Object -FilePath $ResultLog -Append
	Write-Log -level INFO -message "$($Updates.Count) updates missing on $Computer : Run Date $CurrentDate" -logfile $logfile
	#Getting relavant info and outputting to run log, terminal, and results log
    Foreach($update in $Updates){
		Write-Log -level INFO -message "$($update | Select-Object Title, MsrcSeverity, @{ Name = "KBArticleIDs"; Expression = { $_.KBArticleIDs } })" -logfile $logfile
	}
    Write-Output $($Updates | Select-Object Title,MsrcSeverity, @{Name="KBArticleIDs";Expression={$_.KBArticleIDs}} | Format-Table -Property @{Name="Title";Expression={$_.Title};Width=70},MsrcSeverity, @{Name="KBArticleIDs";Expression={$_.KBArticleIDs}} -Wrap) | Tee-Object -FilePath $ResultLog -Append  
}

#Creates necessary log folders and path if they do not already exist to allow for logs to be created. 
Function Set-LogFolders {
    ##Tests for and creates necessary folders and files for the script to run and log appropriately
    $global:LogFolder = $CurrentPath + "\Logs\"
    if (!(Test-Path $LogFolder)) {
        Write-Output "$LogFolder \Logs does not exist, creating path"
        New-Item -Path $LogFolder -ItemType "directory" | out-null
        if (Test-Path $LogFolder){
            Write-Output "$LogFolder created successfully"
        }
        else {
            Write-Output "Error creating path: $LogFolder maybe try manual creation?"
        }
    }
    if (!(Test-Path "$RunPath")) {
		New-Item -Path "$RunPath" -ItemType "directory" | out-null
    }
    if (!(Test-Path $ResultPath)) {
		New-Item -Path $ResultPath -ItemType "directory" | out-null
    }
}
#################################### EXECUTION #####################################

Set-LogFolders

Write-Log -level INFO -message "Windows update checks ran by $User on $Computer" -logfile $logfile

Get-CABSignature

Get-MissingUpdates

$sw.stop()
Write-Output "Total time to check for updates $($sw.elapsed)"
Write-Log -level INFO -message "Total time to check for updates $($sw.elapsed)." -logfile $logfile

If ($LogBackupPath){
	$LogBackupPath = $LogBackupPath + "\$($CurrentDate.ToString("yyyy"))\$($CurrentDate.ToString("MM"))\$Computer\"
	robocopy /E /R:2 /W:10 /V /NDL /NFL "$CurrentPath\Logs\$($CurrentDate.ToString("yyyy"))\$($CurrentDate.ToString("MM"))\"* $LogBackupPath | Out-Null
}
