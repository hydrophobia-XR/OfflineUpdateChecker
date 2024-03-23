# OfflineUpdateChecker
 This is a small script that can be used to check for Windows updates in an air-gapped network or Windows Workstation or Server that has no direct internet connection.

# DISCLAIMER:

 By using this content you agree to the following: This script may be used for legal purposes only. Users take full responsibility 
 for any actions performed using this script. The author accepts no liability for any damage caused by this script.  

# DESCRIPTION

 This script utilizes built in Windows tools and the wsusscn2.cab file provided my Microsoft here: https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates ofline to check what updates are missing on a Windows endpoint.
 The script will both display and log the available updates including: Update Name, Criticality and KB Number. 
 The signing certificate is also verified for the wsusscn2.cab file to help ensure it is valid and from Microsoft to prevent potentially malicious cab files being used. 
 Logs will be generated and added to the directory that the script is run from ex: C:\currentdirectory\logs\year\month\Results and C:\currentdirectory\logs\year\month\RunLogs

 After you have a list of missing updates you can use the Microsoft update catalog to download the patches necessary. 
 https://www.catalog.update.microsoft.com/Home.aspx

 This script can also be used with Windows' built in Task Scheduler to automate these scans and all you would have to do is update the wsusscn2.cab file.

### PARAMETER cabpath

 -cabpath {pathtocabfile}: Enter the path where you are storing the most recent wsusscn2.cab file. it's best to have this file local since it is relatively large.

### PARAMETER LogBackupPath

 -LogBackupPath {remotepathtobackuplogs}: if you want to backup your log files to a remote server for consolidation/review use this parameter

### EXAMPLE

 Open an administrator powershell terminal and either navigate to the location of the script or copy the full path to the script and run it in the powershell terminal.
 C:\Path\to\updatescript\OfflineUpdateChecker.ps1 -cabpath c:\Updates\wsusscn2.cab
 In this example logs would be created here: C:\Path\to\updatescript\Logs\2024\01\Results and C:\Path\to\updatescript\Logs\2024\01\RunLogs

### EXAMPLE

 Open an administrator powershell terminal and either navigate to the location of the script or copy the full path to the script and run it in the powershell terminal.
 C:\Updates\OfflineUpdateChecker.ps1 -cabpath c:\Updates\wsusscn2.cab -LogBackupPath \\\server01\logs\UpdateScans
 In this example logs would be created here: C:\Updates\logs\2024\01\Results\ and C:\Updates\logs\2024\01\RunLogs\
 Then logs will be backed up here: \\\server01\logs\UpdateScans\2024\01\Computername\
