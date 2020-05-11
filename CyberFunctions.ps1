<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberFunctions
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Helper Functions
#>

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

#Split-File C:\CyberAuditPS2020\Downloads\Nessus-8.10.0-x64.msi -PartSizeBytes 25MB
#Join-File 

function screenshot ()
{
    $null = New-Item -Path "$AcqBaseFolder\Screenshots" -ItemType Directory -Force
    $timestamp = UniversalTimeStamp
    [void][reflection.assembly]::loadwithpartialname("system.windows.forms")
    [system.windows.forms.sendkeys]::sendwait('{PRTSC}')
    Get-Clipboard -Format Image | ForEach-Object -MemberName Save -ArgumentList "$AcqBaseFolder\Screenshots\capture-$timestamp.png"
}

#get installed application path from application name 
#example: GetAppInstallPath(nessus")
function GetAppInstallPath ($appName)
{
    Write-Host "Looking for $appName installation path, please wait..."
    $loc = Get-WmiObject -Class Win32_Product -Filter "Name like '%$appName%'" | Select InstallLocation
    $locloc = $loc.InstallLocation
    success "$appName is Installed in: $locloc" 
    return $locloc
}

#write success/failed messages in green/red
function success ($msg)
{
    $null = Write-Host "[Success] $msg" -ForegroundColor Green
}

function failed ($msg)
{
    $null = Write-Host "[Failed] $msg" -ForegroundColor Red
}


#kill applications that runs under another process like excell document, java applications and more
#example: KillApp("Javaw","Scuba")
function killApp($ProcessName,$WindowTitle){
    try{
        $c = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -Property id,MainWindowTitle
        foreach($a in $c) {
            if($a.MainWindowTitle.Contains($WindowTitle)) 
            {
            kill $a.Id
            }
         }
     }
     catch
         {
            throw
            return
         }
}

#check if RSAT is installed
function checkRsat {
    If ((Get-Module -Name ActiveDirectory -ListAvailable) -ne $null) 
    {
        Write-Host "[Success] Rsat in installed" -ForegroundColor Green
        Return $true
    } 
    else 
    {
        Write-Host "[Failures] Rsat in  not installed" -ForegroundColor red
        return $false
    }
}

function UniversalTimeStamp
{
 return ((get-date).ToUniversalTime()).ToString("yyyyMMddThhmmssZ")
}

function CurrentDate{
      return (Get-Date -Format 'dd-MM-yyyy')
}

function Get-UserAgent() {
    return "CyberAuditTool/1.0 (+http://cyberaudittool.c1.biz/) PowerShell/$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) (Windows NT $([System.Environment]::OSVersion.Version.Major).$([System.Environment]::OSVersion.Version.Minor); $(if($env:PROCESSOR_ARCHITECTURE -eq 'AMD64'){'Win64; x64; '})$(if($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64'){'WOW64; '})$PSEdition)"
}

#check if machine is part of domain
function CheckMachineRole
     {
        [int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
         $systemRoles = @{
                              0         =    "Standalone Workstation    " ;
                              1         =    "Member Workstation        " ;
                              2         =    "Standalone Server         " ;
                              3         =    "Member Server             " ;
                              4         =    "Backup  Domain Controller " ;
                              5         =    "Primary Domain Controller "       
         }

        if($systemRoleID -eq 0){   
                write-host "[Failure] some features need access to a domain, connect this machine to the organization domain" -ForegroundColor Red
                return $false
        }
        else
        {
            write-host "[Success] This machine role is: " $systemRoles[[int]$systemRoleID] -ForegroundColor Green
            return $true
        }
    }

function fname($path) { split-path $path -leaf }
function strip_ext($fname) { $fname -replace '\.[^\.]*$', '' }
function strip_filename($path) { $path -replace [regex]::escape((fname $path)) }
function strip_fragment($url) { $url -replace (new-object uri $url).fragment }
function url_filename($url) {
    (split-path $url -leaf).split('?') | Select-Object -First 1
}

function dl($url,$to) {
    $wc = New-Object Net.Webclient
    $wc.headers.add('Referer', (strip_filename $url))
    $wc.Headers.Add('User-Agent', (Get-UserAgent))
    $wc.downloadFile($url,$to)
}

#Set Script directory tree variables
$Tools = "$PSScriptRoot\Tools"
$scoopDir = "$Tools\Scoop"
$scoopGlobalDir = "$Tools\GlobalScoopApps"
$SVNDir = "$Tools\SVN"
$PowerShellsDir = "$Tools\PowerShells"
$DownloadsDir = "$Tools\Downloads"
$bucketsDir = "$scoopDir\buckets"
$appsDir = "$scoopGlobalDir\apps"

#locate a scoop application directory
function appDir ($appName){
    $c = scoop prefix $appName
    Write-Host "[Success] Setting directory to $c" -ForegroundColor Green
    Return $c
}

function YesNo ($FirstName, $LastName) {
    $d = [Windows.Forms.MessageBox]::show($FirstName,$LastName,[Windows.Forms.MessageBoxButtons]::YesNo, [Windows.Forms.MessageBoxIcon]::Question)
    If ($d -eq [Windows.Forms.DialogResult]::Yes)
    {
        return $true
    }
    else
    {
        return $false
    }
}

#Set Acquisition folders
$AcqBaseFolder = New-Item -Path $PSScriptRoot -Name $env:computername -ItemType "directory" -Force

Function ACQ{
    Param ($dir)
    $ACQdir = New-Item -Path $AcqBaseFolder -Name $dir -ItemType "directory" -Force
    Write-Host "$dir Aquisition folder is: $ACQdir" -ForegroundColor Yellow
    Return $ACQdir.FullName
}

#Set GUI
$Host.UI.RawUI.BackgroundColor = ($bckgrnd = "Black")
$Host.UI.RawUI.ForegroundColor = "White"
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - functions"
$BufferSize = $Host.UI.RawUI.BufferSize
$BufferSize.Height = 500
$Host.UI.RawUI.BufferSize = $BufferSize
#$WindowSize = $host.UI.RawUI.WindowSize
#$WindowSize.Height = 45
#$host.UI.RawUI.WindowSize = $WindowSize


Function Get-Folder($initialDirectory) {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.RootFolder = 'MyComputer'
    if ($initialDirectory) { $FolderBrowserDialog.SelectedPath = $initialDirectory }
    $Topmost = New-Object System.Windows.Forms.Form
    $Topmost.TopMost = $True
    $Topmost.MinimizeBox = $True
    [void] $FolderBrowserDialog.ShowDialog($Topmost) 
    return $FolderBrowserDialog.SelectedPath
}


function Get-FileName
{  
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.filter = "All files (*.*)| *.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

function SelfElevte(){
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
     if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
      $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
      Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
      Exit
     }
    }
}

function checkAdmin {
    $admin = [security.principal.windowsbuiltinrole]::administrator
    $id = [security.principal.windowsidentity]::getcurrent()
    ([security.principal.windowsprincipal]($id)).isinrole($admin)
}


function CyberBginfo () {
    . $PSScriptRoot\Bginfo64.exe $PSScriptRoot\CyberBginfo.bgi /silent /accepteula /timer:0
} 


function ShowINCD() {
$incd = @"                                                                        
                         ..,co88oc.oo8888cc,..
  o8o.               ..,o8889689ooo888o"88888888oooc..
.88888             .o888896888".88888888o'?888888888889ooo....
a888P          ..c6888969""..,"o888888888o.?8888888888"".ooo8888oo.
088P        ..atc88889"".,oo8o.86888888888o 88988889",o888888888888.
888t  ...coo688889"'.ooo88o88b.'86988988889 8688888'o8888896989^888o
 888888888888"..ooo888968888888  "9o688888' "888988 8888868888'o88888
  ""G8889""'ooo888888888888889 .d8o9889""'   "8688o."88888988"o888888o .
           o8888'""""""""""'   o8688"          88868. 888888.68988888"o8o.
           88888o.              "8888ooo.        '8888. 88888.8898888o"888o.
           "888888'               "888888'          '""8o"8888.8869888oo8888o .
      . :.:::::::::::.: .     . :.::::::::.: .   . : ::.:."8888 "888888888888o
                                                        :..8888,. "88888888888.
                                                        .:o888.o8o.  "866o9888o
                                                         :888.o8888.  "88."89".
                                                        . 89  888888    "88":.
                   CyberAuditTool [CAT]                 :.     '8888o
                 Israel Cyber Directorate                .       "8888..
                   Prime Ministers Office                          888888o.
                     V1.0 (08-03-2020)                              "888889,
                                                             . : :.:::::::.: :.

"@
Write-Host $incd -ForegroundColor Green
}

#Disable Firewall,Defender real time
function DisableFirewall(){
    Write-Host ("**************************************************************************************") -ForegroundColor green
    Write-Host ("We will try now to disable the local firewall protection profiles")
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    write-host (Get-NetFirewallProfile | Select-Object name,enabled )
    Write-Host ("**************************************************************************************") -ForegroundColor green
}

#Locate AntiMalware product and try to stop realtime protection

function DisableAntimalware(){
    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct 
    Write-Host ("You are running [" + ($AntiVirusProduct | measure).Count + "] antivirus realtime protection solutions:") -ForegroundColor green
    write-host ($AntiVirusProduct | % $_ {write-host "-->" $_.displayname  -ForegroundColor Green})
    $WinEdition = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName .).caption
    if (!$WinEdition.Contains("HOME") -or !$WinEdition.Contains("Education")) {
        $AntiVirusName = $AntiVirusProduct.DisplayName
        if($AntiVirusName -match "Windows Defender" -AND (Get-Service -name "sense").Status -cnotmatch "Stopped") 
        {
            Write-Host ("We will try to disable Windows Defender real time protection") -ForegroundColor red
            Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
        }
        elseif ($AntiVirusName -notmatch "Windows Defender") {
            $note = @"
            *****************************************************************
            Read this before continuing with using this software:

            In order to install and run some scripts such as sharphound
            which is safe but can be used also as malicious by hackers
            all antivirus & antimalware real time scanning should be stopped.
            *****************************************************************

"@
            Write-Host $note -ForegroundColor Yellow
            write-host ($AntiVirusName + "--> Real time scanning should be stopped") -ForegroundColor Red                
        }
    }
    else {
        $note = @"
     ********************************************************************
        Read this before continuing with using this software:

     1. In order to install and run some scripts such as sharphound
        which is safe but can be used also as malicious by hackers
        all antivirus & antimalware real time scanning should be stopped.
        
     2. Your computer is running $WinEdition Edition 
        In order to be able to connect to Domain Server during audit
        you must upgrade to either Windows 10 Pro or Enterprise Editions.
     ********************************************************************

"@
        Write-Host $note -ForegroundColor Yellow
    }
} 


function pro {notepad $profile}
function gg {git add .;git commit -m "new app";git push}
function scc($URL) {scoop create $URL;notepad (Get-ChildItem . -Recurse  -Filter *.json | Sort-Object -Property LastWriteTime -Descending | select -First 1).name}
function sci($appname) {scoop install $appname -g}
function scu($appname) {scoop uninstall (($appname -replace '.json') -replace '.\\') -g}
function scs {scoop uninstall scoop}
function ss($path,$pattern){Select-String -Path $path -Pattern $pattern}

#Outputting ordinal numbers (1st, 2nd, 3rd)
# 1,2,3 | OrdinalNumber --> 1st,2nd,3rd
function OrdinalNumber() {
    process{"$_$(switch -r($_){"(?<!1)1$"{'st'}"(?<!1)2$"{'nd'}"(?<!1)3$"{'rd'}default{'th'}})"}
    }

#Check that power cli is installed and configure credentials for connecting to Vsphere
function checkPowerCLI () {            
            Write-Host "Check that VMWARE Power CLI is installed on your machine"
            try {
                Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false

                if (Get-Module -Name VMware.PowerCLI -ListAvailable)
                 {
                    Write-Host ""
                    Write-Host "*** VMWARE Power CLI is installed, Great you can continue now ***" -ForegroundColor Green
                 }
                else 
                {
                    Write-Host ""
                    Write-Host "*** VMWARE Power CLI is not installed, Please try again ***" -ForegroundColor Red
                }
            }
            catch
            {
            Write-Host "There was a problem importing VMWARE Power CLI, please try again" -ForegroundColor Red
            }
}

#Powershell minimal version is 5.1 (needs to be manually installed on windows 7,8,sever2012/R2)
function CheckPowershell()
{
        $psver = (get-host).Version.Major.ToString() + "." + (Get-Host).Version.Minor.ToString()
        if ($psver -ge 5.1)
        {
            write-host "Powershell version is OK" -ForegroundColor Green
        }
        else
        {
            write-host "Powershell version is less than 5.1, please upgrade manually" -ForegroundColor Red
            Write-Host "https://www.microsoft.com/en-us/download/details.aspx?id=54616"
            start-process "https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        }
}

#Checks if DotNet 3.5 is installed and also if latest 4.8 is installed
function CheckDotNet()
{
        try
        {
            $ScoopInstalled = $null
            $ScoopInstalled = scoop
            $dotNet = detect.ps1
        }
        catch 
        {
            if (-not (test-path "C:\Temp")) {mkdir "C:\Temp" }
            Invoke-WebRequest "https://github.com/peterM/Net_Framework_Installed_Versions_Getter/archive/master.zip" -OutFile "C:\Temp\DotNetDetect.zip"
            Expand-Archive c:\Temp\dotnetdetect.zip -DestinationPath C:\Temp -Force
            $dotNet = C:\Temp\Net_Framework_Installed_Versions_Getter-master\Source\detect.ps1
        }
        foreach ($dotnetVer in $dotNet)
        {
            if ($dotnetVer -ne "=> Installed .Net Framework 3.5") 
                {
                    Write-Host $dotnetVer
                }
            else
                {
                    Write-Host "Great, You have DotNet 3.5 which is needed for some of the tools" -ForegroundColor Gree
                    $DotNet35Installed = "true"
                }
        }
            if (!$DotNet35Installed)
            { 
                Write-Host "Attention, You need to install DotNet 3.5 as well as latest .Net version" -ForegroundColor Red
                write-host "Enable the .NET Framework 3.5 in Control Panel --> Turn Windows features on or off" -ForegroundColor Red
            }
        
        $latest = 
        $update = Read-Host "Press [I] if you want to Install .Net version 4.8 (Or Enter to continue)"
        if ($update -eq "I")
        {
            C:\Temp\Net_Framework_Installed_Versions_Getter-master\Source\detect.ps1 c:\Temp\ -requestVersion 12
        }
}

#Clean the Scoop environment variables from Path,GIT_SSH,SCOOP_GLOBAL,SCOOP,GIT_INSTALL_ROOT,JAVA_HOME,PSModulePath
function ScoopCleanEnv(){
    
    Get-ChildItem env: |  ? value -Match "scoop"

    #variables that can be deleted
    $delVars = @("SCOOP","SCOOP_GLOBAL","GIT_INSTALL_ROOT","GIT_SSH")
    foreach ($delVar in $delVars) {
        Write-Host "Deleting [$delVar] from Environment Variables" -ForegroundColor Green
        #[Environment]::SetEnvironmentVariable($delVar,$null,"USER")
        #[Environment]::SetEnvironmentVariable($delVar,$null,"MACHINE")
    }

    #Variables that needs to remove scoop from their paths
    $remVars = @("Path","JAVA_HOME","PSModulePath")
    foreach ($remVar in $remVars) {
        if ([System.Environment]::GetEnvironmentVariable($remVar,'USER') -match "Scoop") {
                $PathsUser = [System.Environment]::GetEnvironmentVariable($remVar,'USER').split(";")
            }
        if ([System.Environment]::GetEnvironmentVariable($remVar,'MACHINE') -match "Scoop") {
            $PathsMachine = [System.Environment]::GetEnvironmentVariable($remVar,'MACHINE').split(";")
            }
        $cleanPathsUser = $null
        $cleanPathsMachine = $null
        
        foreach ($path in $PathsUser) {
            if (!$path.Contains("Scoop"))
                {
                $cleanPathsUser += "$Path;"
                }    
             }

        foreach ($path in $PathsMachine) {
            if (!$path.Contains("Scoop"))
                {
                $cleanPathsMachine += "$Path;"
                }
        }
       
       if ($cleanPathsUser -match ";") { $cleanPathsUser = $cleanPathsUser.Replace(";;",";") }
       if ($cleanPathsMachine -match ";") { $cleanPathsMachine = $cleanPathsMachine.Replace(";;",";") }
       Write-Host "$remVar [User] = $cleanPathsUser" -ForegroundColor Yellow   
       Write-Host "$remVar [Machine] = $cleanPathsMachine" -ForegroundColor Yellow
       #[Environment]::SetEnvironmentVariable($remVar,$cleanPathsUser,"USER")
       #[Environment]::SetEnvironmentVariable($remVar,$cleanPathsMachine,"MACHINE")
  }

    if(Get-ChildItem env: |  ? value -Match "scoop") {
        Write-Host ""
        Write-Host "Cleaning the Environment Variables failed, Please try manually" -ForegroundColor Red
    }
    else {
        Write-Host ""
        Write-Host "Cleaning the Environment Variables was successfull" -ForegroundColor Green
    }
}

#Create elevated shprtcuts with icons
Function CreateShortcut
{
    [CmdletBinding()]
    param (	
	    [parameter(Mandatory=$true)]
	    [ValidateScript( {[IO.File]::Exists($_)} )]
	    [System.IO.FileInfo] $Target,
	
	    [ValidateScript( {[IO.Directory]::Exists($_)} )]
	    [System.IO.DirectoryInfo] $OutputDirectory,
	
	    [string] $Name,
	    [string] $Description,
	
	    [string] $Arguments,
	    [System.IO.DirectoryInfo] $WorkingDirectory,
	
	    [string] $HotKey,
	    [int] $WindowStyle = 1,
	    [string] $IconLocation,
	    [switch] $Elevated
    )

    try {
	    #region Create Shortcut
	    if ($Name) {
		    [System.IO.FileInfo] $LinkFileName = [System.IO.Path]::ChangeExtension($Name, "lnk")
	    } else {
		    [System.IO.FileInfo] $LinkFileName = [System.IO.Path]::ChangeExtension($Target.Name.ToString(), "lnk")
	    }
	
	    if ($OutputDirectory) {
		    [System.IO.FileInfo] $LinkFile = [IO.Path]::Combine($OutputDirectory, $LinkFileName)
	    } else {
		    [System.IO.FileInfo] $LinkFile = [IO.Path]::Combine($Target.Directory.ToString(), $LinkFileName)
	    }
       
	    $wshshell = New-Object -ComObject WScript.Shell
	    $shortCut = $wshShell.CreateShortCut($LinkFile) 
	    $shortCut.TargetPath = $Target.ToString()
	    $shortCut.WindowStyle = $WindowStyle
	    $shortCut.Description = $Description
	    $shortCut.WorkingDirectory = $WorkingDirectory
	    $shortCut.HotKey = $HotKey
	    $shortCut.Arguments = $Arguments
	    if ($IconLocation) {
		    $shortCut.IconLocation = $IconLocation
	    }
	    $shortCut.Save()
	    #endregion

	    #region Elevation Flag
	    if ($Elevated) {
		    $tempFileName = [IO.Path]::GetRandomFileName()
		    $tempFile = [IO.FileInfo][IO.Path]::Combine($LinkFile.Directory, $tempFileName)
		
		    $writer = new-object System.IO.FileStream $tempFile, ([System.IO.FileMode]::Create)
		    $reader = $LinkFile.OpenRead()
		
		    while ($reader.Position -lt $reader.Length)
		    {		
			    $byte = $reader.ReadByte()
			    if ($reader.Position -eq 22) {
				    $byte = 34
			    }
			    $writer.WriteByte($byte)
		    }
		
		    $reader.Close()
		    $writer.Close()
		
		    $LinkFile.Delete()
		
		    Rename-Item -Path $tempFile -NewName $LinkFile.Name
	    }
	    #endregion
    } catch {
	    Write-Error "Failed to create shortcut. The error was '$_'."
	    return $null
    }
    return $LinkFile
}

function proxydetect
{
    <#
        .DESCRIPTION
        Checks, if a proxy is active. Uses current users credentials for Proxy Access / other user input is possible as well.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>    
    #Proxy Detect #1

    Write-Host -ForegroundColor Yellow 'Searching for network proxy...'

    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $env:COMPUTERNAME)
    $regkey2 = $reg2.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")

    if ($regkey2.GetValue('ProxyServer') -and $regkey2.GetValue('ProxyEnable'))
    {
        $proxy = Read-Host -Prompt 'Proxy detected! Proxy is: '$regkey2.GetValue('ProxyServer')'! Does the Powershell-User have proxy rights? (yes/no)'
        if ($proxy -eq "yes" -or $proxy -eq "y" -or $proxy -eq "Yes" -or $proxy -eq "Y")
        {
             #Proxy
            Write-Host -ForegroundColor Yellow 'Setting up Powershell-Session Proxy Credentials...'
            $Wcl = new-object System.Net.WebClient
            $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Please enter valid credentials, or the script will fail!'
            #Proxy Integration manual user
            $webclient=New-Object System.Net.WebClient
            $creds=Get-Credential
            $webclient.Proxy.Credentials=$creds
        }
   }
    else {Write-Host -ForegroundColor Yellow 'No proxy detected, continuing... '}
}

function TempDir
{
 if(!(Test-Path -Path C:\temp\))
 {
    mkdir C:\temp
 }
}

function DomainComputersToFile 
{
    $i = 0
    Remove-Item -Path $AcqBaseFolder\DomainComputers.txt -ErrorAction SilentlyContinue
    $ADcomputers = Get-ADComputer -Filter * | Select-Object name
    foreach ($comp in $ADcomputers)
    {
        if (Test-Connection -ComputerName $comp.name -Count 1 -TimeToLive 20 -ErrorAction Continue)
        {
            $compname = $comp.name
            success "$compname is alive"
            Add-Content -Path $AcqBaseFolder\DomainComputers.txt -Value $compname -Force
            $i++
        }
    }
    success "$AcqBaseFolder\DomainComputers.txt includes $i machines"
}

#Gets the current active IP-Address configuration
function Get-currentIP
{
    $IPaddress = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}
    return $IPaddress
}


#sets required python version to 2.x or 3.x
#example:  SetPythonVersion "2"
function SetPythonVersion ($version)
{
    $pyVer = (python --version) -match "python 3"
    if ($pyVer)
    {
        if ($version -eq "2")
        {
            scoop reset python27
            success "Python version 3.x changed to 2.x"
        }
        else
        {
            success "Current python version is 3.x"
        }
    }
    else
    {
      if ($version -eq "3")
        {
            scoop reset python37
            success "Python version 2.x changed to 3.x"
        }
            else
        {
            success "Current python version is 2.x"
        }
    }
}

function Get-IPrange
{
<# 
  .SYNOPSIS  
    Get the IP addresses in a range 
  .EXAMPLE 
   Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
  .EXAMPLE 
   Get-IPrange -ip 192.168.8.3 -cidr 24 
#> 
 
    param 
    ( 
        [string]$start, 
        [string]$end, 
        [string]$ip, 
        [string]$mask, 
        [int]$cidr 
    ) 
 
    function IP-toINT64 () { 
        param ($ip) 
 
        $octets = $ip.split(".") 
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
    } 
 
    function INT64-toIP() { 
        param ([int64]$int) 

        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    } 
 
    if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
    if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
    if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
    if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
    if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
    if ($ip) { 
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
    } else { 
        $startaddr = IP-toINT64 -ip $start 
        $endaddr = IP-toINT64 -ip $end 
    } 
 
 
    for ($i = $startaddr; $i -le $endaddr; $i++) 
    { 
        INT64-toIP -int $i 
    }

}