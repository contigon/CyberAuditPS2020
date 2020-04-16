<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberMenu
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Build
#>

. $PSScriptRoot\CyberFunctions.ps1
#ShowIncd
CyberBginfo
DisableFirewall
DisableAntimalware
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - build"

#Checkpoint-Computer -Description 'before installing CyberAuditTool'

#Create or Set the Script directory tree
$scoopDir = New-Item -Path $Tools -Name "\Scoop" -ItemType "directory" -Force
$SVNDir = New-Item -Path $Tools -Name "\SVN" -ItemType "directory" -Force
$PowerShellsDir = New-Item -Path $Tools -Name "\PowerShells" -ItemType "directory" -Force
$DownloadsDir = New-Item -Path $Tools -Name "\Downloads" -ItemType "directory" -Force

#Powershell Modules, Utilities and Applications that needs to be installed
$PSGModules = @("Testimo","VMware.PowerCLI","ImportExcel","Posh-SSH")
$utilities = @("Net_Framework_Installed_Versions_Getter","oraclejdk","putty","winscp","nmap","rclone","everything","notepadplusplus","googlechrome","firefox","foxit-reader","irfanview","grepwin","sysinternals","wireshark")
$CollectorApps = @("ntdsaudit","RemoteExecutionEnablerforPowerShell","PingCastle","goddi","SharpHound","Red-Team-Scripts","Scuba-Windows","azscan3","LGPO","grouper2","Outflank-Dumpert")
$AnalyzerApps = @("PolicyAnalyzer","BloodHoundExampleDB","BloodHoundAD","neo4j","ophcrack","vista_proba_free")
$GPOBaselines = @("Windows10Version1507SecurityBaseline.json","Windows10Version1511SecurityBaseline.json","Windows10Version1607andWindowsServer2016SecurityBaseline.json","Windows10Version1703SecurityBaseline.json","Windows10Version1709SecurityBaseline.json","Windows10Version1803SecurityBaseline.json","Windows10Version1809andWindowsServer2019SecurityBaseline.json","Windows10Version1903andWindowsServerVersion1903SecurityBaseline-Sept2019Update.json","Windows10Version1909andWindowsServerVersion1909SecurityBaseline.json","WindowsServer2012R2SecurityBaseline.json")
$AttackApps = @("nirlauncher", "ruler")

#Creating desktop shortcuts
if ((Test-Path -Path "C:\Users\Public\Desktop\Build.lnk","C:\Users\Public\Desktop\Audit.lnk","C:\Users\Public\Desktop\Analyze.lnk") -match "False")
{
    Write-Host "[Success] Creating desktop shorcuts for cyberAuditTool modules" -ForegroundColor Green
    $null = CreateShortcut -name "Build" -Target "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Arguments "-ExecutionPolicy Unrestricted -File $PSScriptroot\cyberBuild.ps1" -OutputDirectory "C:\Users\Public\Desktop" -IconLocation "$PSScriptroot\CyberBlackIcon.ico" -Description "CyberAuditTool Powershell Edition" -Elevated True
    $null = CreateShortcut -name "Audit" -Target "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Arguments "-ExecutionPolicy Unrestricted -File $PSScriptroot\CyberAudit.ps1" -OutputDirectory "C:\Users\Public\Desktop" -IconLocation "$PSScriptroot\CyberRedIcon.ico" -Description "CyberAuditTool Powershell Edition" -Elevated True
    $null = CreateShortcut -name "Analyze" -Target "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -Arguments "-ExecutionPolicy Unrestricted -File $PSScriptroot\cyberAnalyzers.ps1" -OutputDirectory "C:\Users\Public\Desktop" -IconLocation "$PSScriptroot\CyberGreenIcon.ico" -Description "CyberAuditTool Powershell Edition" -Elevated True
}

read-host “Press ENTER to continue (or Ctrl+C to quit)”

start-Transcript -path $PSScriptRoot\CyberBuildPhase.Log -Force -append

cls

$menuColor  = New-Object System.Collections.ArrayList
for ($i = 1; $i -lt 12;$i++) {
        $null = $menuColor.Add("White")

    }


do {
#Create the main menu
Write-Host ""
Write-Host "************************************************************************          " -ForegroundColor White
Write-Host "*** Cyber Audit Tool (Powershell Edition) - ISRAEL CYBER DIRECTORATE ***          " -ForegroundColor White
Write-Host "************************************************************************          " -ForegroundColor White
Write-Host ""
Write-Host "     Build The Application:                                                       " -ForegroundColor White
Write-Host ""
Write-Host "     1. OS		| Check Windows version and upgrade it to latest build and update " -ForegroundColor $menuColor[1]
Write-Host "     2. PS and .Net	| Check and Update Powershell and .Net framework versions     " -ForegroundColor $menuColor[2]
Write-Host "     3. RSAT		| Install Microsoft Remote Server Administration Tool         " -ForegroundColor $menuColor[3]
Write-Host "     4. PSGallery	| Install PowerShell Modules from Powershell gallery          " -ForegroundColor $menuColor[4]
Write-Host "     5. Scoop		| Install Scoop framework                                     " -ForegroundColor $menuColor[5]
Write-Host "     6. Utilities	| Install Buckets and utilities Applications                  " -ForegroundColor $menuColor[6]
Write-Host "     7. Collectors	| Install Collector Applications                              " -ForegroundColor $menuColor[7]
Write-Host "     8. Analyzers	| Install Analyzers and Reporting tools                       " -ForegroundColor $menuColor[8]
Write-Host "     9. Update   	| Update scoop applications and powershell modules            " -ForegroundColor $menuColor[9]
Write-Host "    10. Licenses   	| Install or Create licenses to/from license files            " -ForegroundColor $menuColor[10]
Write-Host "    11. Uninstall  	| Uninstall scoop applications and powershell modules         " -ForegroundColor White
Write-Host "    12. Attack!  	| Install attacking and Exploiting Scripts and tools          " -ForegroundColor White
Write-Host ""
Write-Host "    99. Quit                                                                      " -ForegroundColor White
Write-Host ""
$input=Read-Host "Select Script Number"

switch ($input) 
{ 
    
     #Check Windows OS and build versions and if needed it can help upgrade an update latest build
     1{
        $menuColor[1] = "Yellow"
        if (!(test-connection 8.8.8.8 -Count 1 -Quiet)) 
            {
        Write-Host "Internet is down, Please connect and try again" -ForegroundColor Red
            } 
        else 
            {
            Write-Host "Internet is up, you can continue with installation" -ForegroundColor Green
            }
        if (([System.Environment]::OSVersion.Version.Major -lt 10))
            {
            write-host "CyberAuditTool requires Windows 10 or later Operating systems, your system does not qualify with that, please upgrade the OS before continuing" -ForegroundColor Red
            } 
        else 
            {
            write-host "Operating System Version is OK so we now test Build number" -ForegroundColor Green
            }
        if (((Get-WmiObject -class Win32_OperatingSystem).Version -lt "10.0.17763"))
            {
            write-host "Minimal Windows 10 build version was not detected, please upgrade the OS before continuing" -ForegroundColor Red
            } 
            else
            {
            write-host "OS build version is OK, you can continue installation without upgrade" -ForegroundColor Green
            }
        $update = Read-Host "Press U to update windows (Or Enter to continue without upgrading)"
        if ($update -eq "U")
        {
            Install-Module -Name PSWindowsUpdate
            Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7
            Get-WUInstall -AcceptAll –IgnoreReboot
        }
      read-host “Press ENTER to continue”
      }
    
     #Check Powershell and .Net versions and install if needed
     2{
        $menuColor[2] = "Yellow"
        CheckPowershell
        CheckDotNet
      read-host “Press ENTER to continue”
      }
    
     #Install RSAT
     3 {
        $menuColor[3] = "Yellow"
        $RSATinstalled = Get-WindowsCapability -online | ? Name -like Rsat* | ? state -eq installed
        if ($RSATinstalled.Count -lt 21)
        {
            Get-WindowsCapability -online | ? Name -like Rsat* | FT
            Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability  -Online
        }
        else
        {
            Write-Host "All Windows RSAT (Remote Server Administration tools) modules are already installed" -ForegroundColor Green
        }
     read-host “Press ENTER to continue”
     }
    
     #Install PowerShell Modules from PSGallery Online
     4 {
        $menuColor[4] = "Yellow"
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-PackageProvider Nuget -Force
        Install-Module –Name PowerShellGet –Force -AllowClobber
        foreach ($PSGModule in $PSGModules)
        {
            If ((Get-Module $PSGModule) -eq $null)
             {
                Try
	            {
                    Get-InstalledModule -Name $PSGModule
                    Install-Module -Name $PSGModule -AllowClobber -Force     
                    Import-Module $PSGModule    
                }
                Catch
	            {
                    Write-Host "$PSGModule To Load" -ForegroundColor Red
                }
             }
            else
            {
                Write-Host "$PSGModule is already installed" -ForegroundColor Green
            }
        }
     read-host “Press ENTER to continue”
     }
    
     #Install scoop
     5 {
        $menuColor[5] = "Yellow"
        Write-Host "Backing up Environment Variables before installing scoop"
        regedit /e $PSScriptRoot\HKEY_CURRENT_USER.reg "HKEY_CURRENT_USER\Environment"
        regedit /e $PSScriptRoot\HKEY_LOCAL_MACHINE.reg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $env:SCOOP_GLOBAL = "$tools\GlobalScoopApps"
        [Environment]::SetEnvironmentVariable("SCOOP_GLOBAL", $env:SCOOP_GLOBAL, "Machine")
        $env:SCOOP = $scoopDir
        [Environment]::SetEnvironmentVariable("SCOOP", $env:SCOOP, "MACHINE")
        iex (new-object net.webclient).downloadstring("https://get.scoop.sh")
        $Reg = "Registry::HKLM\System\CurrentControlSet\Control\Session Manager\Environment"
        $OldPath = (Get-ItemProperty -Path $Reg -Name PATH).Path
        $NewPath = "$OldPath;$scoopDir\shims"
        Set-ItemProperty -Path $Reg -Name PATH -Value $NewPath
        $CurrentValue=[Environment]::GetEnvironmentVariable("PSModulePath","Machine") 
        [Environment]::SetEnvironmentVariable("PSModulePath", "$CurrentValue;$scoopDir\modules", "Machine")
        scoop install aria2 7zip innounp dark -g
        scoop config aria2-enabled false
        scoop install git -g
        scoop install OpenSSH -g
        [environment]::setenvironmentvariable('GIT_SSH', (resolve-path (scoop which ssh)), 'MACHINE')
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1
        scoop checkup
        scoop status
        scoop update        
        read-host “Press ENTER to continue”  
     }
    
    #add buckets and isntall global utilities
    6 {
        $menuColor[6] = "Yellow"
        scoop bucket add extras
        scoop bucket add java
        scoop bucket add CyberAuditBucket https://github.com/contigon/CyberAuditBucket.git
        scoop bucket list
        foreach ($utility in $utilities)
        {
            scoop install $utility -g
        }
     read-host “Press ENTER to continue” 
     }
    
    #install audit applications from cyberauditbucket
    7 {
        $menuColor[7] = "Yellow"
        #(Get-ChildItem $scoopDir\buckets\CyberAuditBucket -Filter *.json).BaseName|ForEach-Object {scoop install $_ -g}
        foreach ($CollectorApp in $CollectorApps)
            {
                scoop install $CollectorApp -g
            }
        $c = scoop list 6>&1
        $i=0
        foreach ($f in $c)
        {
            $i++
            if ($($foreach.current) -match 'failed')
            {
               if ($c[$i-2].ToString() -match "global")
               {
                    Write-Host $c[$i-4].ToString() "--> global app installation failed, we will try to uninstall and reinstall"
                    scoop uninstall $c[$i-4].ToString() -g
                    scoop install $c[$i-4].ToString() -g
                }
                else
                {
                    Write-Host $c[$i-3].ToString() "--> app installation failed, we will try to uninstall and reinstall"
                    scoop uninstall $c[$i-3].ToString()
                    scoop install $c[$i-3].ToString()
                }
            }
        }
     read-host “Press ENTER to continue” 
     }
     
      #install Analyzers and Reporting applications from cyberauditbucket
    8 {
        $menuColor[8] = "Yellow"
        #(Get-ChildItem $scoopDir\buckets\CyberAuditBucket -Filter *.json).BaseName|ForEach-Object {scoop install $_ -g}
        foreach ($AnalyzerApp in $AnalyzerApps)
            {
                if ($AnalyzerApp -eq "vista_proba_free") {
                    $input = Read-Host "Press [Y] to download $AnalyzerApp rainbow table for Ophcrack (or Enter to continue and download it later)"
                     if ($input -eq "Y") {
                        scoop install $AnalyzerApp -g
                        }
                        else
                        {
                            Write-Host "You can download any rainbow table for Ophcrack manually from:" -ForegroundColor Yellow
                            Write-Host "https://ophcrack.sourceforge.io/tables.php" -ForegroundColor Yellow
                        }
                }
                else 
                {
                    scoop install $AnalyzerApp -g
                }
            }
        foreach ($GPOBaseline in $GPOBaselines)
        {
            scoop install $GPOBaseline -g
        }
        $c = scoop list 6>&1
        $i=0
        foreach ($f in $c)
        {
            $i++
            if ($($foreach.current) -match 'failed')
            {
               if ($c[$i-2].ToString() -match "global")
               {
                    Write-Host $c[$i-4].ToString() "--> global app installation failed, we will try to uninstall and reinstall"
                }
                else
                {
                    Write-Host $c[$i-3].ToString() "--> app installation failed, we will try to uninstall and reinstall"
                }
            }
        }
        $c = scoop list 6>&1
        $i=0;foreach ($f in $c)
        {
            $i++
            if ($($foreach.current) -match 'failed')
            {
              if ($c[$i-2].ToString() -match "global")
                 {
                     scoop uninstall $c[$i-4].ToString() -g
                     scoop install $c[$i-4].ToString() -g
                 }
              else
                {
                     scoop uninstall $c[$i-3].ToString()
                     scoop install $c[$i-3].ToString()
                }

            }
        }
     read-host “Press ENTER to continue” 
     }
     
     #Update scoop, Powershell and applications
     9 {
        $menuColor[9] = "Yellow"
        
        Write-Host "Updating the core CyberAuditTool scripts"
        $zipURLB = "http://cyberaudittool.c1.biz/$FileNamef"
        $zipURLA = "https://raw.githubusercontent.com/contigon/Downloads/master/$FileName"
        $FileName = "goUpdate.pdf"
        $FilesToUpdate = (
          "cyberAnalysers.ps1",
          "cyberAudit.ps1",
          "cyberBuild.ps1",
          "CyberCollectNetworkConfig.ps1",
          "CyberCompressGo.ps1",
          "CyberCompressGoUpdate.ps1",
          "CyberCreateRunecastRole.ps1",
          "CyberFunctions.ps1",
          "CyberLicenses.ps1",
          "CyberMenu.ps1",
          "CyberPasswordStatistics.ps1",
          "CyberPingCastle.ps1",
          "CyberAuditDevelopersHelp.txt",
          "CyberBginfo.bgi"
          )
         
        Remove-Item "$PSScriptRoot\$FileName" -Force
        try {
            $zipfile = "$PSScriptRoot\$FileName"
            Write-Host "Trying to Download Cyber Audit Tool Updates from $zipurlA to $PSScriptRoot"
            dl $zipurlA $zipfile
            }
        catch {
            Write-Host "[Failed] Error connecting to 1st download site, trying 2nd download option"
            $zipfile = "$PSScriptRoot\$FileName"
            Write-Host "Trying to Download Cyber Audit Tool Updates from $zipurlB to $PSScriptRoot"
            dl $zipurlB $zipfile
            }
        Write-Output 'Extracting Cyber Audit Tool core files updates...'
        Remove-Item -Path "$PSScriptRoot\update" -Recurse -Confirm:$false -Force
        Add-Type -Assembly "System.IO.Compression.FileSystem"
        [IO.Compression.ZipFile]::ExtractToDirectory($zipfile, "$PSScriptRoot\update")

        #replace only newer files
        $FilesToUpdate |foreach {if ((Get-Item $psscriptroot\$_).LastWriteTime -lt (Get-Item $psscriptroot\update\$_).LastWriteTime) {Write-host "[Update Available] $_" -ForegroundColor Red ; Copy-Item "$psscriptroot\update\$_" -Destination "$psscriptroot\$_" -Force} else {Write-host "[No Updates] $_" -ForegroundColor Green}}
        Remove-Item -Path "$PSScriptRoot\update" -Recurse -Confirm:$false -Force

        Write-Output 'Updating Scoop and applications...'
        scoop status
        scoop update * --global
        scoop checkup
        scoop cleanup * --cache
        
        Write-Output 'Checking and installing Updates of Powershell Modules, This can take some time...'
        Get-InstalledModule | foreach {$PSModule = (find-module $_.name).version; if ($PSModule -ne $_.version) {Write-host "Module:$($_.name) Installed Version:$($_.version) Last Version:$PSModule" -ForegroundColor Yellow ; Update-Module $_.name -Force} else {Write-Host "$($_.name) $($_.version) is the latest" -ForegroundColor Green} }        
        
        Write-Output 'checking .Net version so you can update it manually...'
        detect
     read-host “Press ENTER to continue” 
     }
     
     #Licenses
    10 {
        $menuColor[10] = "Yellow"
        $ScriptToRun = $PSScriptRoot+"\CyberLicenses.ps1"
        &$ScriptToRun
     read-host “Press ENTER to continue” 
     }
     
     #Uninstal scoop utilities, applications and scoop itself
    11 {
        (Get-ChildItem $bucketsDir\CyberAuditBucket -Filter *.json).BaseName|ForEach-Object {scoop uninstall $_ -g}
        foreach ($utility in $utilities)
        {
            scoop uninstall $utility -g
        }
        scoop uninstall scoop
        Remove-Item $scoopDir -Recurse -ErrorAction Ignore
        Remove-Module Microsoft.ActiveDirectory.Management -Verbose
        if (Test-Path $PSScriptRoot\HKEY_CURRENT_USER.reg) {
            reg import $PSScriptRoot\HKEY_CURRENT_USER.reg
            reg import $PSScriptRoot\HKEY_LOCAL_MACHINE.reg
        }
        Get-ComputerRestorePoint
        $resPoint = Read-Host "Input the Sequence Number of the restore point you want to revert to (or Enter to continue)"
        if ($resPoint -gt 0) {
            Restore-Computer -RestorePoint $resPoint -Confirm -ErrorAction SilentlyContinue
            }
        Get-ComputerRestorePoint -LastStatus
     read-host “Press ENTER to continue”       
     }

    #install Attacking scripts and tools
    12 {
        $menuColor[7] = "Yellow"
        #(Get-ChildItem $scoopDir\buckets\CyberAuditBucket -Filter *.json).BaseName|ForEach-Object {scoop install $_ -g}
        foreach ($AttackApp in $AttackApps)
            {
                scoop install $AttackApp -g
            }
        $c = scoop list 6>&1
        $i=0
        foreach ($f in $c)
        {
            $i++
            if ($($foreach.current) -match 'failed')
            {
               if ($c[$i-2].ToString() -match "global")
               {
                    Write-Host $c[$i-4].ToString() "--> global app installation failed, we will try to uninstall and reinstall"
                    scoop uninstall $c[$i-4].ToString() -g
                    scoop install $c[$i-4].ToString() -g
                }
                else
                {
                    Write-Host $c[$i-3].ToString() "--> app installation failed, we will try to uninstall and reinstall"
                    scoop uninstall $c[$i-3].ToString()
                    scoop install $c[$i-3].ToString()
                }
            }
        }
     read-host “Press ENTER to continue” 
     }


   }
  CLS
 }
while ($input -ne '99')
stop-Transcript | out-null