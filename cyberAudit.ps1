<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberMenu
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Audit
#>

. $PSScriptRoot\CyberFunctions.ps1
ShowIncd
CyberBginfo
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - Audit"

#Set the credentials for this Audit (it will be stored in a file)
#Get-Credential $env:userdomain\$env:USERNAME | Export-Clixml -Path $PSScriptRoot\Tools\credentials.xml
#$cred = Import-Clixml -Path $PSScriptRoot\Tools\credentials.xml

start-Transcript -path $AcqBaseFolder\CyberAuditPhase.Log -Force -append

cls

do {
#Create the main menu
Write-Host ""
Write-Host "************************************************************************           " -ForegroundColor White
Write-Host "*** Cyber Audit Tool (Powershell Edition) - ISRAEL CYBER DIRECTORATE ***           " -ForegroundColor White
Write-Host "************************************************************************           " -ForegroundColor White
Write-Host ""
Write-Host "     Audit Data Collection:                                                        " -ForegroundColor White
Write-Host ""
Write-Host "     1. Domain		| Join/Disconnect machine to/from a Domain                     " -ForegroundColor White
Write-Host "     2. Test		| Test Domain Connections and Configurations for audit         " -ForegroundColor White
Write-Host "     3. NTDS		| Remote aquire ntds/SYSTEM                                    " -ForegroundColor White
Write-Host "     4. Network 	| Collect config files and routing from network devices        " -ForegroundColor White
Write-Host "     5. PingCastle 	| Active Directory Security Scoring                            " -ForegroundColor White
Write-Host "     6. Testimo 	| Running audit checks of Active Directory                     " -ForegroundColor White
Write-Host "     7. goddi		| dumps Active Directory domain information                    " -ForegroundColor White
Write-Host "     8. GPO      	| Backup Domain GPO to compare using Microsoft PolicyAnalyzer  " -ForegroundColor White
Write-Host "     9. SharpHound	| BloodHound Ingestor for collecting data from AD              " -ForegroundColor White
Write-Host "    10. HostEnum	| Red-Team-Script Collecting info from remote host and Domain  " -ForegroundColor White
Write-Host "    11. SCUBA		| Vulnerability scanning Oracle,MS-SQL,SAP-Sybase,IBM-DB2,MySQ " -ForegroundColor White
Write-Host "    12. azscan		| Oracle,Unix-Linux,iSeries,AS400-OS400,HP-Alpha,Vax,DECVax,VMS" -ForegroundColor White
Write-Host "    13. Grouper2 	| Find ActiveDirectory GPO security-related misconfigurations  " -ForegroundColor White
Write-Host "    14. Dumpert	 	| LSASS memory dumper for offline extraction of credentials    " -ForegroundColor White
Write-Host "    15. Runecast	| Security Hardening checks of VMWARE vSphere/NSX/cloud        " -ForegroundColor White
Write-Host ""
Write-Host "    99. Quit                                                                       " -ForegroundColor White
Write-Host ""
$input=Read-Host "Select Script Number"

switch ($input) 
     { 
     1 {
        Cls
        net use * /delete
        $choose = Read-Host "Press J to join or D to disconnect (Enter to continue)"
        if ($choose -eq "J"){
        $domain = Read-Host -Prompt "Enter Domain name to join the machine to"
        $username = read-host -Prompt "Enter an admin user name which have enough permissions"
        $password = Read-Host -Prompt "Enter password for $user" -AsSecureString
        $username = $domain+"\"+$username
        $credential = New-Object System.Management.Automation.PSCredential($username,$password)
        Add-Computer -DomainName $domain -Credential $credential
            }
        if ($choose -eq "D"){
        Remove-Computer -PassThru -Verbose
            }
        $restart = read-host "Press R to restart the computer in order for the settings to take effect (Enter to continue without restarting)"
        if ($restart -eq "R"){
            shutdown /r /f /c "Rebooting computer afer Domain joining or unjoining"
            }
        read-host “Press ENTER to continue”
        }
     #Test Domain Connections and Configurations for audit
     2 {
        Cls
        write-host local Computer Name:  $env:COMPUTERNAME
        Write-Host User domain is: $env:USERDOMAIN
        Write-Host Dns domain is: $env:USERDNSDOMAIN
        Write-Host This Domain Controller name is: $DC
        Write-Host DNS root is: (Get-ADDomain).DNSRoot
        Test-ComputerSecureChannel -v
        Enable-PSRemoting -Force;Get-Item WSMan:\localhost\Client\TrustedHosts
        Test-WsMan $DC
        Invoke-Command -ComputerName $DC -ScriptBlock {Get-WmiObject -Class Win32_ComputerSystem } -credential $cred
        $inpYesNo = Read-Host "Press [Enter] if test was successfull or [N] to try a different way"
        Switch ($inpYesNo) {
            "N" {
                Write-Host "Trying to start remote winrm using psexec"
                psexec -accepteula $env:LOGONSERVER -s winrm.cmd quickconfig -q
                write-host "another way is to run SolarWinds Remote Execution Enabler for PowerShell tool"
                RemoteExecutionEnablerforPowerShell
            }
        }
        read-host “Press ENTER to continue”
     }
     #NTDS and SYSTEM hive remote aquisition
     3 {
        cls
        $ACQ = ACQ("NTDS")
        $winVer = Invoke-Command -ComputerName $DC -ScriptBlock {(Get-WmiObject -class Win32_OperatingSystem).Caption} -credential $cred
        if($winVer.contains("2003") -or $winVer.contains("2008")) 
        {
            Write-Host "The domain server is " $winVer -ForegroundColor Red
            $block = @"

        Below window 2012 we cant backup the files remotely, 
        you will need to do it locally on the Domain Controller
        run these steps from elevated CMD:
        --------------------------
        1. ntdsutil
        2. activate instance ntds
        3. ifm
        4. create full C:\ntdsdump
        5. quit
        6. quit
        --------------------------
        when finished please copy the c:\ntdsdump directory to the Aquisition folder (NTDS)

"@
Write-Host $block -ForegroundColor Red
        }
        else
        {
            Write-Host "Please wait untill the backup process is completed" -ForegroundColor Green
            remove-item $env:LOGONSERVER\c$\ntdsdump -Recurse -ErrorAction SilentlyContinue
            winrs -r:$DC ntdsutil "ac i ntds" "ifm" "create full c:\ntdsdump" q q
            Copy-Item -Path $env:LOGONSERVER\c$\ntdsdump\* -Destination $ACQ -Recurse -Force
        }
     read-host “Press ENTER to continue”
     $null = start-Process -PassThru explorer $ACQ
     }
     #Network
     4 {
        Cls
        $ACQ = ACQ("Network")
        $ScriptToRun = $PSScriptRoot+"\CyberCollectNetworkConfig.ps1"
        &$ScriptToRun
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
        }
     #PingCastle
     5 {
        Cls
        $ACQ = ACQ("PingCastle")
        $ScriptToRun = $PSScriptRoot+"\CyberPingCastle.ps1"
        &$ScriptToRun
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
        }
    #Testimo
    6 {
        Cls
        $ACQ = ACQ("Testimo")
        import-module activedirectory ; Get-ADDomainController -Filter * | Select Name, ipv4Address, OperatingSystem, site | Sort-Object -Property Name
        Invoke-Testimo  -ExcludeSources DCDiagnostics -ReportPath $ACQ\Testimo.html
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
    #goddi
    7 {
        Cls
        $ACQ = ACQ("goddi")
        $securePwd = Read-Host "Input a Domain Admin password" -AsSecureString
        $Pwd =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
        goddi-windows-amd64.exe -username $env:USERNAME -password $Pwd -domain $env:USERDNSDOMAIN -dc $DC -unsafe
        Move-Item -Path $appsDir\goddi\current\csv\* -Destination $ACQ
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
     #GPO
     8 {
        cls
        $ACQ = ACQ("GPO")
        Backup-GPO -All -Path $ACQ
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
     #Sharphound
     9 {
        cls
        $ACQ = ACQ("Sharphound")
        Import-Module $appsDir\sharphound\current\SharpHound.ps1
        Invoke-BloodHound -CollectionMethod All,GPOLocalGroup,LoggedOn -OutputDirectory $ACQ
        $MaXLoop = read-host “Choose Maximum loop time for session collecting task (eg. 30m)”
        Invoke-BloodHound -CollectionMethod SessionLoop -MaxLoopTime $MaXLoop -OutputDirectory $ACQ
        Invoke-BloodHound -SearchForeset -CollectionMethod All,GPOLocalGroup,LoggedOn -OutputDirectory $ACQ
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
     #HostEnum
     10 {
        cls
        $ACQ = ACQ("HostEnum")
        Import-Module $appsDir\red-team-scripts\current\HostEnum.ps1
        Invoke-HostEnum -ALL -HTMLReport -Verbose
        Move-Item -Path $appsDir\red-team-scripts\current\*.html -Destination $ACQ
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
     #Scuba
     11 {
        cls
        $ACQ = ACQ("Scuba")
        $help = @"

  
        Time zone issues when auditing mysql server, run this from DOS terminal on the server:
        set @@global.time_zone=+00:00
        set @@session.time_zone='+00:00

"@
        write-host $help 
        $cmd = "Scuba"
        Invoke-Expression $cmd
        read-host “Press ENTER to continue”
        Move-Item -Path $appsDir\scuba-windows\current\Scuba App\production\ -Destination $ACQ -ErrorAction SilentlyContinue
        $null = start-Process -PassThru explorer $ACQ
     }
        #azscan
     12 {
        $ACQ = ACQ("azscan")
        $help = @"

        azscan supprts auditing of Oracle Databases versions: 7,8,9,10gR1,10gR2,11g,12c
        The steps includes running the [AZOracle.sql] script on the Oracle DB which outputs
        a result file [OScan.fil] which needs to be imported back to the azscan tool which 
        will run the tests and prepare a report with the results of the audit

        
"@
        Write-Host $help
        $input = Read-Host "Input [O] in order to audit ORACLE database (Or Enter to continue with other Platforms)"
        if ($input -eq "O") {
            $CopyToPath = Read-Host "Choose Path to Copy AZOracle.sql script to (eg. \\$DC\c$\Temp)"  
            if (Test-Path -Path $CopyToPath -PathType Any)
             {
                Copy-Item -Path $appsDir\azscan3\current\AZOracle.sql -Destination $CopyToPath
                $null = start-Process -PassThru explorer $CopyToPath
                $copyResult = Read-Host "Press [Enter] to copy OScan.fil from $CopyToPath to $ACQ"            
                Copy-Item -Path $CopyToPath\OScan.fil -Destination $ACQ
                $null = start-Process -PassThru explorer $ACQ
            }
            else {
                Write-Host "Could not connect to path $CopyToPath, Please check and try again" -ForegroundColor Red
            }
        }
        $cmd = "azscan3"
        Invoke-Expression $cmd
     }
    #Grouper2
     13 {
        cls
        $ACQ = ACQ("grouper2")
        $cmd = "grouper2.exe -g"
        Invoke-Expression $cmd
        $cmd = " grouper2.exe -f $ACQ\Report.html"
        Invoke-Expression $cmd
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
        #Dumpert
     14 {
        cls
        $ACQ = ACQ("Dumpert")
        Write-Host "This will help dumping memory and later this can be used to decrypt tha users NTLM hashes offline"
        Write-Host "Please use with care and do not execute on critical servers or Virtual machines !!!" -ForegroundColor Red
        $target = Read-Host "Input the Name or IP address of the windows machine you want to run this tool"
        $cmd = "Outflank-Dumpert.exe"
        Copy-Item -Path $appsDir\Outflank-Dumpert\current\Outflank-Dumpert.exe -Destination \\$target\c$\Windows\temp -Recurse -Force
        winrs -r:$target c:\Windows\temp\$cmd
        Copy-Item -Path $target\c$\WINDOWS\Temp\dumpert.dmp -Destination $ACQ -Recurse -Force
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
        #runecast
     15 {
        cls
        $ACQ = ACQ("Runecast")
        $help = @"

linux: rcadmin/admin

web:   rcuser/Runecast!

licence: You need to assign the runecast 14 days licence after connecting to the vsphere servers

Creating User in the vCenter and assigning the [Runecast] role:
---------------------------------------------------------------
1 - Automatically or Manually run the powershell script (https://github.com/Runecast/public/blob/master/PowerCLI/createRunecastRole.ps1)
2 - Log to the vCenter web interface (with user such as administrator@$env:USERDNSDOMAIN)"
3 - Single Sign On --> Users and Groups --> Add User --> (Create New user for Runecast Analyzer)
4 - Access Control --> Global Permissions --> Add Permission
5 - search for the user created in step 2 and assign the [Runecast] role 

[Optional] Syslog analysis !!! Be carefull as this can affect the server performance !!!
-------------------------------------------------------------------------------------
1 - ESXi Log Forwarding by clicking the help ring icon located to the right-hand side of the Host syslog settings section
in the Log Analysis tab, expand the section and click to download the PowerCLI script and Execute the script using PowerCLI
2 - VM Log Forwarding to Syslog Click the help ring icon located on the right side-hand of the
VM log settings section of the Log Analysis tab, expand the Scripted section and download 
the PowerCLI script and Execute the script using PowerCLI
3 - Perform either a vMotion or Power Cycle for each VM
        
"@
        Write-Host $help
        $input = Read-Host "Press [R] to run the Create Role Powershell script (or Enter to contine)"
        if ($input -eq "R") {
            $ScriptToRun = $PSScriptRoot+"\CyberCreateRunecastRole.ps1"
            &$ScriptToRuns
        }
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
    #Menu End
    }
 cls
 }
while ($input -ne '99')
stop-Transcript | out-null
