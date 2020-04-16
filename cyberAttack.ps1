<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberAttack
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Attack
#>

. $PSScriptRoot\CyberFunctions.ps1
ShowIncd
CyberBginfo
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - Attack"

#Set the credentials for this Audit (it will be stored in a file)
#Get-Credential $env:userdomain\$env:USERNAME | Export-Clixml -Path $PSScriptRoot\Tools\credentials.xml
#$cred = Import-Clixml -Path $PSScriptRoot\Tools\credentials.xml

start-Transcript -path $AcqBaseFolder\CyberAttackPhase.Log -Force -append

cls

do {
#Create the main menu
Write-Host ""
Write-Host "************************************************************************               " -ForegroundColor White
Write-Host "*** Cyber Audit Tool (Powershell Edition) - ISRAEL CYBER DIRECTORATE ***               " -ForegroundColor White
Write-Host "************************************************************************               " -ForegroundColor White
Write-Host ""
Write-Host "     Attacking Tools and Scripts:                                                      " -ForegroundColor White
Write-Host ""
Write-Host "     1. InfectionMonkey		| Breach and Attack Simulation tool                        " -ForegroundColor White
Write-Host ""
Write-Host "    99. Quit                                                                           " -ForegroundColor White
Write-Host ""
$input=Read-Host "Select Script Number"

switch ($input) 
     { 
     
     #InfectionMonkey
     1 {
        Cls
        $ACQ = ACQ("InfectionMonkey")
        $help = @"

    Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection.
    The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server.

    The Infection Monkey is comprised of two parts:
    1. Monkey - A tool which infects other machines and propagates to them.
    2. Monkey Island - A dedicated server to control and visualize the Infection Monkeys progress inside the data center.

    The Infection Monkey uses the following techniques and exploits to propagate to other machines:
        
    1. Multiple propagation techniques:
       - Predefined passwords
       - Common logical exploits
       - Password stealing using Mimikatz
        
    2. Multiple exploit methods:
       - SSH
       - SMB
       - WMI
       - Shellshock
       - Conficker
       - SambaCry
       - Elastic Search (CVE-2015-1427)

     Getting started links: 
       - Windows: https://www.guardicore.com/infectionmonkey/wt/win.html
       - Securing Remote Workers: https://www.guardicore.com/infectionmonkey/wfh.html

     Other Platforms:
     - AWS
     - Azure
     - VMware 
     - Docker 
     - Debian

"@
        write-host "Checking if InfectionMonkey is installed, if not we will start the installation"
        $isInstalled = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like '*monkey*'}
        if ($isInstalled)
        {
            $a = "C:\Program Files\Guardicore\Monkey Island\monkey_island"
            Push-Location $a
            Start-Process -FilePath ".\MonkeyIsland.exe"
            Pop-Location
        }
        else
        {
            $a = appDir("infectionmonkey")
            Push-Location $a
            Start-Process -FilePath ".\MonkeyIslandSetup.exe"
            Pop-Location
        }
        
        Write-Host "Web interface: https://localhost:5000/" -ForegroundColor Yellow
        read-host “Press ENTER to continue”
      }

    #Menu End
    }
 cls
 }
while ($input -ne '99')
stop-Transcript | out-null