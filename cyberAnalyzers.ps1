<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberAnalyzers
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Aduti Data Analyzers tools 
#>

. $PSScriptRoot\CyberFunctions.ps1
ShowIncd
DisableFirewall
DisableAntimalware
CyberBginfo
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - Analyzers"

Write-Host " "

#Set the Audit Acquisition folders
if ($AcqABaseFolder -eq $null) 
{
    Write-Host "Choose the root folder with the audit data you want to analyze" -ForegroundColor Yellow
    $AcqABaseFolder = Get-Folder
}

Function ACQA{
    Param ($dir)
    $ACQdir = ("$AcqABaseFolder\$dir").Replace("//","/")
    if (Test-Path -Path $ACQdir) 
        {
            Write-Host "[Note] $ACQdir folder already exsits, this will not affect the process" -ForegroundColor Gray
        }
     else        
        {
        $ACQdir = New-Item -Path $AcqABaseFolder -Name $dir -ItemType "directory" -Force
        write-host "$ACQdir was created successfuly" -ForegroundColor Green
        }
    Return $ACQdir
}

cls

do {
#Create the main menu
Write-Host ""
Write-Host "************************************************************************                " -ForegroundColor White
Write-Host "*** Cyber Audit Tool (Powershell Edition) - ISRAEL CYBER DIRECTORATE ***                " -ForegroundColor White
Write-Host "************************************************************************                " -ForegroundColor White
Write-Host ""
Write-Host "     Audit Data Analysis:                                                               " -ForegroundColor White
Write-Host "" 
Write-Host "     Root aquisition folder is $AcqABaseFolder (Press [0] To change path)               " -ForegroundColor yellow
Write-Host ""
Write-Host "     1. Pwdump         | Process NTDS/SYSTEM files and export pwdump/ophcrack files    " -ForegroundColor White
Write-Host "     2. Ophcrack       | Password cracker based on rainbow tables                      " -ForegroundColor White
Write-Host "     3. Hashcat        | Password cracker based on dictionaries                        " -ForegroundColor White
Write-Host "     4. BloodHound     | Find attack vectors within Active Directory                   " -ForegroundColor White
Write-Host "     5. PolicyAnalizer | Compare GPO to Microdoft Security configuration baselines     " -ForegroundColor White
Write-Host "     6. statistics     | Cracked Enterprise & Domain Admin passwords statistics        " -ForegroundColor White
Write-Host "     7. Dsinternals    | Password cracking using haveibeenpawned NTLM v5 file          " -ForegroundColor White
Write-Host ""
Write-Host "    99. Quit                                                                            " -ForegroundColor White
Write-Host ""
$input=Read-Host "Select Script Number"

switch ($input) {
     #Analyze the NTDS and SYSTEM hive (ntdsaudit, DSInternals)
     1 {
        cls
        $ACQ = ACQ("NTDS")
        Get-ChildItem -Path $ACQ -Recurse -File | Move-Item -Destination $ACQ
        NtdsAudit $ACQ\ntds.dit -s $ACQ\SYSTEM  -p  $ACQ\pwdump.txt -u  $ACQ\user-dump.csv --debug --history-hashes
        Import-Module DSInternals
        $bk=Get-BootKey -SystemHivePath $ACQ\SYSTEM
        $fileFormat = @("Ophcrack","HashcatNT","HashcatLM","JohnNT","JohnLM")
        foreach ($f in $fileFormat) 
        {
            Write-Host "[Success] Exporting hashes to $f format" -ForegroundColor Green
            Get-ADDBAccount -All -DBPath $ACQ\ntds.dit -BootKey $bk|Format-Custom -View $f|Out-File $ACQ\hashes-$f.txt -Encoding ASCII
        }
        read-host “Press ENTER to continue”
        $null = start-Process -PassThru explorer $ACQ
     }
     #Ophcrack
     2 {
        CLS
        $ACQ = ACQA("NTDS")
        $help = @"
        
        In order to run the hashed passwords cracking process, we will upload the
        $ACQ\hashes-Ophcrack.txt into ophcrack.
       
        Next step you will need to Press the [Crack] button to start the process.

"@
        write-host $help -ForegroundColor Yellow
        if (Test-Path -Path $ACQ\hashes-Ophcrack.txt)
        {
            Write-Host "[Success] The file $ACQ\hashes-Ophcrack.txt was found" -ForegroundColor Green
            $cmd = "ophcrack -d $appsDir\vista_proba_free\current -t $appsDir\vista_proba_free\current -f $ACQ\hashes-Ophcrack.txt -n 4"
            Invoke-Expression $cmd
        }
        else 
        {
            Write-Host "[Failed] The file $ACQ\hashes-Ophcrack.txt was not found, please check and try again" -ForegroundColor Red
        }
        read-host “Press ENTER to continue”
     }
       #hashcat
     3 {
        CLS
        $ACQ = ACQ("NTDS")
        #check if not Virtual Machine
        $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
        $GPU = (Get-WmiObject Win32_VideoController).VideoProcessor
        switch ($ComputerSystemInfo.Model) { 
        # Check for Hyper-V Machine Type 
        "Virtual Machine" { 
            $MachineType="VM" 
            } 
        # Check for VMware Machine Type 
        "VMware Virtual Platform" { 
            $MachineType="VM" 
            }  
        # Check for Oracle VM Machine Type 
        "VirtualBox" { 
            $MachineType="VM"             } 
        # Otherwise it is a physical Box 
        default { 
            $MachineType="Physical" 
            } 
        } 
        
        if ($MachineType -ne "Physical")
        {
            $help = @"

        [Failed] Your Virtualization graphics adapter is : $GPU

        hashcat needs OpenCL drivers which will operate best on physical GPU

        or try searching for help about GPU passthru for you virtualization environment.

"@

            Write-Host $help -ForegroundColor Red
        }
        else
        {
            $hashcatPath = scoop prefix hashcat
            $dumpFile = "pwdump.txt"
            Push-Location $hashcatPath
            $help = @"
        
        Hashcat will try now to crack the hashes extracted from Active Directory database file.

        You are running hashcat using this GPU: $GPU 
        It is best using a PC with GPU such as Nvidia 1080Ti GPU for faster cracking.
        
        We will be using the Rockyou.txt dictionary file.

        More dictionaries can be downloaded from:
        https://github.com/danielmiessler/SecLists/tree/master/Passwords
        https://www.blacktraffic.co.uk/pw-dict-public/dict/

        We will be using the l33tpasspro rule file.

        More rules can be downloaded from:
        https://github.com/nccgroup/hashcrack

        Other cracking tools recommended:
        hashcrack - Automatic tool that Guesses hash types, picks some sensible dictionaries and rules for hashcat
        https://github.com/nccgroup/hashcrack

"@
            write-host $help -ForegroundColor Yellow
            if (Test-Path -Path $ACQ\$dumpFile)
            {
                    Write-Host "[Success] The file $ACQ\$dumpFile was found" -ForegroundColor Green
                    $cmd = "hashcat -a 0 -m 1000 --username $ACQ\$dumpFile $appsDir\rockyou\current\rockyou.txt -r $appsDir\rockyou\current\l33tpasspro.rule.txt  --loopback  -O -w3 --force  -o $ACQ\pwdump_cracked.txt  --potfile-path $ACQ\hashcat-rockyou-lm.pot"
                    Invoke-Expression $cmd -WarningAction SilentlyContinue
                    $cmd = "hashcat -a 0 -m 1000 --username $ACQ\$dumpFile $appsDir\rockyou\current\rockyou.txt -r $appsDir\rockyou\current\l33tpasspro.rule.txt  --loopback  -O -w3 --force  -o $ACQ\pwdump_show_cracked.txt  --potfile-path $ACQ\hashcat-rockyou-lm.pot --show"
                    Invoke-Expression $cmd -WarningAction SilentlyContinue
                    $cracked = (Get-Content $ACQ\pwdump_show_cracked.txt).Split("\")
                    for ($i = 1 ; $i -lt (Get-Content .\cracked.txt).count;$i+=2)
                    {
                        Add-Content -Path $ACQ\found_cracked.txt  -value $cracked[$i]
                    }
                    $a = (Get-Content -Path  $ACQ\$dumpFile).count
                    $b = (Get-Content -Path  $ACQ\pwdump_show_cracked.txt).count
                    Add-Content -Path $ACQ\left_uncracked.txt  -value ($a - $b)
                    Start-Process iexplore $ACQ
            }
            else 
            {
                Write-Host "[Failed] The file $ACQ\pwdump.txt was not found, please check and try again" -ForegroundColor Red
            }
        }
     Pop-Location
     read-host “Press ENTER to continue”
     }
     #BloodHound
     4 {
        CLS
        $ACQ = ACQA("Sharphound")
        $help = @"
        
        Please wait untill the neo4j database is running, this can take some time,
        when logged in to the bloodhound application you will need to upload the
        sharphound collected .json files in $ACQ

"@
        write-host $help -ForegroundColor Yellow
	    if (Get-Service -Name "neo4j" -ErrorAction SilentlyContinue) 
            {
	            $cmd = "net start 'neo4j'"
                Invoke-Expression $cmd
                write-host "User Name: neo4j" -ForegroundColor Yello
                write-host "Password: BloodHound" -ForegroundColor Yello
                invoke-expression "BloodHound"
        }
        else {
                $cmd = "neo4j install-service"
                Invoke-Expression $cmd
                Copy-Item $appsDir\BloodHoundExampleDB\current\BloodHoundExampleDB.graphdb $appsDir\neo4j\current\data\databases\BloodHoundExampleDB.graphdb -Recurse -Force      
                (Get-Content -Path  $appsDir\neo4j\current\conf\neo4j.conf -Raw) -replace "#dbms.active_database=graph.db","dbms.active_database=BloodHoundExampleDB.graphdb" | set-content -Path $appsDir\neo4j\current\conf\neo4j.conf
                (Get-Content -Path  $appsDir\neo4j\current\conf\neo4j.conf -Raw) -replace "#dbms.allow_upgrade=true","dbms.allow_upgrade=true" | set-content -Path $appsDir\neo4j\current\conf\neo4j.conf
	            $cmd = "net start 'neo4j'"
                Invoke-Expression $cmd
	            write-host "If you have problem with service starting, please start it manually from services.msc"
	            write-host "Verify neo4j is running(web console should show up in your browser"
	            start explorer http://localhost:7474/
	            write-host "User Name: neo4j" -ForegroundColor Green
	            write-host "Password: neo4j" -ForegroundColor Green
	            write-host "Please change initial password to: BloodHound" -ForegroundColor Red
                write-host "User Name: neo4j" -ForegroundColor Yello
                write-host "Password: BloodHound" -ForegroundColor Yello
                invoke-expression "BloodHound"
        }
        Start-Process iexplore $ACQ
        read-host “Press ENTER to continue”
     }
     #Ophcrack
     5 {
        CLS
        $ACQ = ACQA("GPO")
        $help = @"
        
        In order to add the backup GPO please follow this help:
        1. Press ADD
        2. Choose File --> Add Files From GPO
        3. Path for GPO files is:  $ACQ
        4. Save this GPO (you will 1st need to give a name for this GPO)

"@
        write-host $help -ForegroundColor Yellow
        $cmd = "policyanalyzer"
        Invoke-Expression $cmd
        read-host “Press ENTER to continue”     
     }
     #Statistics
     6 {     
        $ACQ = ACQA("Statistics")

        Write-Host "Searching for installed Microsoft Excel..."
        $excelVer = Get-WmiObject win32_product | where{$_.Name -match "Excel"} | select Name,Version
        if ($excelVer) 
        {
            Write-Host "[Success]" $excelVer[0].name "is already installed" -ForegroundColor Green
        }

        else
        {
             Write-Host "[Failure] Please install Microsoft Excel before continuing running this analysis" -ForegroundColor Red
             read-host “Press [Enter] if you installed Excel (or Ctrl + c to quit)”
        }

        $help = @"
        
        In order to create the password statistics excel we need 4 files
        ----------------------------------------------------------------
        Files From hashview or hashcat application after cracking the pwdump file
        You need export and copy them to $ACQ :
        1 - found_*.txt
        2 - left_*.txt
       
        Files that were created using the goddi applications
        we will try to copy them automatically:
        3 - Domain_Users_Domain Admins.csv
        4 - Domain_Users_Enterprise Admins.csv

"@

        $files = @("found_","left_","Domain_Users_Domain Admins.csv","Domain_Users_Enterprise Admins.csv")
        $hashcat = ACQA("NTDS")
        $found = $hashcat + "\" + $files[0].ToString()
        Copy-Item -Path $found*.txt -Destination $ACQ -Force
        $left = $hashcat + "\" + $files[1].ToString()
        Copy-Item -Path $left*.txt -Destination $ACQ -Force

        $goddi = ACQA("goddi")
        $DomainAdmins = $goddi + "\" + $files[2].ToString()
        Copy-Item -Path $DomainAdmins -Destination $ACQ -Force
        $EntAdmins = $goddi + "\" + $files[3].ToString()
        Copy-Item -Path $EntAdmins -Destination $ACQ -Force
        Write-Host $help -ForegroundColor Yellow
        Start-Process iexplore $ACQ
        $input  = Read-Host "Press [Enter] if you all files are located in $ACQ (or Ctrl + C to quit)"
        $folderFiles = Get-ChildItem -Path $ACQ -Recurse -File -Name
        $i = 0
        foreach ($f in $files) {
            if ($folderFiles -match $f) { 
                Write-Host "File $f*.txt was found." -foregroundcolor green
                $i++
            } else { 
                Write-Host "File $f*.txt was not found!" -foregroundcolor red 
            }
        }
        if ($i -eq 4)
        {
            Write-Host "[Success] Creating the statistics excel file..."
            $ScriptToRun = $PSScriptRoot+"\CyberPasswordStatistics.ps1"
            &$ScriptToRun
        }
        else 
        {
            Write-Host "[Failed] Check that all files are copied to the $ACQ folder and try again" -ForegroundColor Red
            Start-Process iexplore $ACQ
        }
        read-host “Press ENTER to continue”
     }

    #DSInternals
     7 {
        CLS
        $ACQ = ACQA("GPO")
        $help = @"
        
        https://haveibeenpwned.com/Passwords

"@
        write-host $help -ForegroundColor Yellow
        read-host “Press ENTER to continue”     
     }

#End Menu
    }
 cls
 }
while ($input -ne '99')
$cmd = "net stop 'neo4j'"
Invoke-Expression $cmd
