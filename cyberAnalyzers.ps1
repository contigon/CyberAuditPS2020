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
Write-Host "     3. BloodHound     | Find attack vectors within Active Directory                   " -ForegroundColor White
Write-Host "     4. PolicyAnalizer | Compare GPO to Microdoft Security configuration baselines     " -ForegroundColor White
Write-Host "     5. statistics     | Cracked Enterprise & Domain Admin pas0swords statistics       " -ForegroundColor White
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
        Get-ADDBAccount -All -DBPath $ACQ\ntds.dit -BootKey $bk|Format-Custom -View Ophcrack|Out-File $ACQ\hashes-Ophcrack.txt -Encoding ASCII
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
     #BloodHound
     3 {
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
     4 {
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
     5 {     
        $ACQ = ACQA("Statistics")
        $help = @"
        
        In order to create the password statistics excel we need 4 files
        ----------------------------------------------------------------
        Files From hashview application after cracking the pwdump file
        You need export and copy them to $ACQ :
        1 - found_*.txt
        2 - left_*.txt
       
        Files that were created using the goddi applications
        we will try to copy them automatically:
        3 - Domain_Users_Domain Admins.csv
        4 - Domain_Users_Enterprise Admins.csv

"@
        Read-Host $help
        $files = @("found_","left_","Domain_Users_Domain Admins.csv","Domain_Users_Enterprise Admins.csv")
        $goddi = ACQA("goddi")
        $DomainAdmins = $goddi + "\" + $files[2].ToString()
        Copy-Item -Path $DomainAdmins -Destination $ACQ
        $DomainAdmins = $goddi + "\" + $files[3].ToString()
        Copy-Item -Path $DomainAdmins -Destination $ACQ
        $folderFiles = Get-ChildItem -Path $ACQ -Recurse -File -Name
        $i = 0
        foreach ($f in $files) {
            if ($folderFiles -match $f) { 
                Write-Host "File $f was found." -foregroundcolor green
                $i++
            } else { 
                Write-Host "File $f was not found!" -foregroundcolor red 
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
    }
 cls
 }
while ($input -ne '99')
$cmd = "net stop 'neo4j'"
Invoke-Expression $cmd
