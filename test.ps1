Function ACQA{
    Param ($dir)
    $ACQdir = ("C:\CyberAuditPS2020\CYBER-AUDIT-PC\$dir").Replace("//","/")
    if (Test-Path -Path $ACQdir) 
        {
            Write-Host "[Note] $ACQdir folder already exsits, this will not affect the process" -ForegroundColor Gray
        }
     else        
        {
        $ACQdir = New-Item -Path C:\CyberAuditPS2020\CYBER-AUDIT-PC -Name $dir -ItemType "directory" -Force
        write-host "$ACQdir was created successfuly" -ForegroundColor Green
        }
    Return $ACQdir
}

$ACQ = ACQA("Statistics")
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
