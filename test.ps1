. $PSScriptRoot\CyberFunctions.ps1

$ACQ = ACQ("Scuba")
        $help = @"

  
        Time zone issues when auditing mysql server, run this from DOS terminal on the server:
        set @@global.time_zone=+00:00
        set @@session.time_zone='+00:00

"@
        write-host $help 
        $cmd = "Scuba"
        #Invoke-Expression $cmd
        #$input = read-host “Wait untill Database auditing is finished, Then Press Enter”

            $ScubaDir = scoop prefix scuba-windows
            $serverAddress = Select-String -Path "$ScubaDir\Scuba App\production\AssessmentResults.js"  -pattern "serverAddress"
            $a = $serverAddress -split "'"
            $b = $a[3] -split ":"
            $database = Select-String -Path "$ScubaDir\Scuba App\production\AssessmentResults.js"  -pattern "database"
            $c = $database -split "'"
            $fName = "$b[0]$c[3]"
            Write-Host $fName
            #Compress-Archive -Path "$appsDir\scuba-windows\current\Scuba App\*" -DestinationPath "$ACQ\$fname.zip"
            #$null = start-Process -PassThru explorer $ACQ