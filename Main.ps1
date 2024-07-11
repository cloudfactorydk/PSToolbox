param(
    [ValidateSet("Interactive", "Monitor-RDS","PingTool")]
    [string]$scriptaction = "Interactive"
)

#region functions

#region Monitor-RDS
function Get-RDPSessions {
    param(
        [int]$MeasureTimeSeconds = 1
    )

    #region Get RDPSessions
    $DisconnectedReasonCodes = @{
        0   = "No additional information is available."
        1   = "An application initiated the disconnection."
        2   = "An application logged off the client."
        3   = "The server has disconnected the client because the client has been idle for a period of time longer than the designated time-out period."
        4   = "The server has disconnected the client because the client has exceeded the period designated for connection."
        5   = "The client's connection was replaced by another connection."
        6   = "No memory is available."
        7   = "The server denied the connection."
        8   = "The server denied the connection for security reasons."
        9   = "The server denied the connection for security reasons."
        10  = "Fresh credentials are required."
        11  = "User activity has initiated the disconnect."
        12  = "The user logged off, disconnecting the session."
        256 = "Internal licensing error."
        257 = "No license server was available."
        258 = "No valid software license was available."
        259 = "The remote computer received a licensing message that was not valid."
        260 = "The hardware ID does not match the one designated on the software license."
        261 = "Client license error."
        262 = "Network problems occurred during the licensing protocol."
        263 = "The client ended the licensing protocol prematurely."
        264 = "A licensing message was encrypted incorrectly."
        265 = "The local computer's client access license could not be upgraded or renewed."
        266 = "The remote computer is not licensed to accept remote connections."
        267 = "An access denied error was received while creating a registry key for the license store."
        768 = "Invalid credentials were encountered."
    }

    $events = Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' }
    $NetTCPSessions = Get-NetTCPConnection -State Established -LocalPort 3389
    $sessions = qwinsta | ? { $_ -notmatch '^ SESSIONNAME' } | % {
        [PSCustomObject]@{
            Active                   = $_.Substring(0, 1) -match '>'
            SessionName              = $_.Substring(1, 18).Trim()
            SessionNameRDP           = $null
            Username                 = $_.Substring(19, 20).Trim()
            DateTime                 = get-date
            Id                       = $_.Substring(39, 9).Trim()
            State                    = $_.Substring(48, 8).Trim()
            Type                     = $_.Substring(56, 12).Trim()
            Device                   = $_.Substring(68).Trim()
            Idle                     = $null
            IdleTime                 = $null
            
            LogonTime                = $null
            LastReconnectTime        = $null
            LastDisconnectedTime     = $null
            LastDisconnectedReason   = $null
            LastDisconnectedReasonID = $null
            SessionEvents            = $null
            RemoteIP                 = $null
            RemotePort               = $null
            AvgAppResponseTime       = $null
            WorstAPPName             = $null
            WorstAPPResponseTime     = $null
            DroppedFramesServer      = $null
            DroppedFramesClient      = $null
            DroppedFramesNetwork     = $null
            CurrentTCPRTT            = $null
            BottleNeck               = $null
        }
    }

    #Merge data from qwinsta and quser
    foreach ($session in ($sessions | ? username)) {
        $user = quser | ? { $_ -match $session.Username }
        if ($session.SessionName -match "rdp-tcp#") {
            $session.SessionNameRDP = $session.SessionName -replace "rdp-tcp#", ""
            
        }
        #TODO: nogengange fejler den her. den kører if statement selvom user er tom. wrap i try.
        if ($user) {
            try{
            $idletime = $user.Substring(54, 9).Trim()
            $session.IdleTime = $idletime
            $session.Idle = $idletime -eq "\."
            $session.LogonTime = get-date ($user.Substring(65, 16).Trim())
        }
        catch {
            
        }

        }

        $SessionEvents = $events | ? TimeCreated -gt $session.LogonTime | ? { $_.message -match "Session ID: $($session.Id)" -or $_.message -match "Session $($session.Id) " } | sort timecreated -Descending 
        $session.SessionEvents = $SessionEvents
        #Get Client IP
        $LastClientIPEvent = $SessionEvents | ? message -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | select -first 1
        $null = $LastClientIPEvent.message -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        $session.RemoteIP = $matches[0]
        #Get Client Port
        $session.RemotePort = $NetTCPSessions | ? RemoteAddress -eq $session.RemoteIP | select -first 1 | select -ExpandProperty RemotePort
    

        # Fill in the values from eventlog
        $lastReconnectEvent = $SessionEvents | ? id -eq 25 | select -first 1
        if ($lastReconnectEvent) {
            $session.LastReconnectTime = $lastReconnectEvent.TimeCreated
        }

        #Session 5 has been disconnected, reason code 12
        $lastDisconnectEvent = $SessionEvents | ? id -eq 40 | select -first 1
        if ($lastDisconnectEvent) {
            $session.LastDisconnectedTime = $lastDisconnectEvent.TimeCreated
            $null = $lastDisconnectEvent.Message -match "reason code (\d+)"

            
            try {
                $session.LastDisconnectedReasonID = [int]$matches[1]
                $session.LastDisconnectedReason = $DisconnectedReasonCodes[$session.LastDisconnectedReasonID]
            }
            catch {
                $session.LastDisconnectedReason = "Unknown"
            }
            
        }
    }


    #endregion

    #region Performance Measurement
    # Detect system language
    $Language = (Get-Culture).Name

    # Define counters for English
    $Counters_EN = @(
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Server Resources"
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Network Resources"
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Client Resources"
        "\RemoteFX Graphics(*)\Average Encoding Time"
        "\RemoteFX Graphics(*)\Output Frames/Second"
        "\RemoteFX Network(*)\Current TCP RTT"
        "\RemoteFX Network(*)\Current UDP RTT"
        "\User Input Delay per Process(*)\Max Input Delay"
        "\Processor(_Total)\% Processor Time"
    )

    # Define counters for Danish (you need to find the correct Danish translations)
    $Counters_DA = @(
        "\RemoteFX-grafik(*)\Rammer sprunget over/sekund - utilstrækkelige serverressourcer"
        "\RemoteFX-grafik(*)\Rammer sprunget over/sekund - utilstrækkelige netværksressourcer"
        "\RemoteFX-grafik(*)\Rammer sprunget over/sekund - utilstrækkelige klientressourcer"
        "\RemoteFX-grafik(*)\Gennemsnitlig kodningstid"
        "\RemoteFX-grafik(*)\Outputrammer/sekund"
        "\RemoteFX-netværk(*)\Aktuel RTT for TCP"
        "\RemoteFX-netværk(*)\Aktuel RTT for UDP"
        "\Forsinkelse af brugerinput pr. proces(*)\Maks. inputforsinkelse"
        "\Processoroplysninger(*)\% processortid"
    )

    # Define regex patterns for language specific paths
    $Patterns_EN = @{
        CPUUtil = "% Processor Time"
        UserInputDelay = "user input delay per process"
        RemoteFX = "RemoteFX"
        TCPRTT = "current tcp rtt"
        InsufficientServerResources = "insufficient server resources"
        InsufficientNetworkResources = "insufficient network resources"
        InsufficientClientResources = "insufficient client resources"
    }

    $Patterns_DA = @{
        CPUUtil = "% processortid"
        UserInputDelay = "Forsinkelse af brugerinput pr. proces"
        RemoteFX = "RemoteFX"
        TCPRTT = "Aktuel RTT for TCP"
        InsufficientServerResources = "utilstrækkelige serverressourcer"
        InsufficientNetworkResources = "utilstrækkelige netværksressourcer"
        InsufficientClientResources = "utilstrækkelige klientressourcer"
    }

    # Select the correct patterns based on the language
    switch ($Language) {
        "en-US" { $Patterns = $Patterns_EN }
        "da-DK" { $Patterns = $Patterns_DA }
        default { throw "Language not supported: $Language" }  # Default to English if language is not supported
    }

    # Select the correct counters based on the language
    switch ($Language) {
        "en-US" { $Counters = $Counters_EN }
        "da-DK" { $Counters = $Counters_DA }
        default { throw "Language not supported: $Language" }  # Default to English if language is not supported
    }
    
    try {
        $PerformanceData = Get-Counter -ErrorAction Stop -Counter $Counters -MaxSamples $MeasureTimeSeconds -SampleInterval 1
   
    }

    catch {
        continue
    }
    
    #threshold in ms for application response time to be considered slow
    $SlowApplicationResponsTime = 500
    #threshold in ms for general response time to be considered slow. This is used to determine if the server is overloaded
    $GeneralSlowResponsTime = 150

    [int]$ServerCPUUtil = $PerformanceData.CounterSamples | ? path -match $Patterns.CPUUtil | sort cookedvalue -Descending | select -first 1 | select -ExpandProperty CookedValue
    #$session = $sessions | ? username -eq "laajadmin"
    foreach ($session in $sessions | ? state -eq "active" ) {
       
        #region App Responsetime
        $SlowApplicationCount = $PerformanceData.CounterSamples | ? path -match $Patterns.UserInputDelay | ? cookedvalue -gt $GeneralSlowResponsTime  | measure | select -ExpandProperty count
        
        $AvgAppResponseTime = $PerformanceData.CounterSamples | ? path -match $Patterns.UserInputDelay | ? instanceName -match "^$($session.Id)" | ? cookedvalue -gt 0 | measure -Average -Property cookedvalue | select -ExpandProperty Average
        $session.AvgAppResponseTime = $AvgAppResponseTime
            
        $WorstAPP = $PerformanceData.CounterSamples | ? path -match $Patterns.UserInputDelay | ? instanceName -match "^$($session.Id)" | sort cookedvalue -Descending | select -first 1
            
        $null = $WorstAPP.instancename -match "<(.+?)>"
        $session.WorstAPPName = $matches[1]
        $session.WorstAPPResponseTime = $WorstAPP.CookedValue
        #endregion

        #region Resources
        $SessionRemoteFXCounters = $PerformanceData.CounterSamples | ? path -match $Patterns.RemoteFX | ? path -match "\(rdp-tcp $($session.SessionNameRDP)\)"
       
        [int]$DroppedFramesServer = $SessionRemoteFXCounters | ? path -match $Patterns.InsufficientServerResources | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        [int]$DroppedFramesClient = $SessionRemoteFXCounters | ? path -match $Patterns.InsufficientClientResources | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        [int]$DroppedFramesNetwork = $SessionRemoteFXCounters | ? path -match $Patterns.InsufficientNetworkResources | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        $CurrentTCPRTT = $SessionRemoteFXCounters | ? path -match $Patterns.TCPRTT | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        
        $session.DroppedFramesServer = $DroppedFramesServer
        $session.DroppedFramesClient = $DroppedFramesClient
        $session.DroppedFramesNetwork = $DroppedFramesNetwork
        $session.CurrentTCPRTT = $CurrentTCPRTT
       
       
        if ($DroppedFramesServer -gt 5 ) {
            $BottleNeck = "Server Resources: $($session.DroppedFramesServer) frames skipped"
        }
        elseif ($DroppedFramesNetwork -gt 5) {
            $BottleNeck = "Network Packetdrops: $($session.DroppedFramesNetwork) frames skipped"
        }
        elseif ($DroppedFramesClient -gt 5) {
            $BottleNeck = "Client: $($session.DroppedFramesClient) frames skipped"
        }
        #shows 400 ms when it cant calculate the RTT. so we exclude that
        elseif ($session.CurrentTCPRTT -gt 150 -and $session.CurrentTCPRTT -ne 400) {
            $BottleNeck = "Network Latency: $($session.CurrentTCPRTT) ms"
        }
        elseif ($session.WorstAPPResponseTime -gt $SlowApplicationResponsTime) {
            $BottleNeck = "Application $($session.WorstAPPName) ( $($session.WorstAPPResponseTime) ms)"
        }
        elseif ($session.AvgAppResponseTime -gt $generalSlowResponsTime -and $SlowApplicationCount -gt 5) {
            
            
            $BottleNeck = "Server Avg. Application response time: $($session.AvgAppResponseTime) ms. $SlowApplicationCount applications are slow. Server CPU utilization: $ServerCPUUtil% "
        }
        else {
            $BottleNeck = "None"
        }
        $session.BottleNeck = $BottleNeck
        
        #endregion        
    }

    # User Input Delay per Session(*)\* Input Delay
    

    #endregion


    return $sessions
}

function Monitor-RDS {
    $Logfilepath = Join-Path -Path $global:config.Logfolder -ChildPath "Monitor-RDS.csv"
    
    while ($true) {
        
        #Get-RDPSessions -MeasureTimeSeconds 5 |select * -ExcludeProperty SessionEvents| ft * 
        write-progress -id 0 -activity "Analyzing Performance. Let the script run in background." -status (get-date)
        write-progress -id 1 -activity "Outputting to $Logfilepath"
        
        $Bottlenecks = Get-RDPSessions -MeasureTimeSeconds 1 | ? state -eq "active"
        if (ISInteractive) {
            $Bottlenecks | ft -AutoSize Datetime, username, RemoteIP, BottleNeck, DroppedFramesServer, DroppedFramesClient, DroppedFramesNetwork, CurrentTCPRTT, AvgAppResponseTime, WorstAPPName, WorstAPPResponseTime
        }
        $Bottlenecks | ? bottleneck -ne "none" | select Datetime, username, RemoteIP, BottleNeck, DroppedFramesServer, DroppedFramesClient, DroppedFramesNetwork, CurrentTCPRTT, AvgAppResponseTime, WorstAPPName, WorstAPPResponseTime | export-csv  $Logfilepath -NoTypeInformation -Append
    }
    
}
#endregion Monitor-RDS

#region PingTool
Function New-IntervalPing {

    [Alias("iping")]
    Param(
        [string]$ComputerName = "1.1.1.1",
        [int]$Count = 10,
        [int]$TimeOut = 100,
        [int]$Interval = 100
    )
  
    $successCount = 0
    $Ping = [System.Net.NetworkInformation.Ping]::New()
    $results = 1..$Count | ForEach-Object {
        
        $PingResult = $Ping.Send($ComputerName, $TimeOut)
        if ($PingResult.Status -eq "Success") {
            $successCount += 1
            $PingResult.RoundtripTime
        }
        else {
            $TimeOut + 1
        }
        
        start-sleep -Milliseconds $Interval
    }
    
    $packetLossPercent = ($Count - $successCount) / $Count * 100
    $maxRoundtrip = ($results | Measure-Object -Maximum).Maximum

    $percentile99 = $results | Sort-Object -Descending | Select-Object -Skip (($Count - ($Count * 0.99))) | Select-Object -First 1
    $percentile95 = $results | Sort-Object -Descending | Select-Object -Skip (($Count - ($Count * 0.95))) | Select-Object -First 1
    $averageRoundtrip = ($results | Measure-Object -Average).Average
    $minRoundtrip = ($results | Measure-Object -Minimum).Minimum
    
    $stddevresult = Get-StandardDeviation $results

    return [pscustomobject]@{
        "stddev"              = $stddevresult.stddev
        "stddevpercent"       = $stddevresult.stddevpercent
        "MaxRoundTrip"        = $maxRoundtrip
        "99PercentileLatency" = $percentile99
        "95PercentileLatency" = $percentile95
        "AverageRoundTrip"    = $averageRoundtrip
        "MinRoundTrip"        = $minRoundtrip
        "PacketLossPercent"   = $packetLossPercent
        "Count"               = $successCount
    }
}
Function New-IntervalPingJob {

    [Alias("iping")]
    Param(
        [string[]]$ComputerNames = @("1.1.1.1", "8.8.8.8"),
        [int]$Count = 60,
        [int]$runtimeMinutes = 10,
        [int]$TimeOut = 1000,
        [int]$Interval = 1000,
        [string]$LogFolder = "C:\CloudFactoryToolbox\Logs",
        [switch]$RestartJobs = $False
    )
    
    if ($RestartJobs) {
        Get-Job "Ping*" -ErrorAction SilentlyContinue | Stop-Job | remove-job 
    }
    
    $jobs = @()
    $computerNames | ForEach-Object {
        $computerName = $_
        $Jobname = "Ping$computerName"
        Get-Job -name $Jobname -ErrorAction SilentlyContinue | ? state -NE "running" | remove-job 
        if (!((Get-Job -name $Jobname -ErrorAction SilentlyContinue).State -eq "running")) {
            #job already running. Skip
            
            $job = Start-Job -name $Jobname -ScriptBlock {
                param($ComputerName, $Count, $TimeOut, $Interval, $LogFolder, $runtimeMinutes)
                $stopwatch = New-Object System.Diagnostics.Stopwatch

                $Ping = [System.Net.NetworkInformation.Ping]::New()
                do {
                    $output = 1..$Count | ForEach-Object {

                        $PingResult = $Ping.Send($ComputerName, $TimeOut)
                        [PSCustomObject]@{
                            Status        = $PingResult.Status
                            RoundtripTime = $PingResult.RoundtripTime
                        }
                 
                        Start-Sleep -Milliseconds $Interval

                    }


                    #output to file
                    $timestamp = (Get-Date).ToString("HH-mm-ss")
                    $logPath = Join-Path -Path $LogFolder -ChildPath "Ping-$ComputerName-$timestamp.csv"
                    $output | Export-Csv -Path $logPath -Force -Delimiter ";"
               
                
                    Start-Sleep -Milliseconds $Interval
                
                }until($stopwatch.Elapsed.TotalMinutes -ge $runtimeMinutes)

            


            } -ArgumentList $computerName, $Count, $TimeOut, $Interval, $LogFolder, $runtimeMinutes

            $jobs += $job
          
            
            
        }
       
    }

}
function Get-StandardDeviation {
    #Begin function Get-StandardDeviation
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [decimal[]]$value
    )

    #Simple if to see if the value matches digits, and also that there is more than one number.
    if ($value -match '\d+' -and $value.Count -gt 1) {

        #Variables used later
        [decimal]$newNumbers = $Null
        [decimal]$stdDev = $null
        
        #Get the average and count via Measure-Object
        $avgCount = $value | Measure-Object -Average | Select Average, Count
    
        if ($avgCount.Average -eq 0) {
            return [pscustomobject]@{
                'stddev'        = 0
                'stddevpercent' = 0
                'avg'           = 0
            } 
        }
        #Iterate through each of the numbers and get part of the variance via some PowerShell math.
        ForEach ($number in $value) {

            $newNumbers += [Math]::Pow(($number - $avgCount.Average), 2)

        }

        #Finish the variance calculation, and get the square root to finally get the standard deviation.
        $stdDev = [math]::Sqrt($($newNumbers / ($avgCount.Count - 1)))

        #Create an array so we can add the object we create to it. This is incase we want to perhaps add some more math functions later.
        [System.Collections.ArrayList]$formattedObjectArray = @()
        

        #Create a hashtable collection for the properties of the object
        Return [pscustomobject]@{
            'stddev'        = [double][Math]::Round($stdDev, 2)
            'stddevpercent' = [double][Math]::Round($stdDev / $avgCount.Average * 100, 2)
            'avg'           = [double][Math]::Round($avgCount.Average, 2)
        }


    }
    else {

        #Display an error if there are not enough numbers
        Write-Host "You did not enter enough numbers!" -ForegroundColor Red -BackgroundColor DarkBlue
 
    } 
      
}
function Calculate-Jitter {
    param (
        [float[]]$Latencies
    )

    # Calculate variations in interarrival times (latencies)
    $Variations = @()
    for ($i = 0; $i -lt $Latencies.Length - 1; $i++) {
        $Variations += [math]::Abs(($Latencies[$i + 1] - $Latencies[$i]))
    }

    # Calculate average jitter
    $Jitter = ($Variations | Measure-Object -Sum).Sum / $Variations.Length
    return [math]::Round($Jitter, 2)
}

function Calculate-MOS {
    param (
        [float]$Latency,
        [float]$Jitter,
        [float]$PacketLossPercent
    )

    # Calculate PacketLossImpact
    $PacketLossImpact = 2.5 * $PacketLossPercent

    # Simplified R-factor calculation
    $R = 94.2 - ($Latency + $Jitter) / 2 - $PacketLossImpact
    if ($R -lt 0) { $R = 0 }
    # Calculate MOS using the simplified formula
    $MOS = 1 + 0.035 * $R + 7 * [math]::Pow(10, -6) * $R * ($R - 60) * (100 - $R)

    return [math]::Round($MOS, 2)
}
function Analyze-PingData {
    [CmdletBinding()]
    param (
        [string]$LogFolder = "C:\CloudFactoryToolbox\Logs",
        $DatabasePath = "C:\CloudFactoryToolbox\Logs\PingDatabase.csv",
        [switch]$UploadToGoogleSheet = $false,
        [int]$PingInterval = 500,
        [int]$PingCount = 100
    )

    function Update-RunningAverage {
        param (
            $ExistingAverage,
            $NewValue,
            [int]$TotalCount = 10
        )

        [double]$ExistingAverage = $ExistingAverage -replace ",", "."
        [double]$NewValue = $NewValue -replace ",", "."
     
        if ($TotalCount -eq 1) {
            return $NewValue
        }

        $newAverage = ($ExistingAverage * ($TotalCount - 1) + $NewValue) / $TotalCount
        
        if ($newAverage -gt 1000) {
            Write-Warning "ExistingAverage $ExistingAverage"
            Write-Warning "NewValue $NewValue"
            Write-Warning "TotalCount $TotalCount"
            Write-Warning "newAverage $newAverage"
        }
        return $newAverage
    }

    function Round-Number {
        param ($number)
        return [math]::Round($number, 2)
    }
   
    # Read existing database
    $existingData = @()
    if (Test-Path $DatabasePath) {
        $existingData += Import-Csv -Path $DatabasePath -Delimiter ";"
    }

    # Get a list of all ping log files in the folder
    $files = Get-ChildItem -Path $LogFolder -Filter "Ping-*.csv" | Sort-Object -Property LastWriteTime
    <#
    $file=$files[0]
    #>

    foreach ($file in $files) {
        try {
            Write-Verbose "Processing file: $($file.FullName)"
            $pingResults = Import-Csv $file.FullName -Delimiter ";"
            $SuccessfullPingResults = $pingResults | Where-Object { $_.Status -eq "Success" }
            $successCount = $SuccessfullPingResults.Count
            $totalCount = $pingResults.Count
            $packetLossPercent = ($totalCount - $successCount) / $totalCount * 100

            Write-Verbose "Total pings: $totalCount, Successful pings: $successCount, Packet Loss: $packetLossPercent%"

            if ($successCount -gt 0) {
                $maxRoundtrip = ($SuccessfullPingResults | Measure-Object -Maximum RoundtripTime).Maximum
                $minRoundtrip = ($SuccessfullPingResults | Measure-Object -Minimum RoundtripTime).Minimum
                $averageRoundtrip = ($SuccessfullPingResults | Measure-Object -Average RoundtripTime).Average
                $jitter = Calculate-Jitter -Latencies ($SuccessfullPingResults | Select-Object -ExpandProperty RoundtripTime)
                $mos = Calculate-MOS -Latency $averageRoundtrip -Jitter $jitter -PacketLossPercent $packetLossPercent
            }
            else {
                $maxRoundtrip = 0
                $minRoundtrip = 0
                $averageRoundtrip = 0
                $jitter = 0
                $mos = 1  # Lowest possible MOS score
            }
            
            Write-Verbose "Max RTT: $maxRoundtrip, Min RTT: $minRoundtrip, Avg RTT: $averageRoundtrip, Jitter: $jitter, MOS: $mos"

            $mosCategory = Get-MOSCategory -MOS $mos

            $computerName = $file.BaseName.Split("-")[1]
            $currentDateTime = $file.LastWriteTime
            $Sourcecomputer = $env:COMPUTERNAME
            $SourceIP = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 | ForEach-Object { $_.IPAddressToString }

            $entry = [pscustomobject]@{
                "DateTimeFirst"     = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
                "DateTime"          = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
                "SourceComputer"    = $Sourcecomputer
                "SourceIP"          = $SourceIP
                "ComputerName"      = $computerName
                "PacketLossPercent" = Round-Number $packetLossPercent
                "Jitter"            = Round-Number $jitter
                "MOS"               = Round-Number $mos
                "MOSCategory"       = $mosCategory
                "MaxRoundTrip"      = Round-Number $maxRoundtrip
                "MinRoundTrip"      = Round-Number $minRoundtrip
                "AverageRoundTrip"  = Round-Number $averageRoundtrip
                "TotalCount"        = $totalCount
                "SuccessCount"      = $successCount
                "UniqueString"      = "$Sourcecomputer-$SourceIP-$computerName"
                "Reason"            = ""

            }

            #select the newest entry for the specific unique entry
            $existingEntry = $existingData | ? UniqueString -eq $entry.UniqueString | Sort-Object -Descending DateTimeFirst | select -first 1
            $NewEntryIntervalSeconds = ($PingInterval * $PingCount / 1000)
            
            
            #old entry exists
            if ($existingEntry) {

                #write-warning "Check if old entry is too old. Then we add a new entry"
                $existingMOSCategory = $existingEntry.MOSCategory
                $existingDateTimeFirst = [DateTime]::ParseExact($existingEntry.DateTimeFirst, "yyyy-MM-dd HH:mm:ss", $null)
                $existingDateTime = [DateTime]::ParseExact($existingEntry.DateTime, "yyyy-MM-dd HH:mm:ss", $null)


                Write-Verbose "Existing MOS Category: $existingMOSCategory, New MOS Category: $($entry.MOSCategory)"

                
                $SecondsSinceLastEntry = $currentDateTime - $existingDateTime | select -ExpandProperty TotalSeconds
                
                #Check if last entry is more the 3x interval time. Then create a new entry. This should only happen if script is paused.
                if ($SecondsSinceLastEntry -gt (5 * $NewEntryIntervalSeconds)) {
                
                    #Old entry is too old. we create new Entry

                    #Write-Warning "SecondsSinceLastEntry $SecondsSinceLastEntry is to high. creating new entry)"
                    $entry.reason = "Old entry is too old. we create new Entry"
                    $existingData += $entry

                    
                }
                
                else {
                    #write-warning "Old entry is strill fresh."


                    #MOS Category is the same as last measurement. Update the running averages
                    if ($entry.MOSCategory -eq $existingMOSCategory) {
                        
                        #UpdateTimeEntry
                        $existingEntry.DateTime = $entry.datetime

                        $timeDifference = ($currentDateTime - $existingDateTimeFirst).TotalSeconds
                        $measurementCount = [Math]::Ceiling($timeDifference / $NewEntryIntervalSeconds)

                        Write-Verbose "Time difference: $timeDifference seconds, Measurement count: $measurementCount"
                        $tempexistingEntry = $existingEntry | ConvertTo-Json | ConvertFrom-Json
                        $tempentry = $entry | ConvertTo-Json | ConvertFrom-Json

                        if ($measurementCount -gt 1) {
                            Write-Verbose "Updating running averages"

                            $existingEntry.PacketLossPercent = Round-Number (Update-RunningAverage -ExistingAverage $existingEntry.PacketLossPercent -NewValue $entry.PacketLossPercent -TotalCount $measurementCount)
                            $existingEntry.Jitter = Round-Number (Update-RunningAverage -ExistingAverage $existingEntry.Jitter -NewValue $entry.Jitter -TotalCount $measurementCount)
                        
                            #write-warning "Old Mos $($existingEntry.MOS)"
                            #Write-Warning "New Mos $($entry.MOS)"
                            #write-warning "Measurement count $measurementCount"
                            $existingEntry.MOS = Round-Number (Update-RunningAverage -ExistingAverage $existingEntry.MOS -NewValue $entry.MOS -TotalCount $measurementCount)
                            #Write-Warning "New Mos running avg. $($entry.MOS)"

                            $existingEntry.AverageRoundTrip = Round-Number (Update-RunningAverage -ExistingAverage $existingEntry.AverageRoundTrip -NewValue $entry.AverageRoundTrip -TotalCount $measurementCount)
                            $existingEntry.reason = "Updated old entry: $(get-date)"
                            
                            Write-Verbose "Updated values:"
                            Write-Verbose "PacketLossPercent: $($entry.PacketLossPercent), Jitter: $($entry.Jitter), MOS: $($entry.MOS), AverageRoundTrip: $($entry.AverageRoundTrip)"
                        

                        }
                    }
                    else {
                        Write-Warning "MOS Category changed. Creating a new entry."
                        # MOS Category changed, create a new entry
                        $entry.reason = "MOS Category changed. Creating a new entry"
                        $existingData += $entry
                    
                    }
                }
            }
            else {
                #no old entry exists. Create new entry
                $entry.reason = "no old entry exists. Create new entry"
                $existingData += $entry
            }


                
        }
        catch {
            Write-Warning "Error processing file $($file.FullName): $($_|out-string)"
        }

        try {
            Remove-Item -Path $file.FullName -Force
        }
        catch {
            Write-Warning "Can't remove file $($file.FullName): $_"
        }
    }

    if ($UploadToGoogleSheet) {
        Append-GoogleSheet -Data $existingData
    }

    # Write updated data back to CSV
    $existingData | sort DateTime, SourceComputer, SourceIP, ComputerName | Export-Csv -Path $DatabasePath -Delimiter ";" -NoTypeInformation


}

function Ping-IPRange {
    <#
    .SYNOPSIS
        Sends ICMP echo request packets to a range of IPv4 addresses between two given addresses.

    .DESCRIPTION
        This function lets you sends ICMP echo request packets ("pings") to 
        a range of IPv4 addresses using an asynchronous method.

        Therefore this technique is very fast but comes with a warning.
        Ping sweeping a large subnet or network with many swithes may result in 
        a peak of broadcast traffic.
        Use the -Interval parameter to adjust the time between each ping request.
        For example, an interval of 60 milliseconds is suitable for wireless networks.
        The RawOutput parameter switches the output to an unformated
        [System.Net.NetworkInformation.PingReply[]].

    .INPUTS
        None
        You cannot pipe input to this funcion.

    .OUTPUTS
        The function only returns output from successful pings.

        Type: System.Net.NetworkInformation.PingReply

        The RawOutput parameter switches the output to an unformated
        [System.Net.NetworkInformation.PingReply[]].

    .NOTES
        Author  : G.A.F.F. Jakobs
        Created : August 30, 2014
        Version : 6

    .EXAMPLE
        Ping-IPRange -StartAddress 192.168.1.1 -EndAddress 192.168.1.254 -Interval 0 -timeout 500
      
        IPAddress                                 Bytes                     Ttl           ResponseTime
        ---------                                 -----                     ---           ------------
        192.168.1.41                                 32                      64                    371
        192.168.1.57                                 32                     128                      0
        192.168.1.64                                 32                     128                      1
        192.168.1.63                                 32                      64                     88
        192.168.1.254                                32                      64                      0

        In this example all the ip addresses between 192.168.1.1 and 192.168.1.254 are pinged using 
        a 0 millisecond interval between each request.
        All the addresses that reply the ping request are listed.

    .LINK
        http://gallery.technet.microsoft.com/Fast-asynchronous-ping-IP-d0a5cf0e

    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    Param(
        [parameter(Mandatory = $false, Position = 0)]
        [System.Net.IPAddress]$StartAddress,
        [parameter(Mandatory = $false, Position = 1)]
        [System.Net.IPAddress]$EndAddress,
        [System.Net.IPAddress[]]$IPrange,

        [int]$Interval = 30,
        $timeout = 100,
        [Switch]$RawOutput = $false
    )

    #if range not specified, use the start and end address to create a range
    if (!($IPrange)) {
        function New-Range ($start, $end) {

            [byte[]]$BySt = $start.GetAddressBytes()
            [Array]::Reverse($BySt)
            [byte[]]$ByEn = $end.GetAddressBytes()
            [Array]::Reverse($ByEn)
            $i1 = [System.BitConverter]::ToUInt32($BySt, 0)
            $i2 = [System.BitConverter]::ToUInt32($ByEn, 0)
            for ($x = $i1; $x -le $i2; $x++) {
                $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
                [Array]::Reverse($ip)
                [System.Net.IPAddress]::Parse($($ip -join '.'))
            }
        }

        $IPrange = New-Range $StartAddress $EndAddress
    }
    $IpTotal = $IPrange.Count

    Get-Event -SourceIdentifier "ID-Ping*" | Remove-Event
    Get-EventSubscriber -SourceIdentifier "ID-Ping*" | Unregister-Event

    $IPrange | ForEach-Object {

        [string]$VarName = "Ping_" + $_.Address

        New-Variable -Name $VarName -Value (New-Object System.Net.NetworkInformation.Ping)

        Register-ObjectEvent -InputObject (Get-Variable $VarName -ValueOnly) -EventName PingCompleted -SourceIdentifier "ID-$VarName"

        (Get-Variable $VarName -ValueOnly).SendAsync($_, $timeout, $VarName)

        Remove-Variable $VarName

        try {

            $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count

        }
        catch [System.InvalidOperationException] {}

        $index = [array]::indexof($IPrange, $_)
        try {
            Write-Progress -Activity "Sending ping to" -Id 1 -status $_.IPAddressToString -PercentComplete (($index / $IpTotal) * 100)
            Write-Progress -Activity "ICMP requests pending" -Id 2 -ParentId 1 -Status ($index - $pending) -PercentComplete (($index - $pending) / $IpTotal * 100)
    
        }
        catch {
            
        }

        Start-Sleep -Milliseconds $Interval
    }

    try {
        Write-Progress -Activity "Done sending ping requests" -Id 1 -Status 'Waiting' -PercentComplete 100 
    }
    catch {
        # Handle any errors that occur during the execution of the code here
    }

    While ($pending -lt $IpTotal) {

        Wait-Event -SourceIdentifier "ID-Ping*" | Out-Null

        Start-Sleep -Milliseconds 10

        $pending = (Get-Event -SourceIdentifier "ID-Ping*").Count

        try {
            Write-Progress -Activity "ICMP requests pending" -Id 2 -ParentId 1 -Status ($IpTotal - $pending) -PercentComplete (($IpTotal - $pending) / $IpTotal * 100)
        }
        catch {
            # Handle any errors that occur during the execution of the code here
        }
    }

    if ($RawOutput) {

        $Reply = Get-Event -SourceIdentifier "ID-Ping*" | ForEach { 
            If ($_.SourceEventArgs.Reply.Status -eq "Success") {
                $_.SourceEventArgs.Reply
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }

    }
    else {

        $Reply = Get-Event -SourceIdentifier "ID-Ping*" | ForEach { 
            If ($_.SourceEventArgs.Reply.Status -eq "Success") {
                $_.SourceEventArgs.Reply | select @{
                    Name = "IPAddress"   ; Expression = { $_.Address }
                },
                @{Name = "Bytes"       ; Expression = { $_.Buffer.Length } },
                @{Name = "Ttl"         ; Expression = { $_.Options.Ttl } },
                @{Name = "ResponseTime"; Expression = { $_.RoundtripTime } }
            }
            Unregister-Event $_.SourceIdentifier
            Remove-Event $_.SourceIdentifier
        }
    }
    if ($Reply -eq $Null) {
        Write-Verbose "Ping-IPrange : No ip address responded" -Verbose
    }

    return $Reply
}
function Get-MOSCategory {
    param (
        [float]$MOS
    )

    switch ($MOS) {
        { $_ -ge 4.3 } { return "Excellent" }
        { $_ -ge 4.0 } { return "Good" }
        { $_ -ge 3.6 } { return "Fair" }
        { $_ -ge 3.1 } { return "Poor" }
        default { return "Bad" }
    }
}
function Get-TracerouteIPs {

    param($destination = "1.1.1.1", $Hopcount = 3)
    
    <#test params
    $destination="1.1.1.1"
    $Hopcount=3
    #>

    $Traceroute = Test-NetConnection -ComputerName $destination -TraceRoute -Hops $Hopcount
    $TracerouteIPs = $Traceroute.TraceRoute

    $RespondingIPs = (Ping-IPRange -iprange  $TracerouteIPs).IPAddress.IPAddressToString
    return $RespondingIPs
}
function Get-DefaultGateway {
    Get-WmiObject -Class Win32_IP4RouteTable |  
    where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0' } |
    Sort-Object metric1 | select -first 1 -ExpandProperty nexthop
}
function PingTool {
    $pings = @(
        "1.1.1.1"
        "1.0.0.1"
        "8.8.8.8"
        "8.8.4.4"
    )

    #$pings += (Ping-IPRange -StartAddress 10.245.100.1 -EndAddress 10.245.100.254).IPAddress.IPAddressToString
    #$pings += (Ping-IPRange -StartAddress 10.245.110.1 -EndAddress 10.245.110.254).IPAddress.IPAddressToString

    #add all pingable trace route ips
    $RespondingTraceRouteIPs = Get-TracerouteIPs -destination "1.1.1.1" -Hopcount 1
    $pings += $RespondingTraceRouteIPs

    #add default gateway in case its not pingable
    $DefaultGateway = Get-DefaultGateway
    $pings += $DefaultGateway

    $pings = $pings | Sort-Object -Unique
    $pings = (Ping-IPRange -iprange $pings).IPAddress.IPAddressToString

    Write-Output "Pinging following IPs"
    $pings
    get-job | Stop-Job | Remove-Job
    $interval = 500
    $count = 100 #count needs to be high for the percent calculation to be accurate. 100+ is good.
    New-IntervalPingJob -ComputerNames $pings -Interval $interval -Count $count -LogFolder "C:\CloudFactoryToolbox\Logs" -RestartJobs $true
    while ($true) {
        #get-job
        Analyze-PingData -PingInterval $interval -PingCount $count | out-null
        Start-Sleep -Seconds 1
    }
    get-job | Stop-Job | Remove-Job
}

#endregion PingTool

#region Helper functions
function Append-GoogleSheet {
    param (
        $Endpoint = "https://script.google.com/macros/s/AKfycbwuNMkMVNgkTq7eo3a5fcKWI2cAMVfZ_HrHd9Gs1j89lfRHt7gcCPN5Kmzf3MGnZMKbBQ/exec",
        $SheetName = "Ping",
        $Data = $pingData
    )
    #region Google Sheet Script
    #function doPost(e) {
    #    var requestData;
    #    if (e) {
    #      requestData = JSON.parse(e.postData ? e.postData.contents : "{}");
    #    } else {
    #      // Use the provided JSON test data as dummy data
    #      requestData = {
    #        sheetName: 'Ping', // Ensure this sheet name exists in your spreadsheet
    #        data: [
    #          { Age: 25, Name: 'Jane Doe', Email: 'jane@example.com', Country: 'USA' }, 
    #          { Name: 'John Doe', Age: 30, Email: 'john@example.com' },
    #          { Name: 'Mike Smith', Age: 28 } // Note: Missing 'Email' and 'Country'
    #        ]
    #      };
    #    }
    #  
    #  
    #      var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(requestData.sheetName);
    #      var data = requestData.data;
    #  
    #      // Get current headers or initialize if sheet is empty
    #      var isFirstRun = sheet.getLastColumn() === 0;
    #      var dataKeys = data.length > 0 ? Object.keys(data[0]) : [];
    #  
    #      // If first run, set headers to keys of the first data item
    #      if (isFirstRun) {
    #        headers = dataKeys;
    #        sheet.appendRow(headers);
    #      } else {
    #        var range = sheet.getRange(1, 1, 1, sheet.getLastColumn());
    #      var headers = range.getValues()[0].filter(String); // Remove empty strings to get actual headers
    #     
    #        // Check for any new headers in incoming data and add them
    #        dataKeys.forEach(function(key) {
    #          if (!headers.includes(key)) {
    #            headers.push(key);
    #            sheet.getRange(1, headers.length).setValue(key); // Add new header to the sheet
    #          }
    #        });
    #      }
    #  
    #      // Append data rows, ensuring values align with headers
    #      data.forEach(function(item) {
    #        var row = headers.map(function(header) {
    #          return item.hasOwnProperty(header) ? item[header] : "";
    #        });
    #        sheet.appendRow(row);
    #      });
    #  
    #  }
    
    #endregion

    #force the data to be an array
    $Dataarray = @()
    $Dataarray += $Data
    # Create the request body
    $requestBody = @{
        sheetName = $sheetName
        data      = $Dataarray
    }
    # use depth 1 since we can only output text
    $jsonRequestBody = $requestBody | ConvertTo-Json -Depth 2

    Write-Verbose "Outputting JSON Request Body:"
    Write-Verbose ($jsonRequestBody | out-string)
    Invoke-RestMethod -Uri $endpoint -Method Post -Body $jsonRequestBody -ContentType "application/json"
}
function Select-FromStringArray {
    param(
        $title = "please select",
        [string[]]$options = ("test1", "Test2")
    )
    $prompt = "`n"
    $i = 1
    foreach ($option in $options) {
        $prompt += "$i - $option`n"
        $i++
    }
    $prompt += "Select option"
    $MenuChoice = Read-Host -Prompt $prompt
    $choice = $options[$MenuChoice - 1]
    if ($null -eq $choice) {
        throw "Invalid choice"
        
    }
    else {
        return $choice
    }
    

}


function Initialize-Config {
    $Rootfolder = "C:\CloudFactoryToolbox"
    $Logfolder = join-path -Path $Rootfolder -ChildPath "Logs"
    [pscustomobject]$global:config = @{
        Logfolder    = $Logfolder
        ErrorLogPath = join-path -Path $Logfolder -ChildPath "Errors.log"
    }
    #create logfolder if it doesnt exist. including parent folders
    if (!(Test-Path -Path $Logfolder)) {
        New-Item -ItemType Directory -Force -Path $Logfolder
    } 
}

function ISElevated {
    #check if script is running elevated. Elevate if not.
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        return $false
    }
    else {
        return $true
    }
    
}
function ISInteractive {
    [System.Environment]::UserInteractive
}
function Update-Toolbox {
    Invoke-RestMethod toolbox.cloudfactory.dk | invoke-expression
    exit
}
function Refresh {
    Clear-Host

}
#endregion Helper functions

#region Scheduled tasks
function Create-ScheduledTask {
    param(
        
        [string]$ScriptAction = "Monitor-RDS"

    )
    [string]$TaskName = "CloudFactoryToolboxTask-$ScriptAction"
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    if (-not $TaskExists) {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-file $($MyInvocation.MyCommand.ScriptBlock.File) -scriptaction $ScriptAction"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -MultipleInstances IgnoreNew
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal
    }
}

function Delete-ScheduledTask {
    param(
        
        [string]$ScriptAction = "Monitor-RDS"

    )
    [string]$TaskName = "CloudFactoryToolboxTask-$ScriptAction"
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    if ($TaskExists) {
        Stop-ScheduledTask -TaskName $TaskName
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}




function CreateAndStartTask {
    param(
        [string]$ScriptAction = "Monitor-RDS"
    )
    Create-ScheduledTask -ScriptAction $ScriptAction
    Start-ScheduledTask -TaskName "CloudFactoryToolboxTask-$ScriptAction"
    Write-Host "$ScriptAction task has been created and started"

}

function StopAndDeleteTask {
    param(
        [string]$ScriptAction = "Monitor-RDS"
    )
    Stop-ScheduledTask -TaskName "CloudFactoryToolboxTask-$ScriptAction"
    Delete-ScheduledTask -ScriptAction $ScriptAction
    Write-Host "$ScriptAction task has been stopped and deleted"
}


function Start-Monitor-RDS {
    $Action="Monitor-RDS"
    CreateAndStartTask -ScriptAction $Action
}

function Stop-Monitor-RDS {
    $Action="Monitor-RDS"
    StopAndDeleteTask -ScriptAction $Action
}

function Start-PingTool {
    $Action="PingTool"
    CreateAndStartTask -ScriptAction $Action
}

function Stop-PingTool {
    $Action="PingTool"
    StopAndDeleteTask -ScriptAction $Action
}
#endregion Scheduled tasks

#endregion

$ErrorActionPreference = "Stop"
try {
    #write host which script is running
    Write-Host "Running $($MyInvocation.MyCommand.ScriptBlock.File)"

    #elavate to admin if not already
    #region mainloop
    if (-not (ISElevated)) {
        write-host -ForegroundColor Red "Script was started without elevation. Restart with elevation!"
        Start-Sleep -second 10
        exit
    }

    Initialize-Config

    switch ($scriptaction) {
        PingTool {
            PingTool
        }
        Monitor-RDS {
            Monitor-RDS
        }
        Default {
            #region check if a new version of the script is available
            try {
                $localscript = Get-Item -Path $MyInvocation.MyCommand.ScriptBlock.File
                $localscriptcontent = Get-Content -Path $localscript.FullName -Raw
                $remotescriptcontent = Invoke-RestMethod "https://raw.githubusercontent.com/cloudfactorydk/PSToolbox/main/Main.ps1"
                if ($localscriptcontent -ne $remotescriptcontent) {
                    write-host -ForegroundColor Blue "New version of script is available."
                }
            }
            catch {
                Write-Warning "Can't check for new version of script."
            }
            #endregion



            #region menuloop
            while ($true) {
                Write-Output "Current Config:`n $($global:config|out-string)"

                #show running scheduled tasks
                $ScheduledTasks = Get-ScheduledTask -TaskName "CloudFactoryToolboxTask-*" -ErrorAction SilentlyContinue
                if ($ScheduledTasks) {
                    Write-Host "Running Scheduled Tasks:"
                    $ScheduledTasks | ft TaskName, State, LastRunTime, NextRunTime
                }
                else {
                    Write-Host "No Scheduled Tasks are running"
                }

                $Action = Select-FromStringArray -title "Choose Action" -options @(
                    "Start-PingTool"
                    "Stop-PingTool"
                    "Start-Monitor-RDS" 
                    "Stop-Monitor-RDS"
                    "Update-Toolbox"
                    "Refresh"
                    "Exit"
        
                )
                $ActionSB = ([scriptblock]::Create($action))
                Invoke-Command -ScriptBlock $ActionSB

            }

            #endregion

        }

    }

}
catch {
    try {
        $_ | Out-String 

        $_ | Out-String | Out-File -FilePath $global:config.ErrorLogPath -Append
    }
    catch {}

    #pause if script is interactive
    if (ISInteractive) {
        pause
    }


}

#endregion
