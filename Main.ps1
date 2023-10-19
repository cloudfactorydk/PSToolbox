#region functions



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
        if ($user) {
            $idletime = $user.Substring(54, 9).Trim()
            $session.IdleTime = $idletime
            $session.Idle = $idletime -eq "\."
            $session.LogonTime = get-date ($user.Substring(65, 16).Trim())
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
    #create variable with all performancecounter instances with the names from the list below
    $Counters = @(
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Server Resources"
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Network Resources"
        "\RemoteFX Graphics(*)\Frames Skipped/Second - Insufficient Client Resources"
        "\RemoteFX Graphics(*)\Average Encoding Time"
        "\RemoteFX Graphics(*)\Output Frames/Second"
        "\RemoteFX Network(*)\Current TCP RTT"
        "\RemoteFX Network(*)\Current UDP RTT"
        #"\User Input Delay per Session(*)\Max Input Delay"
        "\User Input Delay per Process(*)\Max Input Delay"
        "\Processor(_Total)\% Processor Time"
    )
    try {
        $PerformanceData = Get-Counter -ErrorAction Stop -Counter $Counters -MaxSamples $MeasureTimeSeconds -SampleInterval 1
   
    }
    catch {
        continue
    }
    #test
    
    #threshold in ms for application response time to be considered slow
    $SlowApplicationResponsTime=500
    #threshold in ms for general response time to be considered slow. This is used to determine if the server is overloaded
    $GeneralSlowResponsTime=150

    [int]$ServerCPUUtil=$PerformanceData.CounterSamples | ? path -match "% Processor Time" | sort cookedvalue -Descending | select -first 1 | select -ExpandProperty CookedValue
    #$session = $sessions | ? username -eq "laajadmin"
    foreach ($session in $sessions | ? state -eq "active" ) {
       
        #region App Responsetime
        $SlowApplicationCount=$PerformanceData.CounterSamples | ? path -match "user input delay per process" | ? cookedvalue -gt $GeneralSlowResponsTime  | measure |select -ExpandProperty count
        
        $AvgAppResponseTime = $PerformanceData.CounterSamples | ? path -match "user input delay per process" | ? instanceName -match "^$($session.Id)" | ? cookedvalue -gt 0 | measure -Average -Property cookedvalue | select -ExpandProperty Average
        $session.AvgAppResponseTime = $AvgAppResponseTime
            
        $WorstAPP = $PerformanceData.CounterSamples | ? path -match "user input delay per process" | ? instanceName -match "^$($session.Id)" | sort cookedvalue -Descending | select -first 1
            
        $null = $WorstAPP.instancename -match "<(.+?)>"
        $session.WorstAPPName = $matches[1]
        $session.WorstAPPResponseTime = $WorstAPP.CookedValue
        #endregion

        #region Resources
        $SessionRemoteFXCounters = $PerformanceData.CounterSamples | ? path -match "RemoteFX" | ? path -match "\(rdp-tcp $($session.SessionNameRDP)\)"
       
        [int]$DroppedFramesServer = $SessionRemoteFXCounters | ? path -match "insufficient server resources" | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        [int]$DroppedFramesClient = $SessionRemoteFXCounters | ? path -match "insufficient client resources" | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        [int]$DroppedFramesNetwork = $SessionRemoteFXCounters | ? path -match "insufficient network resources" | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        $CurrentTCPRTT = $SessionRemoteFXCounters | ? path -match "current tcp rtt" | sort CookedValue -desc | select -first 1 | select -ExpandProperty CookedValue
        
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
function Select-FromStringArray {
    param(
        $title = "please select",
        [string[]]$options = ("test1", "Test2")
    )
    $prompt = "`n"
    $i = 0
    foreach ($option in $options) {
        $prompt += "$i - $option`n"
        $i++
    }
    $prompt += "Select option"
    $MenuChoice = Read-Host -Prompt $prompt
    $choice = $options[$MenuChoice]
    if ($null -eq $choice) {
        throw "Invalid choice"
        
    }
    else {
        return $choice
    }
    

}

function Monitor-RDS{
    while ($true) {

        #Get-RDPSessions -MeasureTimeSeconds 5 |select * -ExcludeProperty SessionEvents| ft * 
        write-progress -activity "Analyzing Performance" -status (get-date)
        $Bottlenecks = Get-RDPSessions -MeasureTimeSeconds 1 | ? state -eq "active"
        $Bottlenecks | ft -AutoSize Datetime, username, RemoteIP, BottleNeck, DroppedFramesServer, DroppedFramesClient, DroppedFramesNetwork, CurrentTCPRTT, AvgAppResponseTime, WorstAPPName, WorstAPPResponseTime
        $Bottlenecks | ? bottleneck -ne "none"| export-csv "$($PSScriptRoot)\Bottlenecks.csv" -NoTypeInformation -Append
    }
    
}


#endregion



while ($true) {
    try {
        $Action = Select-FromStringArray -title "Choose Action" -options @(
            "Monitor-RDS"
            

        )
        $ActionSB = ([scriptblock]::Create($action))
        Invoke-Command -ScriptBlock $ActionSB
    }
    catch {
        Write-Warning $_ | Out-String
    }
}