param(
    [ValidateSet("Interactive", "Monitor-RDS")]
    [string]$scriptaction = "Interactive"
)

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


function Start-Monitor-RDS {
    Create-ScheduledTask -ScriptAction "Monitor-RDS"
    Start-ScheduledTask -TaskName "CloudFactoryToolboxTask-Monitor-RDS"
    Write-Host "Monitor-RDS task has been created and started"
}

function Stop-Monitor-RDS {
    Delete-ScheduledTask -ScriptAction "Monitor-RDS"
    Write-Host "Monitor-RDS task has been stopped and deleted"
}

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
                    "Start-Monitor-RDS" 
                    "Stop-Monitor-RDS"
                    "Update-Toolbox"
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
