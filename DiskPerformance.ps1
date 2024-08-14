
    #region Performance Measurement
   $MeasureTimeSeconds=10
    while ($true){
    $LogicalDiskCounters = Get-Counter -ListSet "LogicalDisk" | select -expand PathsWithInstances | ? { $_ -match ":" -and ($_ -match "% Idle Time" -or $_ -match "Avg. Disk sec/Transfer" -or  $_ -match "Avg. Disk Bytes/Transfer" ) }

    $Counters = @(
       #"\TCPIP Performance Diagnostics\TCP successful loss recovery episodes" #only newer OS supports
       "\TCPv4\Segments Retransmitted/sec"
       "\Processor(_Total)\% Processor Time"
       "\memory\page reads/sec"
       "\memory\available bytes"
       "\memory\long-term average standby cache lifetime (s)"
    )
    $counters += $LogicalDiskCounters
    try {
        Write-Progress -Activity "Monitoring" -Status (get-date)
        #Measuring

        $PerformanceData = Get-Counter -ErrorAction Stop -Counter $Counters -MaxSamples 1 -SampleInterval $MeasureTimeSeconds
        
        #region analysis

        #Get-Counter -ListSet * | select -expand Paths | select-string "logicaldisk" | select-string "bytes"
        $output=[pscustomobject]@{
            DateTime=(get-date)
            Bottleneck=@()
            Message=@()
        }
        
        #region disk analysis

        $DiskCounters=$PerformanceData.CounterSamples| ? path -match "logicaldisk" | Group-Object -Property Instancename
        foreach ($DiskCounter in $DiskCounters){
            $DriveLetter=$DiskCounter.name
            $IdleTime=$DiskCounter.Group|? path -Match "idle time" | select -ExpandProperty CookedValue
            [int]$KBytesPerTransfer=($DiskCounter.Group|? path -Match "Avg. Disk Bytes/Transfer" | select -ExpandProperty CookedValue)/1024
            
            [int]$TransferTime=($DiskCounter.Group|? path -Match "disk sec/transfer" | select -ExpandProperty CookedValue)*1000
            
            if ($IdleTime -lt 5 -and $TransferTime -gt 10){
                $output.Bottleneck+="Disk $DriveLetter"
                $output.message+="$DriveLetter idletime: $IdleTime%. $TransferTime ms. Bytes pr transfer: $KBytesPerTransfer KB"

            }
           
        }
        #endregion
        
        #region CPU
        [int]$CPUUtil=$PerformanceData.CounterSamples|? path -Match "% processor time" | select -ExpandProperty CookedValue
        if ($CPUUtil -gt 75){
             $output.Bottleneck+="CPU"
             $output.message+="CPU Utilization is $CPUUtil %"
        }

        #endregion
        #region Network
        [int]$Retransmits=$PerformanceData.CounterSamples|? path -Match "segments retransmitted" | select -ExpandProperty CookedValue
        if ($Retransmits -gt 10){
             $output.Bottleneck+="Network"
             $output.message+="$Retransmits pps lost on the network"
        }

        #endregion

        #region Memory
        $availableGB=[math]::round((($PerformanceData.CounterSamples|? path -Match "available bytes" | select -ExpandProperty CookedValue) /1GB),1)
        [int]$CacheLifetimeSeconds=($PerformanceData.CounterSamples|? path -Match "long-term average standby cache lifetime" | select -ExpandProperty CookedValue)
        [int]$HardFaults=($PerformanceData.CounterSamples|? path -Match "page reads/sec" | select -ExpandProperty CookedValue)
        
        
        if ($availableGB -gt 1){
            $output.Bottleneck+="Memory"
            $output.message+="$HardFaults Hardfaults/s. $availableGB GB available memory. Cachelifetime seconds: $CacheLifetimeSeconds"
             

        }



        #endregion

        #endregion
    }
    catch {
        
    }

    $output|? bottleneck | ft
    }
