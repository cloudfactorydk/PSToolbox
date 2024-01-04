$counters=@(
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000000ms & <000001ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000001ms & <000002ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000002ms & <000005ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000005ms & <000010ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000010ms & <000020ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000020ms & <000050ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000050ms & <000100ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000100ms & <000200ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000200ms & <000500ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=000500ms & <001000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=001000ms & <002000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=002000ms & <005000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=005000ms & <010000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=010000ms & <020000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=020000ms & <050000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=050000ms & <100000ms"
"\\cfportalsqln01\SQLServer:Batch Resp Statistics(Elapsed Time:Requests)\Batches >=100000ms"
)

 $timeframe = 30 # Timeframe in seconds
 $threshold = 50 # Threshold in milliseconds for fast requests
 $fastRequests = 0
 $slowRequests = 0


 $lastCounterValues = @{}
 $lasttimestamp=get-date
 while($true) {
     $counterValues = Get-Counter -Counter $counters -SampleInterval 1 -MaxSamples 1
     $timestamp = $counterValues.Timestamp
     $totalResponseTime=0
     $totalRequests = 0
     $fastRequests =0
     $slowRequests =0

     foreach($counterSample in $counterValues.CounterSamples) {
         $counter = $counterSample.Path
         $counterValue = $counterSample.CookedValue
         $deltaValue = 0
         
         if ($lastCounterValues.ContainsKey($counter)) {
             $deltaValue = $counterValue - $lastCounterValues[$counter]
            
         }
         $lastCounterValues[$counter] = $counterValue
         
         $match=$counter -match "(\d+)ms.*?$"
         [int]$responseTime=$matches[1]
         $totalRequests += $deltaValue
         $totalResponseTime += $deltaValue * $responseTime
         if($responseTime -lt $threshold) {
             $fastRequests += $deltaValue
         } else {
             $slowRequests += $deltaValue
         }
         "$counter $deltaValue $responseTime ms"
         
     }
        
     $elapsedTime =  $timestamp - $lasttimestamp
     $lasttimestamp=$timestamp
     $fastRequestsPerSec = $fastRequests / $elapsedTime.TotalSeconds
     $slowRequestsPerSec = $slowRequests / $elapsedTime.TotalSeconds
     Write-Output "Fast requests per second: $fastRequestsPerSec"
     Write-Output "Slow requests per second: $slowRequestsPerSec"
     if($totalRequests -gt 0) {
         $avgResponseTime = $totalResponseTime / $totalRequests
         Write-Output "Average response time: $avgResponseTime ms"
     }

     Start-Sleep -Seconds $timeframe
 }

