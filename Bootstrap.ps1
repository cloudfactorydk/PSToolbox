Invoke-RestMethod "https://raw.githubusercontent.com/cloudfactorydk/PSToolbox/main/Main.ps1" | invoke-expression
irm toolbox.cloudfactory.dk | iex
iex (New-Object Net.WebClient).DownloadString('http://toolbox.cloudfactory.dk')
iex(irm toolbox.cloudfactory.dk)
