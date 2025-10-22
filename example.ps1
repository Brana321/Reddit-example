
# Min example of the PSexec
# $result = @{
#   Hostname = $env:COMPUTERNAME
#   OS = (Get-CimInstance Win32_OperatingSystem).Caption
#   Timestamp = (Get-Date).ToString("o")
# }
# $result | ConvertTo-Json -Depth 4
