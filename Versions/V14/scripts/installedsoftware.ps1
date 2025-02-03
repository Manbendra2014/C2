# List Installed Software

$installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version

Write-Output "Installed Software:"
$installedSoftware | ForEach-Object { Write-Output "$($_.Name) - $($_.Version)" }
