# Obtain all saved Wi-Fi passwords

# Get all the Wi-Fi profiles stored on the computer
$profiles = netsh wlan show profiles

# Extract the names of all the profiles
$profiles = $profiles | Select-String "All User Profile" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }

# Loop through each profile and get its corresponding password (if available)
foreach ($profile in $profiles) {
    # Show the profile name
    Write-Host "Profile: $profile"
    
    # Get the key (password) associated with the profile
    $key = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }

    # Check if the key is found
    if ($key) {
        Write-Host "Password: $key" -ForegroundColor Green
    } else {
        Write-Host "Password: Not found (may be hidden)" -ForegroundColor Red
    }
    Write-Host "-----------------------------"
}
