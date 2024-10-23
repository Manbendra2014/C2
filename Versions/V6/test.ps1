# Open a new instance of Notepad
$notepadProcess = Start-Process -FilePath "notepad.exe" -PassThru
# Wait for Notepad to fully load (2 seconds for most systems, adjust if needed)
Start-Sleep -Seconds 2
# Send "Hello World" to Notepad
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("Welcome , My name is Ghost.")