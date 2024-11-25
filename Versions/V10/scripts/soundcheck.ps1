# Run a beep sound-check
for ($i = 500; $i -lt 2000; $i += 100) {
    [console]::beep($i, 200)
}
