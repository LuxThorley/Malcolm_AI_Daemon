# sign_policy.ps1
# Generates policy.sig for MalcolmAI daemon using HMAC-SHA256 + key "I_AM_AETHORIAN"

$policyPath = "policy.json"
$sigPath    = "policy.sig"
$key        = [Text.Encoding]::UTF8.GetBytes("I_AM_AETHORIAN")

# Read policy.json as raw bytes
$message = [System.IO.File]::ReadAllBytes($policyPath)

# Create HMAC-SHA256 object
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $key

# Compute the HMAC
$hashBytes = $hmac.ComputeHash($message)

# Convert to lowercase hex
$hex = -join ($hashBytes | ForEach-Object { $_.ToString("x2") })

# Save to policy.sig
Set-Content -Path $sigPath -Value $hex -Encoding ASCII

Write-Host "policy.sig generated:"
Write-Host $hex
