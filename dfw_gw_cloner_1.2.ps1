# =====================================================================
# Clone DFW Policy → New Gateway Policy (Dynamic Inputs)
# Auto-detects if Gateway policy exists
#   → PUT = create
#   → PATCH = update
# =====================================================================

$nsx_url = Read-Host "Enter NSX Manager FQDN or IP"
$creds   = Get-Credential -Message "Enter NSX credentials"

# ==== HEADERS =============================================================
$base64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(
        "$($creds.username):$($creds.GetNetworkCredential().Password)"
    )
)
$headers = @{ Authorization = "Basic $base64" }

Write-Host "`nTesting NSX Authentication..."

try {
    $test=Invoke-RestMethod -Uri "https://$nsx_url/policy/api/v1/infra" -Headers $headers -SkipCertificateCheck -ErrorAction Stop
    Write-Host "✅ Authenticated successfully."
}
catch {
    Write-Host "❌ Authentication FAILED!" -ForegroundColor Red
    exit
}

# Ask user for DFW Policy Name (Display Name, usually same as ID)
$dfw_name = Read-Host "Enter the *display name* of the DFW policy you want to clone"
$dfw_id = $dfw_name

# Ask user for T0 Gateway Name
$t0_name = Read-Host "Enter the *display name* of the T0 Gateway to apply to"

# =====================================================================
# Validate T0 exists
# =====================================================================
$t0_check_ep = "https://$nsx_url/policy/api/v1/infra/tier-0s/$t0_name"

Write-Host "`nValidating T0 Gateway '$t0_name'..." -ForegroundColor Cyan

try {
    $t0_obj = Invoke-RestMethod -Uri $t0_check_ep -Headers $headers -Method GET -SkipCertificateCheck
    Write-Host "✔ T0 Gateway found." -ForegroundColor Green
}
catch {
    Write-Host "❌ ERROR: T0 Gateway '$t0_name' not found in NSX!" -ForegroundColor Red
    Write-Host "Please verify the T0 name exactly as it appears in NSX Manager." -ForegroundColor Yellow
    exit
}

# Scope is only assigned AFTER validation succeeds
$t0_scope = "/infra/tier-0s/$t0_name"

# New Gateway Policy name
$new_gw_id = "$dfw_name-gw"

# --- Build Auth Header ---
$username = $creds.UserName
$password = $creds.GetNetworkCredential().Password
$token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$username`:$password"))
$headers = @{
    Authorization = "Basic $token"
    "Content-Type" = "application/json"
}

# --- Endpoints ---
$dfw_ep = "https://$nsx_url/policy/api/v1/infra/domains/default/security-policies/$dfw_id"
$gw_ep  = "https://$nsx_url/policy/api/v1/infra/domains/default/gateway-policies/$new_gw_id"

# ============================================================
# Fetch DFW policy
# ============================================================
Write-Host "`nFetching DFW policy '$dfw_name'..." -ForegroundColor Cyan

try {
    $dfw = Invoke-RestMethod -Uri $dfw_ep -Headers $headers -Method GET -SkipCertificateCheck
} catch {
    Write-Host "❌ ERROR: DFW policy '$dfw_name' not found!" -ForegroundColor Red
    exit
}

# ============================================================
# Build NEW Gateway Policy
# ============================================================
$newGatewayPolicy = @{
    "resource_type"   = "GatewayPolicy"
    "id"              = $new_gw_id
    "display_name"    = $new_gw_id
    "description"     = "Cloned automatically from DFW policy '$dfw_name'"
    "sequence_number" = $dfw.sequence_number
    "rules"           = @()
}

# ============================================================
# Convert each DFW rule → valid Gateway rule
# ============================================================
foreach ($rule in $dfw.rules) {

    $newRule = @{
        "resource_type"      = "Rule"
        "id"                 = $rule.id + "_gw"
        "display_name"       = $rule.display_name
        "action"             = $rule.action
        "sequence_number"    = $rule.sequence_number
        "source_groups"      = $rule.source_groups
        "destination_groups" = $rule.destination_groups
        "services"           = $rule.services
        "logged"             = $rule.logged
        "direction"          = $rule.direction
        "ip_protocol"        = $rule.ip_protocol
        "disabled"           = $rule.disabled

        # Always apply to selected T0
        "scope"              = @($t0_scope)
    }

    # Add rule into the GW policy array
    $newGatewayPolicy.rules += $newRule
}

# ============================================================
# Check if Gateway policy already exists
# ============================================================
$policyExists = $false

try {
    $existing = Invoke-RestMethod -Uri $gw_ep -Headers $headers -Method GET -SkipCertificateCheck
    $policyExists = $true
    Write-Host "`nGateway policy '$new_gw_id' already exists → will PATCH it" -ForegroundColor Yellow
}
catch {
    Write-Host "`nGateway policy '$new_gw_id' does not exist → will CREATE it" -ForegroundColor Green
}

# ============================================================
# Create or Update the Gateway Policy
# ============================================================

if ($policyExists) {

    # --- POLICY EXISTS → PATCH (update only) ---
    $response = Invoke-RestMethod -Uri $gw_ep `
        -Method Patch `
        -Headers $headers `
        -ContentType "application/json" `
        -SkipCertificateCheck `
        -Body ($newGatewayPolicy | ConvertTo-Json -Depth 40)

    Write-Host "`nUPDATED existing Gateway policy '$new_gw_id' successfully." -ForegroundColor Green
}
else {

    # --- POLICY DOES NOT EXIST → PUT (create new) ---
    $response = Invoke-RestMethod -Uri $gw_ep `
        -Method Put `
        -Headers $headers `
        -ContentType "application/json" `
        -SkipCertificateCheck `
        -Body ($newGatewayPolicy | ConvertTo-Json -Depth 40)

    Write-Host "`nCREATED new Gateway policy '$new_gw_id' successfully." -ForegroundColor Green
}

Write-Host "`nDONE." -ForegroundColor Cyan

