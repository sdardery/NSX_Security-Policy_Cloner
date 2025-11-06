# ==== INPUTS (interactive) ====================================================
$source_url = Read-Host "Enter SOURCE NSX FQDN or IP (e.g., nsx-l-01a.corp.local)"
#$source_url="nsx-l-01a.corp.local"
$sourceCreds = Get-Credential -Message "Enter SOURCE NSX credentials"

$dest_url   = Read-Host "Enter DESTINATION NSX FQDN or IP (e.g., nsx-l-02b.corp.local)"
#$dest_url="nsx-l-02b.corp.local"
$destCreds  = Get-Credential -Message "Enter DESTINATION NSX credentials"

# Path to the policies list file (This is filled by the user , any policy in this file will be cloned)
$filePath = "policies.txt"

# ==== HEADERS (This is to authorize API Commands) ===================
# 1) Build source header using source creds
$base64Creds = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes("$($sourceCreds.username):$($sourceCreds.GetNetworkCredential().password)")
)
$source_header = @{ Authorization = "Basic $base64Creds" }

# 2) Build destination header using destination creds
$base64Creds = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes("$($destCreds.username):$($destCreds.GetNetworkCredential().password)")
)
$dest_header = @{
    Authorization = "Basic $base64Creds";
    "Content-Type" = "application/json"
}

# ==== Test authentication to SOURCE and DESTINATION ===========================
Write-Output "`nTesting authentication to NSX Managers..."

try {
    $srcTest = Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1/infra" -Headers $source_header -SkipCertificateCheck -ErrorAction Stop
    Write-Output "✅ Successfully authenticated to SOURCE NSX: $source_url"
}
catch {
    Write-Output "❌ Failed to authenticate to SOURCE NSX: $source_url"
    Write-Output "   Error: $($_.Exception.Message)"
    exit
}

try {
    $destTest = Invoke-RestMethod -Method Get -Uri "https://$dest_url/policy/api/v1/infra" -Headers $dest_header -SkipCertificateCheck -ErrorAction Stop
    Write-Output "✅ Successfully authenticated to DESTINATION NSX: $dest_url"
}
catch {
    Write-Output "❌ Failed to authenticate to DESTINATION NSX: $dest_url"
    Write-Output "   Error: $($_.Exception.Message)"
    exit
}

# ==== Read Policy.txt as a powershell array ====================================
$policies = [System.IO.File]::ReadAllLines($filePath)

# ==== ORIGINAL LOGIC (with Try/Catch for missing policy) ======================
foreach ($policy in $policies)
{ 
#START OF POLICY FOR LOOP

write-output "Getting Info for $policy from NSX $source_url"

try {
    # Attempt to get the policy details
    Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1$policy" -headers $source_header -SkipCertificateCheck -ErrorAction Stop | ConvertTo-Json -Depth 10 | Set-Content policy_detail.json
}
catch {
    Write-Output "❌ Policy '$policy' not found or could not be retrieved from $source_url"
    Write-Output "   Skipping this policy and continuing..."
    continue  # Move to the next policy without breaking the loop
}

$policyContent_Body = Get-Content -Path 'policy_detail.json' -Raw ### Policy Content TXT Format
$policyContent_json= Get-Content -Path 'policy_detail.json' -Raw | ConvertFrom-Json ### Policy Content Powershell Array Format

foreach ($rule in $policyContent_json.rules)
{ # START OF EACH RULE LOOP
  foreach ($srcgrp in $rule.source_groups) #Source Group
  { 
    try{
    # START OF EACH Source Group Loop
  if ($srcgrp -ne "ANY") 
  { # Start creating each non ANY group in target nsx
    Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1$srcgrp" -headers $source_header -SkipCertificateCheck | ConvertTo-Json -Depth 10 | Set-Content group_detail.json
    $srcgroup_Body = Get-Content -Path 'group_detail.json' -Raw ### Policy Content TXT Format
    $srcgroup_json= Get-Content -Path 'group_detail.json' -Raw | ConvertFrom-Json ### Policy Content Powershell Array Format

    ##############Starting to create the Security Groups in the destination NSX  ###############
    Invoke-RestMethod -Method PATCH -Uri "https://$dest_url/policy/api/v1$srcgrp" -Headers $dest_header -Body $srcgroup_Body -SkipCertificateCheck
    Remove-Item "group_detail.json"
    # END creating each non ANY group in target nsx
  } 
    }
    catch{Remove-Item "group_detail.json"}
    # END OF EACH Source Group Loop
  } 


  foreach ($dstgrp in $rule.destination_groups) #Destination Group
  { 
    try{
    # START OF EACH Destination Group Loop
  if ($dstgrp -ne "ANY") 
  { 
    # Start creating each non ANY group in target nsx
    Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1$dstgrp" -headers $source_header -SkipCertificateCheck | ConvertTo-Json -Depth 10 | Set-Content group_detail.json
    $dstgroup_Body = Get-Content -Path 'group_detail.json' -Raw ### Policy Content TXT Format
    $dstgroup_json= Get-Content -Path 'group_detail.json' -Raw | ConvertFrom-Json ### Policy Content Powershell Array Format

    ##############Starting to create the Security Group in the destination NSX  ###############
    Invoke-RestMethod -Method PATCH -Uri "https://$dest_url/policy/api/v1$dstgrp" -Headers $dest_header -Body $dstgroup_Body -SkipCertificateCheck
    Remove-Item "group_detail.json"
    # END creating each non ANY Destination group in target nsx
  } 
    }
    catch{Remove-Item "group_detail.json"}
  # END OF EACH Destination Group Loop
  } 

  ##############Starting to create the Services in the destination NSX  ###############
  foreach ($service in $rule.services)
  { 
    try
    {
    # START OF EACH Destination Group Loop
  if ($service -ne "ANY") 
  { # Start creating each non ANY group in target nsx
    Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1$service" -headers $source_header -SkipCertificateCheck | ConvertTo-Json -Depth 10 | Set-Content service_detail.json
    $servicegroup_Body = Get-Content -Path 'service_detail.json' -Raw ### Policy Content TXT Format
    $servicegroup_json= Get-Content -Path 'service_detail.json' -Raw | ConvertFrom-Json ### Policy Content Powershell Array Format

    ##############Starting to create the Custom Service in the destination NSX  ###############
    Invoke-RestMethod -Method PATCH -Uri "https://$dest_url/policy/api/v1$service" -Headers $dest_header -Body $servicegroup_Body -SkipCertificateCheck
    Remove-Item "service_detail.json"
    # END creating each non ANY Destination group in target nsx
  } 
    }
    catch {Remove-Item "service_detail.json"}
  # END OF EACH Service Loop
  
  }

  
#END OF EACH RULE LOOP
} 

##############Creating the  policy in the destination NSX  ###############
write-output "Patching $policy to NSX $dest_url"
Invoke-RestMethod -Method PATCH -Uri "https://$dest_url/policy/api/v1$policy" -Headers $dest_header -Body $policyContent_Body -SkipCertificateCheck #create/overwrite policy in destination
Remove-Item  "policy_detail.json" ##empty the json file to avoid overwriting

#END OF POLICY FOR LOOP
}


