$ErrorActionPreference = "SilentlyContinue"

# ==== INPUTS ==============================================================
$source_url = Read-Host "Enter SOURCE NSX FQDN or IP"
$sourceCreds = Get-Credential -Message "SOURCE NSX credentials"

$dest_url = Read-Host "Enter DESTINATION NSX FQDN or IP"
$destCreds = Get-Credential -Message "DESTINATION NSX credentials"

$filePath = "policies.txt"

# ==== HEADERS =============================================================
$base64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(
        "$($sourceCreds.username):$($sourceCreds.GetNetworkCredential().Password)"
    )
)
$source_header = @{ Authorization = "Basic $base64" }

$base64 = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(
        "$($destCreds.username):$($destCreds.GetNetworkCredential().Password)"
    )
)
$dest_header = @{ Authorization = "Basic $base64"; "Content-Type" = "application/json" }


# ==== AUTH TEST ============================================================
Write-Output "`nTesting NSX Authentication..."
try {
    $test=Invoke-RestMethod "https://$source_url/policy/api/v1/infra" -Headers $source_header -SkipCertificateCheck -ErrorAction Stop
    Write-Output "✅ Authenticated to SOURCE $source_url"
} catch { Write-Output "❌ Failed to authenticate to SOURCE"; exit }

try {
    $test=Invoke-RestMethod "https://$dest_url/policy/api/v1/infra" -Headers $dest_header -SkipCertificateCheck -ErrorAction Stop
    Write-Output "✅ Authenticated to DEST $dest_url"
} catch { Write-Output "❌ Failed to authenticate to DEST"; exit }



# =====================================================================================
# FUNCTION — INFINITE DEPTH GROUP FETCHER
# =====================================================================================
function Get-FullGroupChain {
    param(
        [string]$GroupPath,
        [Hashtable]$Cache,
        [Hashtable]$Visited
    )

    if (-not $GroupPath.StartsWith("/infra/domains/")) { return @() }
    if ($Visited.ContainsKey($GroupPath)) { return @() }

    $Visited[$GroupPath] = $true
    Write-Output "🔍 Inspect Group: $GroupPath"

    if ($Cache.ContainsKey($GroupPath)) { return $Cache[$GroupPath] }

    try {
        $raw = Invoke-RestMethod -Method Get `
            -Uri "https://$source_url/policy/api/v1$GroupPath" `
            -Headers $source_header -SkipCertificateCheck
    } catch {
        Write-Output "   ❌ Failed GET group: $GroupPath"
        return @()
    }

    if ($raw._system_owned -eq $true -or $raw.is_default -eq $true -or $raw._create_user -eq "system") {
        Write-Output "ℹ️ Built-in NSX group — skipping: $GroupPath"
        return @()
    }

    $Cache[$GroupPath] = @([PSCustomObject]@{
        path = $GroupPath
        body = ($raw | ConvertTo-Json -Depth 30)
    })

    foreach ($expr in $raw.expression) {
        if ($expr.paths) {
            foreach ($p in $expr.paths) {
                if ($p.StartsWith("/infra/domains/")) {
                    Write-Output "      → child group: $p"
                    $Cache[$GroupPath] += Get-FullGroupChain -GroupPath $p -Cache $Cache -Visited $Visited
                }
            }
        }
    }

    return $Cache[$GroupPath]
}



# =====================================================================================
# FUNCTION — INFINITE DEPTH SERVICE FETCHER
# =====================================================================================
function Get-FullServiceChain {
    param(
        [string]$Path,
        [Hashtable]$Cache,
        [Hashtable]$Visited
    )

    if (-not $Path.StartsWith("/infra/services/")) { return @() }
    if ($Visited.ContainsKey($Path)) { return @() }

    $Visited[$Path] = $true
    Write-Output "🔍 Inspect Service: $Path"

    if ($Cache.ContainsKey($Path)) { return $Cache[$Path] }

    try {
        $raw = Invoke-RestMethod -Method Get `
            -Uri "https://$source_url/policy/api/v1$Path" `
            -Headers $source_header -SkipCertificateCheck
    } catch {
        Write-Output "   ❌ Failed GET service: $Path"
        return @()
    }

    if ($raw._system_owned -eq $true -or $raw.is_default -eq $true) {
        Write-Output "ℹ️ Built-in NSX service — skipping: $Path"
        return @()
    }

    $Cache[$Path] = @([PSCustomObject]@{
        path = $Path
        body = ($raw | ConvertTo-Json -Depth 30)
    })

    foreach ($entry in $raw.service_entries) {
        $nested = $entry.nested_service_path
        if ($nested -and $nested.StartsWith("/infra/services/")) {
            Write-Output "      → child service: $nested"
            $Cache[$Path] += Get-FullServiceChain -Path $nested -Cache $Cache -Visited $Visited
        }
    }

    return $Cache[$Path]
}



# =====================================================================================
# MAIN POLICY LOOP
# =====================================================================================

$policies = Get-Content $filePath

foreach ($policy in $policies)
{
    Write-Output "`n----------------------------------------------"
    Write-Output "Getting Policy: $policy"
    Write-Output "----------------------------------------------`n"

    try {
        Invoke-RestMethod -Method Get `
            -Uri "https://$source_url/policy/api/v1$policy" `
            -Headers $source_header -SkipCertificateCheck |
            ConvertTo-Json -Depth 30 | Set-Content policy_detail.json
    } catch {
        Write-Output "❌ Policy not found, skipping..."
        continue
    }

    $policyJson = Get-Content policy_detail.json -Raw | ConvertFrom-Json


    # =====================================================================
    # RULE LOOP
    # =====================================================================
    foreach ($rule in $policyJson.rules)
    {
        Write-Output "`n════════════════════════════════════════════════════════════"
        Write-Output "🟦 Processing Rule: $($rule.display_name)"
        Write-Output "════════════════════════════════════════════════════════════"


        # =====================================================================
        # GROUP CLONING
        # =====================================================================
        $allGroups = @()

        if ($rule.source_groups) { $allGroups += $rule.source_groups }
        if ($rule.destination_groups) { $allGroups += $rule.destination_groups }
        if ($rule.scope) { $allGroups += ($rule.scope | Where-Object { $_ -ne "ANY" }) }

        foreach ($grp in $allGroups)
        {
            if ($grp -eq "ANY") { continue }

            Write-Output "`n📦 Fetching Group Chain: $grp"

            $CacheG = @{}
            $VisitedG = @{}
            $chainG = Get-FullGroupChain $grp $CacheG $VisitedG

            if ($chainG.Count -eq 0) {
                Write-Output "   ℹ Built-in group — skipping: $grp"
                continue
            }

            $unique = @{}
            foreach ($item in $chainG) {
                if (-not $unique.ContainsKey($item.path)) {
                    $unique[$item.path] = $item.body
                }
            }

            foreach ($p in ($unique.Keys | Sort-Object -Descending)) {
                Write-Output "🔧 Patching group: $p"
                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header `
                        -Body $unique[$p] `
                        -SkipCertificateCheck
                    Write-Output "   ✅ Group patched: $p"
                } catch {
                    Write-Output "   ❌ Failed group patch: $p"
                }
            }
        }



        # =====================================================================
        # SERVICE CLONING (FIXED IN v2.1)
        # =====================================================================
        foreach ($service in $rule.services)
        {
            if ($service -eq "ANY") { continue }

            Write-Output "`n📄 Fetching Service Chain: $service"

            $CacheS = @{}
            $VisitedS = @{}
            $chainS = Get-FullServiceChain $service $CacheS $VisitedS

            if ($chainS.Count -eq 0) {
                Write-Output "   ℹ Built-in service — skipping: $service"
                continue
            }

            $uniqueS = @{}
            foreach ($item in $chainS) {
                if (-not $uniqueS.ContainsKey($item.path)) {
                    $uniqueS[$item.path] = $item.body
                }
            }

            foreach ($p in ($uniqueS.Keys | Sort-Object -Descending)) {
                Write-Output "🔧 Patching service: $p"
                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header `
                        -Body $uniqueS[$p] `
                        -SkipCertificateCheck
                    Write-Output "   ✅ Patched service: $p"
                } catch {
                    Write-Output "   ❌ Failed service: $p"
                }
            }
        }



        # =====================================================================
        # PATCH RULE (NO SUCCESS/FAIL CHECK)
        # =====================================================================
        Write-Output "`n🔵 Patching Rule: $($rule.path)"

        Invoke-RestMethod -Method PATCH `
            -Uri "https://$dest_url/policy/api/v1$($rule.path)" `
            -Headers $dest_header `
            -Body ($rule | ConvertTo-Json -Depth 30) `
            -SkipCertificateCheck `
            -ErrorAction SilentlyContinue

        # No success/fail output
    }



    # =====================================================================
    # PATCH POLICY
    # =====================================================================
    Write-Output "`n📘 Patching Policy: $policy"
    try {
        Invoke-RestMethod -Method PATCH `
            -Uri "https://$dest_url/policy/api/v1$policy" `
            -Headers $dest_header `
            -Body (Get-Content policy_detail.json -Raw) `
            -SkipCertificateCheck

        Write-Output "`e[32m✅ Policy created successfully: $policy`e[0m"
    } catch {
        Write-Output "`e[31m❌ Policy patch failed: $policy`e[0m"
    }
}
