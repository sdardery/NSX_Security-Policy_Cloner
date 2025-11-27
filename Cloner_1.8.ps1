# =====================================================================================
# NSX SECURITY POLICY + INFINITE DEPTH GROUP & SERVICE CLONER (DEBUG MODE)
# Version: NSX Final Clean Script 1.8
# =====================================================================================
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
} catch { Write-Output "❌ Failed auth to SOURCE"; exit }

try {
    $test=Invoke-RestMethod "https://$dest_url/policy/api/v1/infra" -Headers $dest_header -SkipCertificateCheck -ErrorAction Stop
    Write-Output "✅ Authenticated to DEST $dest_url"
} catch { Write-Output "❌ Failed auth to DEST"; exit }



# =====================================================================================
# FUNCTION — INFINITE DEPTH GROUP FETCHER
# =====================================================================================
function Get-FullGroupChain {
    param(
        [string]$GroupPath,
        [Hashtable]$Cache,
        [Hashtable]$Visited
    )

    $GroupPath = [string]$GroupPath

    if (-not $GroupPath.StartsWith("/infra/domains/")) { return @() }
    if ($Visited.ContainsKey($GroupPath)) { return @() }

    $Visited[$GroupPath] = $true
    Write-Output "🔍 Inspect Group: $GroupPath"

    if ($Cache.ContainsKey($GroupPath)) {
        Write-Output "   ↪ Cached"
        return $Cache[$GroupPath]
    }

    try {
        $raw = Invoke-RestMethod -Method Get `
            -Uri "https://$source_url/policy/api/v1$GroupPath" `
            -Headers $source_header -SkipCertificateCheck
    }
    catch {
        Write-Output "   ❌ Failed GET group: $GroupPath"
        $Cache[$GroupPath] = @()
        return @()
    }

    if (
        $raw._system_owned -eq $true -or
        $raw.is_default -eq $true -or
        $raw._create_user -eq "system"
    ) {
        Write-Output "ℹ️ Built-in NSX group — skipping: $GroupPath"
        return @()
    }

    $json = $raw | ConvertTo-Json -Depth 30
    $Cache[$GroupPath] = @([PSCustomObject]@{
        path = $GroupPath
        body = $json
    })

    $children = @()
    if ($raw.expression) {
        foreach ($expr in $raw.expression) {
            if ($expr.paths) {
                foreach ($p in $expr.paths) {
                    if ($p -and $p.StartsWith("/infra/domains/")) {
                        $children += $p
                    }
                }
            }
        }
    }

    foreach ($child in $children) {
        Write-Output "      → child group: $child"
        $Cache[$GroupPath] += Get-FullGroupChain -GroupPath $child -Cache $Cache -Visited $Visited
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

    $Path = [string]$Path

    if (-not $Path.Trim().StartsWith("/infra/services/")) { return @() }
    if ($Visited.ContainsKey($Path)) { return @() }

    $Visited[$Path] = $true
    Write-Output "🔍 Inspect Service: $Path"

    if ($Cache.ContainsKey($Path)) {
        Write-Output "   ↪ Cached"
        return $Cache[$Path]
    }

    try {
        $raw = Invoke-RestMethod -Method Get `
            -Uri "https://$source_url/policy/api/v1$Path" `
            -Headers $source_header -SkipCertificateCheck
    }
    catch {
        Write-Output "   ❌ Failed GET service: $Path"
        $Cache[$Path] = @()
        return @()
    }

    if (
        $raw._system_owned -eq $true -or
        $raw.is_default -eq $true -or
        $raw._create_user -eq "system"
    ) {
        Write-Output "ℹ️ Built-in NSX service — skipping: $Path"
        return @()
    }

    $json = $raw | ConvertTo-Json -Depth 30
    $Cache[$Path] = @([PSCustomObject]@{
        path = $Path
        body = $json
    })

    $children = @()
    if ($raw.service_entries) {
        foreach ($e in $raw.service_entries) {
            $nested = ([string]$e.nested_service_path).Trim()
            if ($nested -and $nested.StartsWith("/infra/services/")) {
                $children += $nested
            }
        }
    }

    foreach ($child in $children) {
        Write-Output "      → child service: $child"
        $Cache[$Path] += Get-FullServiceChain -Path $child -Cache $Cache -Visited $Visited
    }

    return $Cache[$Path]
}



# =====================================================================================
# MAIN POLICY LOOP
# =====================================================================================

$policies = [System.IO.File]::ReadAllLines($filePath)

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
    }
    catch {
        Write-Output "❌ Policy not found, skipping..."
        continue
    }

    $policyBody = Get-Content policy_detail.json -Raw
    $policyJson = $policyBody | ConvertFrom-Json



    # =====================================================================
    # RULE LOOP
    # =====================================================================
    foreach ($rule in $policyJson.rules)
    {
        Write-Output "`n════════════════════════════════════════════════════════════"
        Write-Output "🟦 Processing Rule:  $($rule.display_name)"
        Write-Output "════════════════════════════════════════════════════════════"



        # =====================================================================
        # INFINITE GROUP CLONING
        # =====================================================================
        $allGroups = @()

        if ($rule.source_groups) { $allGroups += $rule.source_groups }
        if ($rule.destination_groups) { $allGroups += $rule.destination_groups }
        if ($rule.scope) {
            foreach ($s in $rule.scope) {
                if ($s -ne "ANY") { $allGroups += $s }
            }
        }

        foreach ($grp in $allGroups)
        {
            if ($grp -eq "ANY") { continue }

            Write-Output "`n📦 Fetching Group Chain: $grp"

            $CacheG = @{}
            $VisitedG = @{}
            $chainG = Get-FullGroupChain -GroupPath $grp -Cache $CacheG -Visited $VisitedG

            if ($chainG.Count -eq 0) {
                Write-Output "   ℹ️ Built-in group — skipping: $grp"
                continue
            }

            $unique = @{}
            foreach ($item in $chainG) {
                if (-not $unique.ContainsKey($item.path)) {
                    $unique[$item.path] = $item.body
                }
            }

            $ordered = $unique.Keys | Sort-Object -Descending

            foreach ($p in $ordered) {
                Write-Output "🔧 Patching group: $p"

                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header -Body $unique[$p] `
                        -SkipCertificateCheck

                    Write-Output "   ✅ Group patched: $p"
                }
                catch {
                    Write-Output "   ❌ Failed to patch group: $p"
                }
            }
        }



        # =====================================================================
        # INFINITE SERVICE CLONING
        # =====================================================================
        foreach ($service in $rule.services)
        {
            if ($service -eq "ANY") { continue }

            Write-Output "`n📄 Fetching Service Chain: $service"

            $Cache = @{}
            $Visited = @{}
            $chain = Get-FullServiceChain -Path $service -Cache $Cache -Visited $Visited

            if ($chain.Count -eq 0) {
                Write-Output "   ℹ️ Built-in service — skipping: $service"
                continue
            }

            $unique = @{}
            foreach ($item in $chain) {
                if (-not $unique.ContainsKey($item.path)) {
                    $unique[$item.path] = $item.body
                }
            }

            $ordered = $unique.Keys | Sort-Object -Descending

            foreach ($p in $ordered) {
                Write-Output "🔧 Patching service: $p"

                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header `
                        -Body $unique[$p] `
                        -SkipCertificateCheck

                    Write-Output "   ✅ Patched service: $p"
                }
                catch {
                    Write-Output "   ❌ Failed: $p"
                }
            }
        }



        # =====================================================================
        # PATCH RULE ITSELF
        # =====================================================================
        Write-Output "`n🔵 Patching Rule: $($rule.path)"
        try {
            Invoke-RestMethod -Method PATCH `
                -Uri "https://$dest_url/policy/api/v1$($rule.path)" `
                -Headers $dest_header `
                -Body ($rule | ConvertTo-Json -Depth 30) `
                -SkipCertificateCheck

            Write-Output "`e[32m   ✅ Rule patched successfully: $($rule.path)`e[0m"
        }
        catch {
            Write-Output "`e[31m   ❌ Rule patch failed: $($rule.path)`e[0m"
        }
    }



    # =====================================================================
    # PATCH POLICY
    # =====================================================================
    Write-Output "`n📘 Patching Policy: $policy"
    try {
        Invoke-RestMethod -Method PATCH `
            -Uri "https://$dest_url/policy/api/v1$policy" `
            -Headers $dest_header -Body $policyBody `
            -SkipCertificateCheck

        Write-Output "`e[32m✅✅ Policy created successfully: $policy ✅✅`e[0m"
    }
    catch {
        Write-Output "`e[31m❌ Policy patch failed: $policy ❌`e[0m"
    }
}
