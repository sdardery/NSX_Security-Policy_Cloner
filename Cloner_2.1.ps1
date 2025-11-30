# =====================================================================================
# NSX SECURITY POLICY + INFINITE DEPTH NESTED SERVICE & GROUP CLONER (DEBUG MODE)
# Version: NSX Final Clean Script 1.6 + Nested Groups Support
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
# FUNCTION: Get infinite chain of nested services
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
    Write-Output "🔍 Inspect: $Path"

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
        Write-Output "   ❌ Failed GET: $Path"
        $Cache[$Path] = @()
        return @()
    }

    if (
        $raw._system_owned -eq $true -or
        $raw.is_default -eq $true -or
        $raw._create_user -eq "system"
    ) {
        Write-Output "ℹ️ Built-in NSX service — no patch required: $Path"
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
            if ($nested -ne "" -and $nested.StartsWith("/infra/services/")) {
                $children += $nested
            }
        }
    }

    foreach ($child in $children) {
        Write-Output "      → child: $child"
        $Cache[$Path] += Get-FullServiceChain -Path $child -Cache $Cache -Visited $Visited
    }

    return $Cache[$Path]
}



# =====================================================================================
# FUNCTION: Get infinite chain of nested groups  (NEW)
# =====================================================================================
function Get-FullGroupChain {
    param(
        [string]$Path,
        [Hashtable]$Cache,
        [Hashtable]$Visited
    )

    $Path = [string]$Path

    if (-not $Path.Trim().StartsWith("/infra/domains/")) { return @() }
    if ($Visited.ContainsKey($Path)) { return @() }

    $Visited[$Path] = $true
    Write-Output "🔍 Inspect Group: $Path"

    if ($Cache.ContainsKey($Path)) {
        Write-Output "   ↪ Cached"
        return $Cache[$Path]
    }

    try {
        $raw = Invoke-RestMethod -Method GET `
            -Uri "https://$source_url/policy/api/v1$Path" `
            -Headers $source_header -SkipCertificateCheck
    }
    catch {
        Write-Output "   ❌ Failed GET group: $Path"
        $Cache[$Path] = @()
        return @()
    }

    if (
        $raw._system_owned -eq $true -or
        $raw.is_default -eq $true -or
        $raw._create_user -eq "system"
    ) {
        Write-Output "   ℹ️ Built-in NSX group — skip: $Path"
        return @()
    }

    $json = $raw | ConvertTo-Json -Depth 30
    $Cache[$Path] = @([PSCustomObject]@{
        path = $Path
        body = $json
    })

    # Find nested groups
    $children = @()
    if ($raw.expression) {
        foreach ($expr in $raw.expression) {
            if ($expr.resource_type -eq "NestedGroupExpression") {
                foreach ($c in $expr.paths) {
                    if ($c.StartsWith("/infra/domains/")) {
                        $children += $c
                    }
                }
            }
        }
    }

    foreach ($child in $children) {
        Write-Output "      → nested group: $child"
        $Cache[$Path] += Get-FullGroupChain -Path $child -Cache $Cache -Visited $Visited
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
        Invoke-RestMethod -Method Get -Uri "https://$source_url/policy/api/v1$policy" `
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
    # RULES
    # =====================================================================
    foreach ($rule in $policyJson.rules)
    {
        Write-Output ""
        Write-Output "════════════════════════════════════════════════════════════"
        Write-Output "🟦 Processing Rule:"
        Write-Output "   • ID: $($rule.id)"
        Write-Output "   • Name: $($rule.display_name)"
        Write-Output "   • Sources: $($rule.source_groups -join ', ')"
        Write-Output "   • Destinations: $($rule.destination_groups -join ', ')"
        Write-Output "   • Scope: $($rule.scope -join ', ')"
        Write-Output "   • Services: $($rule.services -join ', ')"
        Write-Output "════════════════════════════════════════════════════════════"



        # =====================================================================
        # GROUPS WITH NESTED RECURSION  (NEW)
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

            Write-Output "📦 Group: $grp"

            # ==================== NEW: Nested Group Recursion ====================
            $GCache = @{}
            $GVisited = @{}
            $gChain = Get-FullGroupChain -Path $grp -Cache $GCache -Visited $GVisited

            $uniqueG = @{}
            foreach ($item in $gChain) {
                if (-not $uniqueG.ContainsKey($item.path)) {
                    $uniqueG[$item.path] = $item.body
                }
            }

            $orderedG = $uniqueG.Keys | Sort-Object -Descending

            foreach ($p in $orderedG) {
                Write-Output "🔧 Patching nested group: $p"
                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header -Body $uniqueG[$p] -SkipCertificateCheck
                    Write-Output "   ✅ Patched nested group"
                }
                catch {
                    Write-Output "   ❌ Failed nested group patch"
                }
            }

            # ==================== Patch parent group as before ====================
            try {
                $raw = Invoke-RestMethod -Method Get `
                    -Uri "https://$source_url/policy/api/v1$grp" `
                    -Headers $source_header -SkipCertificateCheck
            }
            catch {
                Write-Output "   ❌ Failed GET group: $grp"
                continue
            }

            if (
                $raw._system_owned -eq $true -or
                $raw.is_default -eq $true -or
                $raw._create_user -eq "system"
            ) {
                Write-Output "   ℹ️ Built-in NSX group — no patch required: $grp"
                continue
            }

            $g = $raw | ConvertTo-Json -Depth 30
            try {
                Invoke-RestMethod -Method PATCH `
                    -Uri "https://$dest_url/policy/api/v1$grp" `
                    -Headers $dest_header -Body $g -SkipCertificateCheck

                Write-Output "   ✅ Group patched"
            }
            catch {
                Write-Output "   ❌ Failed to patch group: $grp"
            }
        }




        # =====================================================================
        # SERVICES — INFINITE DEPTH (UNTOUCHED)
        # =====================================================================
        foreach ($service in $rule.services)
        {
            if ($service -eq "ANY") { continue }

            Write-Output "`n📄 Fetching Service: $service"

            $Cache = @{}
            $Visited = @{}
            $chain = Get-FullServiceChain -Path $service -Cache $Cache -Visited $Visited

            if ($chain.Count -eq 0) {
                Write-Output "   ℹ️ Built-in NSX service — no patch required: $service"
                continue
            }

            $unique = @{}
            foreach ($item in $chain) {
                if (-not $unique.ContainsKey($item.path)) {
                    $unique[$item.path] = $item.body
                }
            }

            $ordered = $unique.Keys | Sort-Object -Descending


            # Patch children
            foreach ($p in $ordered) {
                if ($p -eq $service) { continue }

                Write-Output "🔧 Patching nested: $p"
                try {
                    Invoke-RestMethod -Method PATCH `
                        -Uri "https://$dest_url/policy/api/v1$p" `
                        -Headers $dest_header -Body $unique[$p] `
                        -SkipCertificateCheck
                    Write-Output "   ✅ Patched $p"
                }
                catch {
                    Write-Output "   ❌ Failed: $p"
                }
            }

            # Patch parent
            try {
                $rawParent = Invoke-RestMethod -Method Get `
                    -Uri "https://$source_url/policy/api/v1$service" `
                    -Headers $source_header -SkipCertificateCheck

                if (
                    $rawParent._system_owned -eq $true -or
                    $rawParent.is_default -eq $true -or
                    $rawParent._create_user -eq "system"
                ) {
                    Write-Output "   ℹ️ Built-in NSX service — no patch required: $service"
                    continue
                }
            }
            catch {}

            Write-Output "🔵 Patching parent service: $service"
            try {
                Invoke-RestMethod -Method PATCH `
                    -Uri "https://$dest_url/policy/api/v1$service" `
                    -Headers $dest_header -Body $unique[$service] `
                    -SkipCertificateCheck
                Write-Output "   ✅ Parent patched"
            }
            catch {
                Write-Output "   ❌ Failed parent: $service"
            }
        }
    }



    # =====================================================================
    # PATCH POLICY (WITH COLORS)
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
