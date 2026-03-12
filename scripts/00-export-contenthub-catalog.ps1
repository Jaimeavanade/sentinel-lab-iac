<#
.SYNOPSIS
Exporta el catálogo completo de Microsoft Sentinel Content Hub (Solutions) a CSV.

.DESCRIPTION
- Llama a contentProductPackages (catálogo).
- Paginación por nextLink.
- Arregla nextLink cuando viene sin api-version y/o con $SkipToken en lugar de $skipToken.
- Filtra contentKind=Solution.
- Exporta a CSV: displayName, contentId, contentProductId, version, isPreview, installedVersion.

Notas:
- contentProductPackages soporta query options y paginación por nextLink / $skipToken. [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)
- api-version es obligatorio. [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)
- $top debe ser entero >= 0 (OData). [2](https://apitracker.io/a/azure-senitel)
- installedVersion puede ser null o ausente si no está instalado. [3](https://github.com/pkhabazi/sentineldevops)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$OutCsv = "contenthub-solutions-catalog.csv",

  [Parameter(Mandatory = $false)]
  [switch]$IncludePreview,

  [Parameter(Mandatory = $false)]
  [string]$Search = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de haber hecho azure/login (OIDC) antes."
  }
  return $t
}

function Invoke-ArmGet {
  param([Parameter(Mandatory=$true)][string]$Uri)

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  try {
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
  } catch {
    $body = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd()
      }
    } catch {}
    if ($body) { throw "Fallo GET. Uri=$Uri. Body=$body" }
    throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
  }
}

function Normalize-NextLink {
  <#
    Arregla nextLink cuando:
    - No incluye api-version (obligatorio). [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)
    - Usa $SkipToken (casing raro) en lugar de $skipToken (documentado). [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$NextLink,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $fixed = $NextLink

  # Normalizar casing del skiptoken si viene como $SkipToken
  $fixed = $fixed -replace '\$SkipToken', '`$skipToken'

  # Si no tiene api-version, añadirlo
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') {
      $fixed = "$fixed&api-version=$ApiVersion"
    } else {
      $fixed = "$fixed?api-version=$ApiVersion"
    }
  }

  return $fixed
}

$script:ArmToken = Get-ArmToken

# Endpoint catálogo contentProductPackages [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)
$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"

# Opcional: $search
if ($Search -and $Search.Trim().Length -gt 0) {
  $q = [System.Uri]::EscapeDataString($Search.Trim())
  $base = "$base&`$search=$q"
}

# $top conservador
$base = "$base&`$top=50"

Write-Host "Export catálogo Content Hub (Solutions)"
Write-Host "Workspace: $WorkspaceName"
Write-Host "ApiVersion: $ApiVersion"
Write-Host "IncludePreview: $IncludePreview"
if ($Search -and $Search.Trim()) { Write-Host "Search: $Search" }
Write-Host "OutCsv: $OutCsv"
Write-Host ""

$items = New-Object System.Collections.Generic.List[object]
$next = $base
$page = 0

while ($next) {
  $page++
  Write-Host "Descargando página $page ..."
  $resp = Invoke-ArmGet -Uri $next

  if ($resp.value) {
    foreach ($p in $resp.value) {

      # Solo Solutions
      if (-not $p.properties -or $p.properties.contentKind -ne "Solution") { continue }

      # isPreview puede no existir
      $isPreview = $false
      if ($p.properties.PSObject.Properties.Name -contains "isPreview") {
        try { $isPreview = [bool]$p.properties.isPreview } catch { $isPreview = $false }
      }
      if (-not $IncludePreview -and $isPreview) { continue }

      # installedVersion puede ser null o ausente [3](https://github.com/pkhabazi/sentineldevops)
      $installedVersion = $null
      if ($p.properties.PSObject.Properties.Name -contains "installedVersion") {
        $installedVersion = $p.properties.installedVersion
      }

      $items.Add([pscustomobject]@{
        displayName      = $p.properties.displayName
        contentId        = $p.properties.contentId
        contentProductId = $p.properties.contentProductId
        version          = $p.properties.version
        isPreview        = $isPreview
        installedVersion = $installedVersion
      })
    }
  }

  # nextLink → normalizar (api-version + skipToken)
  if ($resp.nextLink) {
    $next = Normalize-NextLink -NextLink $resp.nextLink -ApiVersion $ApiVersion
  } else {
    $next = $null
  }
}

Write-Host ""
Write-Host "Total Solutions exportadas: $($items.Count)"

($items | Sort-Object displayName) | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "CSV generado: $OutCsv"
