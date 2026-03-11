<#
.SYNOPSIS
Exporta el catálogo completo de Microsoft Sentinel Content Hub (Solutions) a CSV.

.DESCRIPTION
- Llama a contentProductPackages (catálogo).
- Gestiona paginación por nextLink.
- Filtra contentKind=Solution.
- Exporta a CSV: displayName, contentId, contentProductId, version, isPreview, installedVersion.

NOTA:
- Usa token ARM via Azure CLI (az account get-access-token), ideal en GitHub Actions con OIDC.
- Endpoint: contentProductPackages list (catálogo) soporta paging y nextLink. [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
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

  # Opcional: si quieres filtrar por un término y exportar solo coincidencias
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
  return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
}

$script:ArmToken = Get-ArmToken

# Endpoint base de catálogo (contentProductPackages). [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"

# Opcional: aplicar $search (por query)
if ($Search -and $Search.Trim().Length -gt 0) {
  $q = [System.Uri]::EscapeDataString($Search.Trim())
  $base = "$base&`$search=$q"
}

# Pedimos páginas razonables
$base = "$base&`$top=200"

Write-Host "Export catálogo Content Hub (Solutions)"
Write-Host "Workspace: $WorkspaceName"
Write-Host "ApiVersion: $ApiVersion"
Write-Host "IncludePreview: $IncludePreview"
if ($Search) { Write-Host "Search: $Search" }
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

      # Filtrar a Solutions
      if (-not $p.properties -or $p.properties.contentKind -ne "Solution") { continue }

      # Excluir preview si aplica
      $isPreview = $false
      if ($p.properties.PSObject.Properties.Name -contains "isPreview") {
        try { $isPreview = [bool]$p.properties.isPreview } catch { $isPreview = $false }
      }
      if (-not $IncludePreview -and $isPreview) { continue }

      $items.Add([pscustomobject]@{
        displayName      = $p.properties.displayName
        contentId        = $p.properties.contentId
        contentProductId = $p.properties.contentProductId
        version          = $p.properties.version
        isPreview        = $isPreview
        installedVersion = $p.properties.installedVersion
      })
    }
  }

  # Paginación: nextLink (cuando hay más resultados). [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
  if ($resp.nextLink) { $next = $resp.nextLink } else { $next = $null }
}

Write-Host ""
Write-Host "Total Solutions exportadas: $($items.Count)"

# Ordenar por displayName y exportar CSV
$itemsSorted = $items | Sort-Object displayName
$itemsSorted | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

Write-Host "CSV generado: $OutCsv"
