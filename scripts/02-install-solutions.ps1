param(
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$SolutionsCsv
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---- Helpers ----
function Clean([string]$s) {
  if (-not $s) { return "" }
  return $s.Trim().Replace("“","").Replace("”","").Replace('"','')
}

# ---- Inputs ----
$SolutionsCsv = Clean $SolutionsCsv
$solutions = $SolutionsCsv.Split(",") | ForEach-Object { Clean $_ }

Write-Host "Instalación de soluciones solicitadas: $($solutions -join ' | ')"

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Revisa azure/login con enable-AzPSSession=true." }
$subId = $ctx.Subscription.Id

$api = "2025-09-01"

# 1) Asegurar Sentinel habilitado (GET onboardingStates/default) [6](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/deploy-microsoft-sentinel-using-bicep/4270970)[7](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$api"
$check = Invoke-AzRestMethod -Method GET -Uri $onboardUri
if ($check.StatusCode -ne 200) { throw "Sentinel NO está habilitado (onboardingState GET no devuelve 200)." }
Write-Host "OK: Sentinel habilitado. Continuamos con instalación."

# 2) Mapeo estable displayName -> contentId (para evitar matches tipo 1Password)
# Azure Activity contentId en Marketplace [3](https://marketplace.microsoft.com/en-us/product/azure-applications/azuresentinel.azure-sentinel-solution-azureactivity?tab=Overview)
# Syslog contentId usado en ejemplos reales [2](https://cybersecdemystify.com/step-by-step-guide-on-how-to-set-up-and-configure-microsoft-sentinel-for-seamless-security-management/)
$knownContentIds = @{
  "Azure Activity" = "azuresentinel.azure-sentinel-solution-azureactivity"
  "Syslog"         = "azuresentinel.azure-sentinel-solution-syslog"
}

# 3) Catálogo de paquetes (contentProductPackages) [4](https://www.linkedin.com/posts/uros-babic-87a8a2120_mvpbuzz-microsoftsentinel-azure-activity-7428179559596027904-ziYt)
$catalogBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$api"

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "==> Preparando instalación para: $sol"

  if (-not $knownContentIds.ContainsKey($sol)) {
    Write-Warning "No tengo contentId fijo para '$sol'. (Por ahora solo soportamos Azure Activity y Syslog)."
    continue
  }

  $contentId = $knownContentIds[$sol]
  Write-Host "Usando contentId estable: $contentId"

  # Buscar en catálogo el product package para obtener version/contentProductId (filter por contentId)
  # El endpoint soporta $filter [4](https://www.linkedin.com/posts/uros-babic-87a8a2120_mvpbuzz-microsoftsentinel-azure-activity-7428179559596027904-ziYt)
  $contentIdEscaped = $contentId.Replace("'", "''")
  $filterRaw = "properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEscaped'"
  $filterEncoded = [System.Uri]::EscapeDataString($filterRaw)

  $catalogUri = "$catalogBase&`$filter=$filterEncoded&`$top=5"
  $resp = Invoke-AzRestMethod -Method GET -Uri $catalogUri
  $json = $resp.Content | ConvertFrom-Json

  if (-not $json.value -or $json.value.Count -eq 0) {
    Write-Warning "No encontrado en catálogo (contentId): $contentId"
    continue
  }

  $pkg = $json.value | Select-Object -First 1

  $contentKind      = $pkg.properties.contentKind
  $contentProductId = $pkg.properties.contentProductId
  $displayName      = $pkg.properties.displayName
  $version          = $pkg.properties.version

  Write-Host "Catálogo OK: displayName='$displayName' version=$version contentProductId=$contentProductId"

  # 4) Instalar paquete (IMPORTANTE: {packageId} = contentId) [1](https://www.linkedin.com/pulse/how-set-up-microsoft-sentinel-connect-workspace-defender-booker-ivnce)
  $packageId = $contentId
  $installUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$api"

  $installBody = @{
    properties = @{
      contentId        = $contentId
      contentKind      = $contentKind
      contentProductId = $contentProductId
      displayName      = $displayName
      version          = $version
    }
  } | ConvertTo-Json -Depth 10

  Invoke-AzRestMethod -Method PUT -Uri $installUri -Payload $installBody | Out-Null
  Write-Host "OK: Instalado/actualizado -> $displayName"
}

# 5) Listar instalados (confirmación real) [5](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/deploying-and-managing-microsoft-sentinel-as-code/1131928)
Write-Host ""
Write-Host "Listando contentPackages instalados..."
$listUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$api"
$installed = Invoke-AzRestMethod -Method GET -Uri $listUri
Write-Host $installed.Content
