param(
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$SolutionsCsv
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Normaliza entradas (quita comillas raras)
$SolutionsCsv = $SolutionsCsv.Trim().Replace("“","").Replace("”","").Replace('"','')
$solutions = $SolutionsCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }

Write-Host "RG=$ResourceGroup"
Write-Host "Workspace=$WorkspaceName"
Write-Host "Solutions=$($solutions -join ' | ')"

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. ¿Falló azure/login?" }
$subId = $ctx.Subscription.Id

# 1) Onboard Microsoft Sentinel (onboardingStates/default)
# API oficial: Sentinel Onboarding States (Create) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/sentinel-onboarding-states/create?view=rest-securityinsights-2025-09-01)[10](https://learn.microsoft.com/en-us/rest/api/securityinsights/sentinel-onboarding-states?view=rest-securityinsights-2025-09-01)
$onboardingApiVersion = "2025-09-01"
$onboardingUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$onboardingApiVersion"

$payload = @{
  properties = @{
    customerManagedKey = $false
  }
} | ConvertTo-Json -Depth 5

Write-Host "Onboarding Sentinel..."
Invoke-AzRestMethod -Method PUT -Uri $onboardingUri -Payload $payload | Out-Null
Write-Host "OK: Sentinel onboarded (or already onboarded)."

# 2) Buscar paquetes (Content Hub catalog) y luego instalarlos
# Catalog: contentProductPackages list [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
# Install: contentPackages install [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)
$catalogApiVersion = "2025-09-01"
$installApiVersion = "2025-09-01"

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "==> Buscar paquete para: $sol"

  $search = [System.Uri]::EscapeDataString($sol)
  $catalogUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$catalogApiVersion&`$search=$search&`$top=5"

  $resp = Invoke-AzRestMethod -Method GET -Uri $catalogUri
  $json = ($resp.Content | ConvertFrom-Json)

  if (-not $json.value -or $json.value.Count -eq 0) {
    Write-Warning "No encontrado en catálogo: $sol"
    continue
  }

  # Elegimos el primero que parezca Solution
  # Preferimos coincidencia exacta de displayName (case-insensitive)
$pkg = $json.value |
  Where-Object { $_.properties -and $_.properties.contentKind -eq "Solution" } |
  Where-Object { $_.properties.displayName -and ($_.properties.displayName.Trim().ToLower() -eq $sol.Trim().ToLower()) } |
  Select-Object -First 1

# Si no hay exacta, intentamos "contains" (para casos tipo "Azure Activity" vs "Azure Activity (Preview)")
if (-not $pkg) {
  $pkg = $json.value |
    Where-Object { $_.properties -and $_.properties.contentKind -eq "Solution" } |
    Where-Object { $_.properties.displayName -and ($_.properties.displayName.Trim().ToLower().Contains($sol.Trim().ToLower())) } |
    Select-Object -First 1
}

# Si sigue sin haber, log y continua
if (-not $pkg) {
  Write-Warning "No encontré coincidencia razonable en el catálogo para: $sol"
  Write-Host "Top resultados devueltos:"
  $json.value | Select-Object -First 5 | ForEach-Object { Write-Host (" - " + $_.properties.displayName + " | id=" + $_.name) }
  continue
}

  $packageId = $pkg.name
  $contentId = $pkg.properties.contentId
  $contentKind = $pkg.properties.contentKind
  $contentProductId = $pkg.properties.contentProductId
  $displayName = $pkg.properties.displayName
  $version = $pkg.properties.version

  if (-not $packageId -or -not $contentId -or -not $contentProductId -or -not $version) {
    Write-Warning "Paquete incompleto para '$sol'. Saltando."
    continue
  }

  Write-Host "Instalando: $displayName | packageId=$packageId | version=$version"

  $installUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$installApiVersion"

  $installBody = @{
    properties = @{
      contentId = $contentId
      contentKind = $contentKind
      contentProductId = $contentProductId
      displayName = $displayName
      version = $version
    }
  } | ConvertTo-Json -Depth 10

  Invoke-AzRestMethod -Method PUT -Uri $installUri -Payload $installBody | Out-Null
  Write-Host "OK: Instalado/actualizado -> $displayName"
}

Write-Host ""
Write-Host "Fin: Sentinel habilitado + instalación de soluciones solicitada."
