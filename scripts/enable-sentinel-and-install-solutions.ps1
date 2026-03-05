param(
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$SolutionsCsv
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Normaliza entradas (quita comillas raras)
$SolutionsCsv = $SolutionsCsv.Trim().Replace("“","").Replace("”","").Replace('"','')
$solutionList = $SolutionsCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }

Write-Host "RG=$ResourceGroup"
Write-Host "Workspace=$WorkspaceName"
Write-Host "Solutions=$($solutionList -join ' | ')"

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Revisa azure/login con enable-AzPSSession=true." }
$subId = $ctx.Subscription.Id

# 1) Onboard Microsoft Sentinel (onboardingStates/default) [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)[2](https://microsoft.github.io/TechExcel-Sentinel-onboarding-and-migration-acceleration/docs/Ex02/0201.html)
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

# Verificación rápida (GET)
$check = Invoke-AzRestMethod -Method GET -Uri $onboardingUri
Write-Host "OnboardingState GET => $($check.StatusCode)"

# 2) Catálogo de soluciones (contentProductPackages) y luego instalar (contentPackages) [3](https://github.com/microsoft/sentinel-as-code/milestones)[4](https://sentinel.blog/automating-microsoft-sentinel-deployment-with-github-actions/)
$catalogApiVersion = "2025-09-01"
$installApiVersion = "2025-09-01"

foreach ($solutionName in $solutionList) {
  Write-Host ""
  Write-Host "==> Buscar paquete para: $solutionName"

  # Filtro exacto por displayName para evitar resultados random (1Password, etc.) [3](https://github.com/microsoft/sentinel-as-code/milestones)
  $nameEscapedForOdata = $solutionName.Replace("'", "''")
  $filterRaw = "properties/contentKind eq 'Solution' and properties/displayName eq '$nameEscapedForOdata'"
  $filterEncoded = [System.Uri]::EscapeDataString($filterRaw)

  $catalogUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$catalogApiVersion&`$filter=$filterEncoded&`$top=5"
  $resp = Invoke-AzRestMethod -Method GET -Uri $catalogUri
  $json = $resp.Content | ConvertFrom-Json

  if (-not $json.value -or $json.value.Count -eq 0) {
    Write-Warning "No encontrado en catálogo (displayName exacto): $solutionName"
    continue
  }

  $pkg = $json.value | Select-Object -First 1

  $packageId       = $pkg.name
  $contentId       = $pkg.properties.contentId
  $contentKind     = $pkg.properties.contentKind
  $contentProductId= $pkg.properties.contentProductId
  $displayName     = $pkg.properties.displayName
  $version         = $pkg.properties.version

  if (-not $packageId -or -not $contentId -or -not $contentProductId -or -not $version) {
    Write-Warning "Paquete incompleto para '$solutionName'. Saltando."
    continue
  }

  Write-Host "Instalando: $displayName | packageId=$packageId | version=$version"

  # IMPORTANTE: usar ${packageId} para que PowerShell no interprete $packageId?api [4](https://sentinel.blog/automating-microsoft-sentinel-deployment-with-github-actions/)
  $installUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$installApiVersion"

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

Write-Host ""
Write-Host "Fin: Sentinel habilitado + instalación de soluciones solicitada."
