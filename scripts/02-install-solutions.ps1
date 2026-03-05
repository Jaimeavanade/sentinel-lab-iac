param(
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$SolutionsCsv
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Normalize-Name([string]$s) {
  if (-not $s) { return "" }
  $t = $s.ToLower().Trim()
  $t = $t.Replace("“","").Replace("”","").Replace('"','')
  $t = -join ($t.ToCharArray() | ForEach-Object {
    if ([char]::IsLetterOrDigit($_) -or $_ -eq ' ') { $_ } else { ' ' }
  })
  $t = ($t -split '\s+' | Where-Object { $_ }) -join ' '
  return $t.Trim()
}

$SolutionsCsv = $SolutionsCsv.Trim().Replace("“","").Replace("”","").Replace('"','')
$solutions = $SolutionsCsv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }

Write-Host "Instalación de soluciones solicitadas: $($solutions -join ' | ')"

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Asegura azure/login con enable-AzPSSession=true." }
$subId = $ctx.Subscription.Id

$api = "2025-09-01"

# 1) Asegurar que Sentinel está habilitado antes de instalar soluciones (onboardingStates)
$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$api"
$check = Invoke-AzRestMethod -Method GET -Uri $onboardUri
if ($check.StatusCode -ne 200) { throw "Sentinel no está habilitado (onboardingState no devuelve 200)." }
Write-Host "OK: Sentinel habilitado. Continuamos con instalación."

# 2) Catálogo de paquetes: contentProductPackages (list) [4](https://www.linkedin.com/posts/uros-babic-87a8a2120_mvpbuzz-microsoftsentinel-azure-activity-7428179559596027904-ziYt)
$catalogBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$api"

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "==> Buscando en catálogo: $sol"

  $search = [System.Uri]::EscapeDataString($sol)
  $catalogUri = "$catalogBase&`$search=$search&`$top=50"
  $resp = Invoke-AzRestMethod -Method GET -Uri $catalogUri
  $json = $resp.Content | ConvertFrom-Json

  if (-not $json.value -or $json.value.Count -eq 0) {
    Write-Warning "No hay resultados de catálogo para: $sol"
    continue
  }

  # Filtrar solo "Solution"
  $candidates = $json.value | Where-Object { $_.properties -and $_.properties.contentKind -eq "Solution" -and $_.properties.displayName }
  if (-not $candidates -or $candidates.Count -eq 0) {
    Write-Warning "No hay candidatos tipo Solution para: $sol"
    continue
  }

  # Ranking: exact normalizado > contains > primero
  $target = Normalize-Name $sol
  $best = $candidates | Where-Object { (Normalize-Name $_.properties.displayName) -eq $target } | Select-Object -First 1
  if (-not $best) {
    $best = $candidates | Where-Object {
      (Normalize-Name $_.properties.displayName).Contains($target) -or $target.Contains((Normalize-Name $_.properties.displayName))
    } | Select-Object -First 1
  }
  if (-not $best) { $best = $candidates | Select-Object -First 1 }

  $packageId        = $best.name
  $contentId        = $best.properties.contentId
  $contentKind      = $best.properties.contentKind
  $contentProductId = $best.properties.contentProductId
  $displayName      = $best.properties.displayName
  $version          = $best.properties.version

  Write-Host "Match: '$sol' -> '$displayName' (packageId=$packageId, version=$version)"

  # 3) Install content package: contentPackages/{packageId} (PUT) [5](https://www.linkedin.com/pulse/how-set-up-microsoft-sentinel-connect-workspace-defender-booker-ivnce)
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

# 4) Listar instalados (para confirmar) [6](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/deploying-and-managing-microsoft-sentinel-as-code/1131928)
Write-Host ""
Write-Host "Listando contentPackages instalados..."
$listUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$api"
$installed = Invoke-AzRestMethod -Method GET -Uri $listUri
Write-Host $installed.Content
