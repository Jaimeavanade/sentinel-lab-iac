param(
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,
  [Parameter(Mandatory = $true)][string]$SolutionsCsv,
  [string]$ApiVersion = "2025-09-01"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Normalize-Input {
  param([AllowNull()][string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return "" }

  $t = $Text.Trim()

  # Quitar comillas normales y “smart quotes”
  $t = $t.Replace("“","").Replace("”","").Replace('"','')

  return $t
}

# ---- Inputs ----
$SolutionsCsv = Normalize-Input -Text $SolutionsCsv

# Split robusto: soporta espacios alrededor de la coma
$solutions = $SolutionsCsv -split '\s*,\s*' |
  ForEach-Object { Normalize-Input -Text $_ } |
  Where-Object { $_ } |
  Select-Object -Unique

Write-Host "Instalación de soluciones solicitadas: $($solutions -join ' | ')"

# Contexto Az (debe existir por azure/login con enable-AzPSSession=true)
$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Revisa azure/login con enable-AzPSSession=true." }
$subId = $ctx.Subscription.Id

# 1) Comprobar Sentinel habilitado (onboardingStates/default)
$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$ApiVersion"
$check = Invoke-AzRestMethod -Method GET -Uri $onboardUri
if ($check.StatusCode -ne 200) {
  throw "Sentinel NO está habilitado (GET onboardingStates/default no devuelve 200)."
}
Write-Host "OK: Sentinel habilitado. Continuamos con instalación."

# 2) Mapeo estable displayName -> contentId (evita falsos positivos)
# Puedes añadir más aquí si quieres soportar más soluciones de forma “exacta”.
$knownContentIds = @{
  "Azure Activity" = "azuresentinel.azure-sentinel-solution-azureactivity"
  "Syslog"         = "azuresentinel.azure-sentinel-solution-syslog"
}

# 3) Catálogo: contentProductPackages (catálogo)
$catalogBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"

function Get-CatalogPackageByContentId {
  param(
    [Parameter(Mandatory = $true)][string]$ContentId
  )

  $contentIdEscaped = $ContentId.Replace("'", "''")
  $filterRaw = "properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEscaped'"
  $filterEncoded = [System.Uri]::EscapeDataString($filterRaw)

  # IMPORTANTE: usar '&' real, NO '&amp;'
  $uri = "$catalogBase&`$filter=$filterEncoded&`$top=5"
  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $json = $resp.Content | ConvertFrom-Json

  if (-not $json.value -or $json.value.Count -eq 0) { return $null }
  return ($json.value | Select-Object -First 1)
}

function Resolve-ContentIdFromDisplayNameExact {
  param(
    [Parameter(Mandatory = $true)][string]$DisplayName
  )

  # Usamos $search (substring) y luego filtramos exacto en PowerShell
  $searchEncoded = [System.Uri]::EscapeDataString($DisplayName)

  # IMPORTANTE: usar '&' real, NO '&amp;'
  $uri = "$catalogBase&`$search=$searchEncoded&`$top=100"
  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $items = ($resp.Content | ConvertFrom-Json).value

  if (-not $items) { return $null }

  $matches = $items | Where-Object {
    $_.properties.contentKind -eq 'Solution' -and
    $_.properties.displayName -and
    ($_.properties.displayName -ieq $DisplayName)
  }

  if (-not $matches -or $matches.Count -eq 0) { return $null }

  # Preferir no-preview cuando exista, y “mayor versión” si se puede comparar
  $best = $matches |
    Sort-Object `
      @{ Expression = { [bool]$_.properties.isPreview }; Ascending = $true }, `
      @{ Expression = {
          try { [version]$_.properties.version } catch { [version]"0.0.0" }
        }; Descending = $true } |
    Select-Object -First 1

  return $best.properties.contentId
}

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "==> Preparando instalación para: $sol"

  $contentId = $null

  if ($knownContentIds.ContainsKey($sol)) {
    $contentId = $knownContentIds[$sol]
    Write-Host "Usando contentId estable (mapeado): $contentId"
  }
  else {
    $contentId = Resolve-ContentIdFromDisplayNameExact -DisplayName $sol
    if ($contentId) {
      Write-Host "Resuelto por displayName exacto -> contentId: $contentId"
    }
    else {
      Write-Warning "No pude resolver '$sol' en el catálogo (displayName exacto). Añádelo a knownContentIds o revisa el nombre."
      continue
    }
  }

  # Buscar en catálogo para obtener contentProductId/version/displayName/contentKind
  $pkg = Get-CatalogPackageByContentId -ContentId $contentId
  if (-not $pkg) {
    Write-Warning "No encontrado en catálogo (contentId): $contentId"
    continue
  }

  $contentKind      = $pkg.properties.contentKind
  $contentProductId = $pkg.properties.contentProductId
  $displayName      = $pkg.properties.displayName
  $version          = $pkg.properties.version

  Write-Host "Catálogo OK: displayName='$displayName' version=$version contentProductId=$contentProductId"

  # 4) Instalar paquete (PUT contentPackages/{packageId})
  $packageId  = $contentId

  # MUY IMPORTANTE: ${packageId} antes de '?api-version' para evitar $packageId?api
  $installUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$ApiVersion"

  $installBody = @{
    properties = @{
      contentId        = $contentId
      contentKind      = $contentKind
      contentProductId = $contentProductId
      displayName      = $displayName
      version          = $version
    }
  } | ConvertTo-Json -Depth 10

  # --- DIAGNÓSTICO: capturar respuesta y mostrarla en el log ---
  $result = Invoke-AzRestMethod -Method PUT -Uri $installUri -Payload $installBody

  Write-Host "Install StatusCode: $($result.StatusCode)"
  if ($result.Content) {
    Write-Host "Install Response (raw): $($result.Content)"
  }

  if ($result.StatusCode -notin 200, 201) {
    throw "Falló instalación de '$displayName'. StatusCode=$($result.StatusCode)"
  }

  Write-Host "OK: Instalado/actualizado -> $displayName"
}

# 5) Listar instalados (confirmación real)
Write-Host ""
Write-Host "Listando contentPackages instalados..."
$listUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$installed = Invoke-AzRestMethod -Method GET -Uri $listUri
Write-Host $installed.Content
