param(
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,
  [Parameter(Mandatory = $true)][string]$SolutionsCsv,
  [string]$ApiVersion = "2025-09-01",
  [switch]$InstallAllTemplates = $true
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Normalize-Input {
  param([AllowNull()][string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
  $t = $Text.Trim()
  $t = $t.Replace("“","").Replace("”","").Replace('"','')
  return $t
}

function Get-AllPages {
  param(
    [Parameter(Mandatory=$true)][string]$FirstUri
  )
  $items = @()
  $uri = $FirstUri

  while ($uri) {
    $resp = Invoke-AzRestMethod -Method GET -Uri $uri
    $json = $resp.Content | ConvertFrom-Json

    if ($json.value) { $items += $json.value }

    # Muchos endpoints devuelven nextLink para paginación
    if ($json.nextLink) {
      $uri = $json.nextLink
    } else {
      $uri = $null
    }
  }
  return $items
}

# ---- Inputs ----
$SolutionsCsv = Normalize-Input -Text $SolutionsCsv
$solutions = $SolutionsCsv -split '\s*,\s*' |
  ForEach-Object { Normalize-Input -Text $_ } |
  Where-Object { $_ } |
  Select-Object -Unique

Write-Host "Instalación de soluciones solicitadas: $($solutions -join ' | ')"

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Revisa azure/login con enable-AzPSSession=true." }
$subId = $ctx.Subscription.Id

# 1) Comprobar Sentinel habilitado
$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$ApiVersion"
$check = Invoke-AzRestMethod -Method GET -Uri $onboardUri
if ($check.StatusCode -ne 200) {
  throw "Sentinel NO está habilitado (GET onboardingStates/default no devuelve 200)."
}
Write-Host "OK: Sentinel habilitado. Continuamos con instalación."

# 2) Mapeo estable (evita falsos positivos)
$knownContentIds = @{
  "Azure Activity" = "azuresentinel.azure-sentinel-solution-azureactivity"
  "Syslog"         = "azuresentinel.azure-sentinel-solution-syslog"
}

# 3) Catálogo: contentProductPackages (para obtener versión, contentProductId, contentSchemaVersion)
$catalogPackagesBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"

# Catálogo: contentProductTemplates (para obtener todas las plantillas de una solución)
$catalogTemplatesBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductTemplates?api-version=$ApiVersion"

function Get-CatalogPackageByContentId {
  param([Parameter(Mandatory = $true)][string]$ContentId)

  $contentIdEscaped = $ContentId.Replace("'", "''")
  $filterRaw = "properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEscaped'"
  $filterEncoded = [System.Uri]::EscapeDataString($filterRaw)

  $uri = "$catalogPackagesBase&`$filter=$filterEncoded&`$top=5"
  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $json = $resp.Content | ConvertFrom-Json

  if (-not $json.value -or $json.value.Count -eq 0) { return $null }
  return ($json.value | Select-Object -First 1)
}

function Resolve-ContentIdFromDisplayNameExact {
  param([Parameter(Mandatory = $true)][string]$DisplayName)

  $searchEncoded = [System.Uri]::EscapeDataString($DisplayName)
  $uri = "$catalogPackagesBase&`$search=$searchEncoded&`$top=100"
  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $items = ($resp.Content | ConvertFrom-Json).value

  if (-not $items) { return $null }

  $matches = $items | Where-Object {
    $_.properties.contentKind -eq 'Solution' -and
    $_.properties.displayName -and
    ($_.properties.displayName -ieq $DisplayName)
  }

  if (-not $matches -or $matches.Count -eq 0) { return $null }

  $best = $matches |
    Sort-Object `
      @{ Expression = { [bool]$_.properties.isPreview }; Ascending = $true }, `
      @{ Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }; Descending = $true } |
    Select-Object -First 1

  return $best.properties.contentId
}

function Install-AllTemplatesForSolution {
  param(
    [Parameter(Mandatory=$true)][string]$SolutionPackageId,
    [Parameter(Mandatory=$true)][string]$SolutionPackageVersion
  )

  Write-Host ""
  Write-Host "---- Instalando TODAS las plantillas (content types) del paquete: $SolutionPackageId (v$SolutionPackageVersion) ----"

  # Filtrar plantillas del catálogo por packageId (la solución)
  $pkgIdEscaped = $SolutionPackageId.Replace("'", "''")
  $filterRaw = "properties/packageId eq '$pkgIdEscaped'"
  $filterEncoded = [System.Uri]::EscapeDataString($filterRaw)

  $firstUri = "$catalogTemplatesBase&`$filter=$filterEncoded&`$top=500"
  $templates = Get-AllPages -FirstUri $firstUri

  if (-not $templates -or $templates.Count -eq 0) {
    Write-Warning "No encontré plantillas en el catálogo para packageId=$SolutionPackageId. (Puede ser paginación, permisos o que la solución no exponga plantillas)."
    return
  }

  Write-Host "Plantillas encontradas en catálogo: $($templates.Count)"

  foreach ($t in $templates) {
    $templateId = $t.name
    $p = $t.properties

    # Endpoint de instalación de template en el workspace
    $installTemplateUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$templateId?api-version=$ApiVersion"

    # Body requerido por Install Template
    # (incluimos contentSchemaVersion para evitar errores como el que ya viste en paquetes)
    $body = @{
      properties = @{
        contentId            = $p.contentId
        contentKind          = $p.contentKind
        contentProductId     = $p.contentProductId
        displayName          = $p.displayName
        packageId            = $p.packageId
        packageVersion       = $p.packageVersion
        source               = $p.source
        version              = $p.version
        contentSchemaVersion = $p.contentSchemaVersion
      }
    } | ConvertTo-Json -Depth 20

    $r = Invoke-AzRestMethod -Method PUT -Uri $installTemplateUri -Payload $body

    if ($r.StatusCode -in 200,201) {
      Write-Host "  OK Template: $($p.contentKind) -> $($p.displayName)"
    } else {
      Write-Warning "  FAIL Template: $($p.displayName) StatusCode=$($r.StatusCode) Response=$($r.Content)"
    }
  }
}

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "==> Preparando instalación para: $sol"

  $contentId = $null
  if ($knownContentIds.ContainsKey($sol)) {
    $contentId = $knownContentIds[$sol]
    Write-Host "Usando contentId estable (mapeado): $contentId"
  } else {
    $contentId = Resolve-ContentIdFromDisplayNameExact -DisplayName $sol
    if ($contentId) {
      Write-Host "Resuelto por displayName exacto -> contentId: $contentId"
    } else {
      Write-Warning "No pude resolver '$sol' en el catálogo (displayName exacto)."
      continue
    }
  }

  # Obtener datos de paquete del catálogo (para instalar paquete)
  $pkg = Get-CatalogPackageByContentId -ContentId $contentId
  if (-not $pkg) {
    Write-Warning "No encontrado en catálogo (contentId): $contentId"
    continue
  }

  $contentKind          = $pkg.properties.contentKind
  $contentProductId     = $pkg.properties.contentProductId
  $displayName          = $pkg.properties.displayName
  $version              = $pkg.properties.version
  $contentSchemaVersion = $pkg.properties.contentSchemaVersion

  Write-Host "Catálogo OK: displayName='$displayName' version=$version contentProductId=$contentProductId contentSchemaVersion=$contentSchemaVersion"

  if ([string]::IsNullOrWhiteSpace($contentSchemaVersion)) {
    throw "El catálogo no devolvió properties.contentSchemaVersion para '$displayName'. No puedo instalar sin ese valor."
  }

  # Instalar paquete (solución)
  $packageId  = $contentId
  $installUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$ApiVersion"

  $installBody = @{
    properties = @{
      contentId            = $contentId
      contentKind          = $contentKind
      contentProductId     = $contentProductId
      displayName          = $displayName
      version              = $version
      contentSchemaVersion = $contentSchemaVersion
    }
  } | ConvertTo-Json -Depth 10

  $result = Invoke-AzRestMethod -Method PUT -Uri $installUri -Payload $installBody

  Write-Host "Install Package StatusCode: $($result.StatusCode)"
  if ($result.Content) { Write-Host "Install Package Response (raw): $($result.Content)" }

  if ($result.StatusCode -notin 200, 201) {
    throw "Falló instalación de paquete '$displayName'. StatusCode=$($result.StatusCode)"
  }

  Write-Host "OK: Solución instalada/actualizada -> $displayName"

  # Instalar todas las plantillas (content types) de la solución
  if ($InstallAllTemplates) {
    Install-AllTemplatesForSolution -SolutionPackageId $packageId -SolutionPackageVersion $version
  }
}

# Confirmación: listar paquetes instalados
Write-Host ""
Write-Host "Listando contentPackages instalados..."
$listPkgUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$installedPkgs = Invoke-AzRestMethod -Method GET -Uri $listPkgUri
Write-Host $installedPkgs.Content

# Confirmación: listar templates instalados
Write-Host ""
Write-Host "Listando contentTemplates instalados..."
$listTplUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$top=50"
$installedTemplates = Invoke-AzRestMethod -Method GET -Uri $listTplUri
Write-Host $installedTemplates.Content
