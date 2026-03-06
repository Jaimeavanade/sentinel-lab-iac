param(
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,
  [Parameter(Mandatory = $true)][string]$SolutionsCsv,
  [string]$ApiVersion = "2025-09-01",
  [switch]$InstallAllTemplates = $true,

  # Para evitar que tarde demasiado si el catálogo es enorme:
  [int]$CatalogTopPerPage = 200,
  [int]$MaxCatalogPages = 50
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

function Add-QueryParams {
  param(
    [Parameter(Mandatory=$true)][string]$BaseUri,
    [Parameter(Mandatory=$true)][hashtable]$Params
  )

  $BaseUri = $BaseUri -replace '&amp;', '&'

  $sep = ($BaseUri -like "*?*") ? "&" : "?"
  $pairs = @()

  foreach ($k in $Params.Keys) {
    $v = [string]$Params[$k]
    $enc = [System.Uri]::EscapeDataString($v)
    $pairs += ("{0}={1}" -f $k, $enc)
  }

  return "$BaseUri$sep$($pairs -join '&')"
}

function Get-AllPages {
  param(
    [Parameter(Mandatory=$true)][string]$FirstUri,
    [int]$MaxPages = 50
  )

  $items = @()
  $uri = $FirstUri
  $page = 1

  while ($uri) {
    if ($page -gt $MaxPages) {
      Write-Warning "Se alcanzó MaxPages=$MaxPages. Corto paginación para evitar ejecución infinita."
      break
    }

    $uri = $uri -replace '&amp;', '&'
    Write-Host "GET (page $page): $uri"

    $resp = Invoke-AzRestMethod -Method GET -Uri $uri
    Write-Host "  StatusCode: $($resp.StatusCode)"

    if ($resp.StatusCode -ne 200) {
      if ($resp.Content) { Write-Host "  Response (raw): $($resp.Content)" }
      throw "Error llamando al API. StatusCode=$($resp.StatusCode)"
    }

    if ([string]::IsNullOrWhiteSpace($resp.Content)) {
      throw "El API devolvió Content vacío. No puedo leer JSON."
    }

    $json = $resp.Content | ConvertFrom-Json

    if ($json.error) {
      Write-Host "  Response (raw): $($resp.Content)"
      throw "El API devolvió error: $($json.error.code) - $($json.error.message)"
    }

    $hasValue = $json.PSObject.Properties.Name -contains 'value'
    if (-not $hasValue) {
      Write-Host "  Response (raw): $($resp.Content)"
      throw "La respuesta no tiene propiedad 'value'. No es una lista válida."
    }

    if ($json.value) { $items += $json.value }

    if ($json.nextLink) {
      $uri = $json.nextLink
      $page++
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

# 2) Mapeo estable
$knownContentIds = @{
  "Azure Activity" = "azuresentinel.azure-sentinel-solution-azureactivity"
  "Syslog"         = "azuresentinel.azure-sentinel-solution-syslog"
}

# 3) Base URIs de catálogo
$catalogPackagesBase  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"
$catalogTemplatesBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductTemplates?api-version=$ApiVersion"

function Get-CatalogPackageByContentId {
  param([Parameter(Mandatory=$true)][string]$ContentId)

  $contentIdEscaped = $ContentId.Replace("'", "''")
  $filterRaw = "properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEscaped'"
  $uri = Add-QueryParams -BaseUri $catalogPackagesBase -Params @{ '$filter' = $filterRaw; '$top' = '5' }

  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $json = $resp.Content | ConvertFrom-Json
  if (-not $json.value -or $json.value.Count -eq 0) { return $null }
  return ($json.value | Select-Object -First 1)
}

function Resolve-ContentIdFromDisplayNameExact {
  param([Parameter(Mandatory=$true)][string]$DisplayName)

  $uri = Add-QueryParams -BaseUri $catalogPackagesBase -Params @{ '$search' = $DisplayName; '$top' = '100' }
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
  param([Parameter(Mandatory=$true)][string]$SolutionPackageId)

  Write-Host ""
  Write-Host "---- Instalando TODAS las plantillas (content types) del paquete: $SolutionPackageId ----"

  # ✅ IMPORTANTE: NO usamos $filter porque el servicio devuelve 400 con OData query.
  # En su lugar listamos y filtramos localmente.
  # El endpoint List existe y devuelve "value" y soporta paginación con nextLink. [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-templates/list?view=rest-securityinsights-2025-09-01)

  $firstUri = Add-QueryParams -BaseUri $catalogTemplatesBase -Params @{ '$top' = "$CatalogTopPerPage" }
  $allTemplates = Get-AllPages -FirstUri $firstUri -MaxPages $MaxCatalogPages

  if (-not $allTemplates -or $allTemplates.Count -eq 0) {
    Write-Warning "El catálogo de contentProductTemplates vino vacío."
    return
  }

  $templates = $allTemplates | Where-Object {
    $_.properties -and
    $_.properties.packageId -eq $SolutionPackageId -and
    $_.properties.packageKind -eq 'Solution'
  }

  Write-Host "Total plantillas en catálogo (escaneadas): $($allTemplates.Count)"
  Write-Host "Plantillas pertenecientes a esta solución: $($templates.Count)"

  if (-not $templates -or $templates.Count -eq 0) {
    Write-Warning "No encontré plantillas para la solución $SolutionPackageId. (Puede ser que esa solución no publique plantillas en este endpoint)."
    return
  }

  foreach ($t in $templates) {
    $templateId = $t.name
    $p = $t.properties

    if (-not $templateId) {
      Write-Warning "  Saltando: item sin 'name' (templateId)."
      continue
    }

    # Install Template: PUT contentTemplates/{templateId} [2](https://www.infosupport.com/how-to-get-azure-sentinel-incidents-via-api/)
    $installTemplateUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$templateId?api-version=$ApiVersion"

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
    } | ConvertTo-Json -Depth 25

    $r = Invoke-AzRestMethod -Method PUT -Uri $installTemplateUri -Payload $body

    if ($r.StatusCode -in 200, 201) {
      Write-Host "  OK Template: $($p.contentKind) -> $($p.displayName)"
    } else {
      Write-Warning "  FAIL Template: $($p.displayName) StatusCode=$($r.StatusCode)"
      if ($r.Content) { Write-Host "  Response (raw): $($r.Content)" }
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
    throw "El catálogo no devolvió properties.contentSchemaVersion para '$displayName'."
  }

  # Instalar paquete/solución (contentPackages/{packageId}) [3](https://www.azadvertizer.net/azresourcetypes/microsoft.securityinsights_contentproductpackages.html)
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

  if ($InstallAllTemplates) {
    Install-AllTemplatesForSolution -SolutionPackageId $packageId
  }
}

# Confirmación: listar templates instalados (parcial) [3](https://www.azadvertizer.net/azresourcetypes/microsoft.securityinsights_contentproductpackages.html)
Write-Host ""
Write-Host "Listando contentTemplates instalados (muestra parcial)..."
$listTplUri = Add-QueryParams -BaseUri "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion" -Params @{
  '$top' = '50'
}
$installedTemplates = Invoke-AzRestMethod -Method GET -Uri $listTplUri
Write-Host $installedTemplates.Content
