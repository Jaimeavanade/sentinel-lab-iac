param(
  [Parameter(Mandatory = $true)][string]$ResourceGroup,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,
  [Parameter(Mandatory = $true)][string]$SolutionsCsv,
  [string]$ApiVersion = "2025-09-01",
  [switch]$InstallAllTemplates = $true,
  [int]$MaxCatalogPages = 200
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

function Has-Prop {
  param(
    [Parameter(Mandatory=$true)]$Obj,
    [Parameter(Mandatory=$true)][string]$Name
  )
  return ($null -ne $Obj) -and ($Obj.PSObject.Properties.Name -contains $Name)
}

function Get-AllPages {
  param(
    [Parameter(Mandatory=$true)][string]$FirstUri,
    [int]$MaxPages = 200
  )

  $items = @()
  $uri = $FirstUri
  $page = 1

  while ($uri) {
    if ($page -gt $MaxPages) {
      Write-Warning "Se alcanzó MaxPages=$MaxPages. Corto paginación."
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

    # ✅ StrictMode-safe: solo mirar .error si existe
    if ((Has-Prop -Obj $json -Name 'error') -and $json.error) {
      Write-Host "  Response (raw): $($resp.Content)"
      throw "El API devolvió error: $($json.error.code) - $($json.error.message)"
    }

    if (-not (Has-Prop -Obj $json -Name 'value')) {
      Write-Host "  Response (raw): $($resp.Content)"
      throw "La respuesta no tiene propiedad 'value'."
    }

    if ($json.value) { $items += $json.value }

    # ✅ ESTE ERA EL PUNTO QUE ROMPÍA: hay que envolver Has-Prop en paréntesis antes del -and
    if ((Has-Prop -Obj $json -Name 'nextLink') -and $json.nextLink) {
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

# 3) Catálogo
$catalogPackagesBase  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"

# IMPORTANTE: para contentProductTemplates NO usamos OData ($top/$filter) porque te devolvía 400.
$catalogTemplatesBase = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductTemplates?api-version=$ApiVersion"

function Get-CatalogPackageByContentId {
  param([Parameter(Mandatory=$true)][string]$ContentId)

  # Este endpoint sí te funciona con $filter
  $contentIdEscaped = $ContentId.Replace("'", "''")
  $filterEncoded = [System.Uri]::EscapeDataString("properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEscaped'")
  $uri = "$catalogPackagesBase&`$filter=$filterEncoded&`$top=5"

  $resp = Invoke-AzRestMethod -Method GET -Uri $uri
  $json = $resp.Content | ConvertFrom-Json
  if (-not $json.value -or $json.value.Count -eq 0) { return $null }
  return ($json.value | Select-Object -First 1)
}

function Resolve-ContentIdFromDisplayNameExact {
  param([Parameter(Mandatory=$true)][string]$DisplayName)

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
  param([Parameter(Mandatory=$true)][string]$SolutionPackageId)

  Write-Host ""
  Write-Host "---- Instalando TODAS las plantillas (content types) del paquete: $SolutionPackageId ----"

  $allTemplates = Get-AllPages -FirstUri $catalogTemplatesBase -MaxPages $MaxCatalogPages
  Write-Host "Total plantillas en catálogo (escaneadas): $($allTemplates.Count)"

  $templates = $allTemplates | Where-Object {
    $_.properties -and
    $_.properties.packageId -eq $SolutionPackageId -and
    $_.properties.packageKind -eq 'Solution'
  }

  Write-Host "Plantillas pertenecientes a esta solución: $($templates.Count)"

  if (-not $templates -or $templates.Count -eq 0) {
    Write-Warning "No encontré plantillas para la solución $SolutionPackageId."
    return
  }

  foreach ($t in $templates) {
    $templateId = $t.name
    $p = $t.properties

    if (-not $templateId) {
      Write-Warning "  Saltando: item sin 'name' (templateId)."
      continue
    }

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

Write-Host ""
Write-Host "Listando contentTemplates instalados (muestra parcial)..."
$listTplUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$top=50"
$installedTemplates = Invoke-AzRestMethod -Method GET -Uri $listTplUri
Write-Host $installedTemplates.Content
