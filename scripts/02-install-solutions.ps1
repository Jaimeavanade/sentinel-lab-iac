<#
.SYNOPSIS
Instala soluciones de Microsoft Sentinel Content Hub desde un CSV de displayName.

.DESCRIPTION
Para cada displayName:
1) Busca en catálogo (contentProductPackages) usando $search y filtra contentKind=Solution.
   Devuelve version/contentId/contentProductId/contentSchemaVersion y packagedContent (expand). [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
2) Instala el paquete en el workspace vía contentPackages/{packageId} (PUT) usando packageId=contentId. 
3) Despliega packagedContent vía Microsoft.Resources/deployments mode=Incremental para materializar Installed content items. [3](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)

Requisitos:
- azure/login (OIDC) ya ejecutado en el workflow.
- Permisos adecuados (p.ej. Microsoft Sentinel Contributor). [4](https://github.com/noodlemctwoodle/Sentinel-As-Code)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ResourceGroup,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $true)]
  [string]$SolutionsCsv,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$DeploymentApiVersion = "2021-04-01",

  [Parameter(Mandatory = $false)]
  [switch]$IncludePreview,

  [Parameter(Mandatory = $false)]
  [int]$MaxRetries = 5,

  [Parameter(Mandatory = $false)]
  [int]$RetryDelaySeconds = 5,

  [Parameter(Mandatory = $false)]
  [int]$DeploymentWaitSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------
# Utilidades
# ------------------------
function Get-SubscriptionIdFromContext {
  try {
    $ctx = Get-AzContext
    if ($ctx -and $ctx.Subscription -and $ctx.Subscription.Id) { return $ctx.Subscription.Id }
  } catch {}

  try {
    $sub = az account show --query id -o tsv
    if ($sub) { return $sub }
  } catch {}

  throw "No se pudo determinar SubscriptionId. Revisa azure/login / contexto."
}

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa azure/login y permisos."
  }
  return $t
}

function Get-ErrorBodyFromException {
  param([Parameter(Mandatory=$true)] $Exception)
  try {
    if ($Exception.Response -and $Exception.Response.GetResponseStream) {
      $stream = $Exception.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($stream)
      $body = $reader.ReadToEnd()
      if ($body) { return $body }
    }
  } catch { }
  return $null
}

function Invoke-ArmWithRetry {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","DELETE")]
    [string]$Method,
    [Parameter(Mandatory=$true)]
    [string]$Uri,
    [Parameter(Mandatory=$false)]
    [object]$Body
  )

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  $attempt = 0
  while ($true) {
    $attempt++
    try {
      Write-Verbose "$Method $Uri (attempt $attempt/$MaxRetries)" -Verbose
      if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 80
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
      }
    } catch {
      $statusCode = $null
      try {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
          $statusCode = [int]$_.Exception.Response.StatusCode
        }
      } catch { }

      # 400: no reintentar, devolver body
      if ($statusCode -eq 400) {
        $body = Get-ErrorBodyFromException -Exception $_.Exception
        if ($body) { throw "HTTP 400 en $Method $Uri. Body=$body" }
        throw "HTTP 400 en $Method $Uri. Sin body."
      }

      $isTransient = ($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599)
      if ($attempt -ge $MaxRetries -or -not $isTransient) {
        $body = Get-ErrorBodyFromException -Exception $_.Exception
        if ($body) { throw "Fallo en $Method $Uri. StatusCode=$statusCode. Body=$body" }
        throw "Fallo en $Method $Uri. StatusCode=$statusCode."
      }

      $sleep = $RetryDelaySeconds * $attempt
      Write-Warning "Fallo transitorio (StatusCode=$statusCode). Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

function Parse-SolutionsCsv {
  param([Parameter(Mandatory=$true)][string]$Csv)
  $raw = $Csv -replace '\|', ',' -replace "`r", "," -replace "`n", ","
  $raw.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# ------------------------
# Catálogo (búsqueda y match estricto)
# ------------------------
function Get-CatalogCandidates {
  <#
    Catálogo: contentProductPackages, soporta $search y $expand=properties/packagedContent. [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
  #>
  param([Parameter(Mandatory=$true)][string]$DisplayName)

  $search = [System.Uri]::EscapeDataString($DisplayName)
  $uri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$search=$search&`$expand=properties/packagedContent&`$top=50"

  $resp = Invoke-ArmWithRetry -Method GET -Uri $uri
  if (-not $resp.value) { return @() }

  $candidates = $resp.value | Where-Object { $_.properties.contentKind -eq "Solution" }

  if (-not $IncludePreview) {
    $candidates = $candidates | Where-Object { -not $_.properties.isPreview }
  }

  return $candidates
}

function Select-BestCatalogMatch {
  <#
    Match estricto:
    1) Exacto por displayName (case-insensitive)
    2) Si no, match por "contains" (case-insensitive)
    3) Si sigue sin haber nada, FALLA (no elige random).
  #>
  param(
    [Parameter(Mandatory=$true)][string]$RequestedDisplayName,
    [Parameter(Mandatory=$true)]$Candidates
  )

  if (-not $Candidates -or $Candidates.Count -eq 0) {
    throw "Catálogo sin candidatos Solution para '$RequestedDisplayName'."
  }

  $req = $RequestedDisplayName.Trim().ToLower()

  $exact = $Candidates | Where-Object {
    $_.properties.displayName -and $_.properties.displayName.Trim().ToLower() -eq $req
  }

  $pool = $null
  if ($exact -and $exact.Count -gt 0) {
    $pool = $exact
  } else {
    $contains = $Candidates | Where-Object {
      $_.properties.displayName -and $_.properties.displayName.Trim().ToLower().Contains($req)
    }
    if ($contains -and $contains.Count -gt 0) {
      $pool = $contains
    }
  }

  if (-not $pool -or $pool.Count -eq 0) {
    $names = ($Candidates | Select-Object -ExpandProperty properties |
      Select-Object -ExpandProperty displayName | Sort-Object -Unique) -join " | "
    throw "No hay match para '$RequestedDisplayName'. Candidatos devueltos por catálogo: $names"
  }

  # Elegir la mayor versión (semver)
  $sorted = $pool | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending

  return ($sorted | Select-Object -First 1)
}

# ------------------------
# Instalación (contentPackages)
# ------------------------
function Install-ContentPackageFromCatalogItem {
  <#
    Install endpoint: contentPackages/{packageId} (PUT). 
    IMPORTANTE: packageId = contentId (no contentProductId)
  #>
  param([Parameter(Mandatory=$true)]$CatalogItem)

  $contentId        = $CatalogItem.properties.contentId
  $contentKind      = $CatalogItem.properties.contentKind
  $contentProductId = $CatalogItem.properties.contentProductId
  $displayName      = $CatalogItem.properties.displayName
  $version          = $CatalogItem.properties.version
  $schemaVersion    = $CatalogItem.properties.contentSchemaVersion
  if (-not $schemaVersion) { $schemaVersion = "2.0" }

  # ✅ CLAVE: packageId en la URL debe ser el ID del paquete (usamos contentId)
  $packageId = $contentId

  Write-Host "==> Instalando/actualizando: $displayName"
  Write-Host "    packageId           : $packageId"
  Write-Host "    contentId           : $contentId"
  Write-Host "    contentProductId    : $contentProductId"
  Write-Host "    version             : $version"
  Write-Host "    contentSchemaVersion: $schemaVersion"

  $uri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$ApiVersion"

  $body = @{
    properties = @{
      contentId            = $contentId
      contentKind          = $contentKind
      contentProductId     = $contentProductId
      displayName          = $displayName
      version              = $version
      contentSchemaVersion = $schemaVersion
    }
  }

  Invoke-ArmWithRetry -Method PUT -Uri $uri -Body $body | Out-Null
  Write-Host "    OK: contentPackage instalado/actualizado"
}

# ------------------------
# Deployment (packagedContent)
# ------------------------
function Deploy-PackagedContentFromCatalogItem {
  <#
    contentProductPackages puede expandir packagedContent para desplegar el ARM template. [1](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
    Este deployment incremental materializa Installed content items. [3](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)
  #>
  param([Parameter(Mandatory=$true)]$CatalogItem)

  $displayName = $CatalogItem.properties.displayName
  $template = $CatalogItem.properties.packagedContent
  if (-not $template) {
    throw "No hay packagedContent en catálogo para '$displayName'."
  }

  $safeName = ($displayName -replace '[^a-zA-Z0-9\-]', '-')
  $deploymentName = "ContentHub-Install-$safeName"
  if ($deploymentName.Length -gt 62) { $deploymentName = $deploymentName.Substring(0, 62) }

  # ✅ FIX ${deploymentName}?api-version
  $deployUri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Resources/deployments/${deploymentName}?api-version=$DeploymentApiVersion"

  $deployBody = @{
    properties = @{
      mode = "Incremental"
      template = $template
      parameters = @{
        workspace = @{ value = $WorkspaceName }
        "workspace-location" = @{ value = "" }
      }
    }
  }

  Write-Host "    ==> Deploy packagedContent (Incremental): $deploymentName"
  Invoke-ArmWithRetry -Method PUT -Uri $deployUri -Body $deployBody | Out-Null

  $deadline = (Get-Date).AddSeconds($DeploymentWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $get = Invoke-ArmWithRetry -Method GET -Uri $deployUri
    $state = $get.properties.provisioningState
    Write-Verbose "    Deployment state: $state" -Verbose

    if ($state -eq "Succeeded") {
      Write-Host "    OK: packagedContent desplegado"
      return
    }
    if ($state -in @("Failed","Canceled")) {
      $details = $get.properties.error | ConvertTo-Json -Depth 30
      throw "Deployment $deploymentName terminó en estado $state. Error: $details"
    }

    Start-Sleep -Seconds 10
  }

  Write-Warning "Timeout esperando el deployment $deploymentName. Puede seguir en ejecución."
}

# ------------------------
# MAIN
# ------------------------
Write-Host "Instalación de soluciones solicitadas: $SolutionsCsv"

$script:SubscriptionId = Get-SubscriptionIdFromContext
$script:ArmToken = Get-ArmToken

$solutions = Parse-SolutionsCsv -Csv $SolutionsCsv
Write-Host "Total soluciones a procesar: $($solutions.Count)"
Write-Host ("Preview: " + ($(if ($IncludePreview) { "INCLUIDO" } else { "EXCLUIDO" })))

foreach ($sol in $solutions) {
  Write-Host ""
  Write-Host "============================="
  Write-Host "Procesando: $sol"
  Write-Host "============================="

  # 1) catálogo
  $candidates = Get-CatalogCandidates -DisplayName $sol
  $match = Select-BestCatalogMatch -RequestedDisplayName $sol -Candidates $candidates

  Write-Host "Catálogo match: $($match.properties.displayName) (version: $($match.properties.version))"

  # 2) install package (contentPackages)
  Install-ContentPackageFromCatalogItem -CatalogItem $match

  # 3) deploy packagedContent (Installed content items)
  Deploy-PackagedContentFromCatalogItem -CatalogItem $match
}

Write-Host ""
Write-Host "Fin instalación de soluciones."
