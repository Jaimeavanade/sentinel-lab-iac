<#
.SYNOPSIS
Instala soluciones de Microsoft Sentinel Content Hub desde un CSV de displayName.

.DESCRIPTION
- Parse SolutionsCsv (separado por comas).
- Para cada displayName:
  1) Busca en el catálogo (contentProductPackages) usando $search y filtra contentKind=Solution.
     (Soporta $expand=properties/packagedContent) [2](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
  2) Selecciona la versión más reciente (semver).
  3) Instala/actualiza el contentPackage vía PUT incluyendo contentSchemaVersion (evita 400). 
  4) Despliega packagedContent vía Microsoft.Resources/deployments (Incremental) para materializar
     Installed content items (reglas, workbooks, etc.). [1](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)[2](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)

REQUISITOS:
- Azure Login OIDC ya ejecutado en el workflow.
- Permisos adecuados (p.ej. Microsoft Sentinel Contributor). [3](https://github.com/noodlemctwoodle/Sentinel-As-Code)
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

  # API para deployments (Microsoft.Resources/deployments)
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

function Get-SubscriptionIdFromContext {
  try {
    $ctx = Get-AzContext
    if ($ctx -and $ctx.Subscription -and $ctx.Subscription.Id) { return $ctx.Subscription.Id }
  } catch {}
  # fallback
  try {
    $sub = az account show --query id -o tsv
    if ($sub) { return $sub }
  } catch {}
  throw "No se pudo determinar SubscriptionId. Asegúrate de estar autenticado (azure/login) y con contexto."
}

function Get-ArmToken {
  # Token ARM con Azure CLI (robusto en GH Actions OIDC)
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

      # 400: no reintentar; mostrar body
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

  # Soportamos coma y también pipes/newlines por si llega formateado
  $raw = $Csv -replace '\|', ',' -replace "`r", "," -replace "`n", ","
  $list = $raw.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  return $list
}

function Get-CatalogSolutionMatch {
  <#
    Busca en catálogo por $search y devuelve el "mejor match" exacto por displayName,
    y si no hay exacto, el primero que contenga.
    Usa contentProductPackages (catálogo) [2](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$DisplayName
  )

  $search = [System.Uri]::EscapeDataString($DisplayName)
  $uri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$search=$search&`$expand=properties/packagedContent&`$top=50"

  $resp = Invoke-ArmWithRetry -Method GET -Uri $uri

  if (-not $resp.value) {
    throw "Catálogo sin resultados para '$DisplayName'."
  }

  $candidates = $resp.value | Where-Object { $_.properties.contentKind -eq "Solution" }

  if (-not $IncludePreview) {
    $candidates = $candidates | Where-Object { -not $_.properties.isPreview }
  }

  if (-not $candidates -or $candidates.Count -eq 0) {
    throw "No hay candidatos Solution en catálogo para '$DisplayName' (quizá Preview o nombre distinto)."
  }

  # 1) match exacto case-insensitive
  $dn = $DisplayName.Trim().ToLower()
  $exact = $candidates | Where-Object { $_.properties.displayName -and $_.properties.displayName.Trim().ToLower() -eq $dn }

  if ($exact -and $exact.Count -gt 0) {
    $candidates = $exact
  } else {
    # 2) match contains
    $contains = $candidates | Where-Object { $_.properties.displayName -and $_.properties.displayName.Trim().ToLower().Contains($dn) }
    if ($contains -and $contains.Count -gt 0) {
      $candidates = $contains
    }
  }

  # Elegir versión más alta (semver)
  $sorted = $candidates | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending

  return ($sorted | Select-Object -First 1)
}

function Install-ContentPackage {
  <#
    Instala/actualiza paquete vía contentPackages/{packageId} PUT 
  #>
  param(
    [Parameter(Mandatory=$true)]$CatalogItem
  )

  $contentId = $CatalogItem.properties.contentId
  $contentKind = $CatalogItem.properties.contentKind
  $contentProductId = $CatalogItem.properties.contentProductId
  $displayName = $CatalogItem.properties.displayName
  $version = $CatalogItem.properties.version

  # contentSchemaVersion es clave para evitar 400 (reportado por la comunidad) 
  $schemaVersion = $CatalogItem.properties.contentSchemaVersion
  if (-not $schemaVersion) { $schemaVersion = "2.0" }

  # packageId normalmente coincide con el "name" del item del catálogo (ej: ...solution-syslog)
  $packageId = $CatalogItem.name
  if (-not $packageId) { $packageId = $contentId }

  Write-Host "==> Instalando/actualizando: $displayName"
  Write-Host "    packageId          : $packageId"
  Write-Host "    contentId          : $contentId"
  Write-Host "    version            : $version"
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
  Write-Host "    OK: Package instalado/actualizado"
}

function Deploy-PackagedContent {
  <#
    Despliega properties.packagedContent como ARM template (Microsoft.Resources/deployments) mode=Incremental
    para instalar todos los Installed content items. [1](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)[2](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)
  #>
  param(
    [Parameter(Mandatory=$true)]$CatalogItem
  )

  $displayName = $CatalogItem.properties.displayName
  $template = $CatalogItem.properties.packagedContent
  if (-not $template) {
    throw "No hay packagedContent en catálogo para '$displayName'. Revisa que el $expand esté aplicado."
  }

  $safeName = ($displayName -replace '[^a-zA-Z0-9\-]', '-')
  $deploymentName = "ContentHub-Install-$safeName"
  if ($deploymentName.Length -gt 62) { $deploymentName = $deploymentName.Substring(0, 62) }

  # ✅ IMPORTANTE: usar ${deploymentName} para evitar el bug $deploymentName?api
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

  # Esperar fin del deployment
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
if (-not $solutions -or $solutions.Count -eq 0) {
  throw "SolutionsCsv está vacío o no se pudo parsear."
}

Write-Host "Total soluciones a procesar: $($solutions.Count)"
if (-not $IncludePreview) {
  Write-Host "Preview: EXCLUIDO"
} else {
  Write-Host "Preview: INCLUIDO"
}

foreach ($sol in $solutions) {
  try {
    Write-Host ""
    Write-Host "============================="
    Write-Host "Procesando: $sol"
    Write-Host "============================="

    $catalogItem = Get-CatalogSolutionMatch -DisplayName $sol
    Write-Host "Catálogo match: $($catalogItem.properties.displayName) (version: $($catalogItem.properties.version))"

    Install-ContentPackage -CatalogItem $catalogItem

    # Paso clave: desplegar contenido (Installed content items)
    Deploy-PackagedContent -CatalogItem $catalogItem

  } catch {
    Write-Error "ERROR en solución '$sol': $($_.Exception.Message)"
    throw
  }
}

Write-Host ""
Write-Host "Fin instalación de soluciones."
