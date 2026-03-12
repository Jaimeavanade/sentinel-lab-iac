<#
.SYNOPSIS
Instala soluciones de Microsoft Sentinel Content Hub desde un CSV.

.DESCRIPTION
Entrada recomendada: contentId (más específico).
- Si el elemento empieza por "azuresentinel." => se trata como contentId y se resuelve por $filter (exacto).
- Si no => se trata como displayName (fallback) y se resuelve por $search + match.

Usa:
- Catálogo: contentProductPackages (soporta $filter/$search/$top y puede expandir packagedContent). [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)[2](https://github.com/pkhabazi/sentineldevops)
- Install: contentPackages/{packageId} (PUT) requiere contentId/contentKind/contentProductId/displayName/version. [3](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/deploying-and-managing-microsoft-sentinel-as-code/1131928)
- Deploy: Microsoft.Resources/deployments mode=Incremental con template=packagedContent (materializa items). [4](https://www.youtube.com/watch?v=PAjnhYUFxPo)
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

function Get-SubscriptionIdFromContext {
  try {
    $ctx = Get-AzContext
    if ($ctx -and $ctx.Subscription -and $ctx.Subscription.Id) { return $ctx.Subscription.Id }
  } catch {}

  $sub = az account show --query id -o tsv
  if ($sub) { return $sub }

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
      $reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
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

function Get-CatalogByContentId {
  <#
    Resuelve EXACTO por contentId usando $filter (más fiable que displayName).
    El endpoint soporta $filter y puede expandir packagedContent. [1](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/README.md)[2](https://github.com/pkhabazi/sentineldevops)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$ContentId
  )

  $filter = "properties/contentId eq '$ContentId' and properties/contentKind eq 'Solution'"
  $encoded = [System.Uri]::EscapeDataString($filter)

  $uri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encoded&`$expand=properties/packagedContent&`$top=50"

  $resp = Invoke-ArmWithRetry -Method GET -Uri $uri
  if (-not $resp.value -or $resp.value.Count -eq 0) {
    throw "No se encontró en catálogo el contentId '$ContentId'. Revisa el CSV."
  }

  $candidates = $resp.value
  if (-not $IncludePreview) {
    $candidates = $candidates | Where-Object { -not $_.properties.isPreview }
  }

  # Elegir versión más alta por si hay varias
  $sorted = $candidates | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending

  return ($sorted | Select-Object -First 1)
}

function Get-CatalogByDisplayName {
  <#
    Fallback: busca por displayName con $search.
    (Lo dejamos por compatibilidad.)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$DisplayName
  )

  $search = [System.Uri]::EscapeDataString($DisplayName)
  $uri = "https://management.azure.com/subscriptions/$script:SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$search=$search&`$expand=properties/packagedContent&`$top=50"

  $resp = Invoke-ArmWithRetry -Method GET -Uri $uri
  if (-not $resp.value) { throw "Catálogo sin resultados para '$DisplayName'." }

  $candidates = $resp.value | Where-Object { $_.properties.contentKind -eq "Solution" }
  if (-not $IncludePreview) { $candidates = $candidates | Where-Object { -not $_.properties.isPreview } }

  $req = $DisplayName.Trim().ToLower()
  $exact = $candidates | Where-Object { $_.properties.displayName -and $_.properties.displayName.Trim().ToLower() -eq $req }
  $pool = if ($exact) { $exact } else { $candidates | Where-Object { $_.properties.displayName -and $_.properties.displayName.Trim().ToLower().Contains($req) } }

  if (-not $pool) {
    $names = ($candidates | Select-Object -ExpandProperty properties | Select-Object -ExpandProperty displayName | Sort-Object -Unique) -join " | "
    throw "No hay match para '$DisplayName'. Candidatos: $names"
  }

  $sorted = $pool | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending

  return ($sorted | Select-Object -First 1)
}

function Install-ContentPackageFromCatalogItem {
  <#
    Instala mediante contentPackages/{packageId}. packageId lo ponemos como contentId (correcto). [3](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/deploying-and-managing-microsoft-sentinel-as-code/1131928)
  #>
  param([Parameter(Mandatory=$true)]$CatalogItem)

  $contentId        = $CatalogItem.properties.contentId
  $contentKind      = $CatalogItem.properties.contentKind
  $contentProductId = $CatalogItem.properties.contentProductId
  $displayName      = $CatalogItem.properties.displayName
  $version          = $CatalogItem.properties.version

  # contentSchemaVersion: lo enviamos para evitar errores conocidos de 400 en installs
  $schemaVersion = $CatalogItem.properties.contentSchemaVersion
  if (-not $schemaVersion) { $schemaVersion = "2.0" }

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

function Deploy-PackagedContentFromCatalogItem {
  <#
    Despliega packagedContent (ARM template) en modo Incremental para materializar items. [4](https://www.youtube.com/watch?v=PAjnhYUFxPo)
  #>
  param([Parameter(Mandatory=$true)]$CatalogItem)

  $displayName = $CatalogItem.properties.displayName
  $template = $CatalogItem.properties.packagedContent
  if (-not $template) { throw "No hay packagedContent en catálogo para '$displayName'." }

  $safeName = ($displayName -replace '[^a-zA-Z0-9\-]', '-')
  $deploymentName = "ContentHub-Install-$safeName"
  if ($deploymentName.Length -gt 62) { $deploymentName = $deploymentName.Substring(0, 62) }

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

  # Si parece contentId, resolver por filter (exacto)
  $catalogItem = $null
  if ($sol.Trim().ToLower().StartsWith("azuresentinel.")) {
    $catalogItem = Get-CatalogByContentId -ContentId $sol.Trim()
  } else {
    $catalogItem = Get-CatalogByDisplayName -DisplayName $sol.Trim()
  }

  Write-Host "Catálogo match: $($catalogItem.properties.displayName) (version: $($catalogItem.properties.version))"

  Install-ContentPackageFromCatalogItem -CatalogItem $catalogItem
  Deploy-PackagedContentFromCatalogItem -CatalogItem $catalogItem
}

Write-Host ""
Write-Host "Fin instalación de soluciones."
