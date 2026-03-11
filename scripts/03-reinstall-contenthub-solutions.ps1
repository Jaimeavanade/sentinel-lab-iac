<#
.SYNOPSIS
Reinstala soluciones Content Hub (contentPackages) y despliega todos sus "Installed content items"
mediante deployment del packagedContent (ARM template) en modo Incremental.

.DESCRIPTION
1) Lista soluciones instaladas (contentPackages)
2) Uninstall (DELETE)
3) Install (PUT) incluyendo contentSchemaVersion (evita 400)
4) Obtiene packagedContent desde catálogo (contentProductPackages con $expand=properties/packagedContent)
5) Ejecuta un deployment RG (Microsoft.Resources/deployments) mode=Incremental con ese template
   => así se instalan/recuperan los "Installed content items"

NOTA:
- Token ARM se obtiene con Azure CLI (robusto con OIDC).
- Hay casos reportados donde instalar por API no refresca metadata/plantillas hasta desplegar contenido. [1](https://learn.microsoft.com/en-us/azure/templates/microsoft.resources/deployments)
- El patrón de despliegue incremental con template=packagedContent es el enfoque “correcto”. [2](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string[]]$SolutionDisplayName = @(),

  [Parameter(Mandatory = $false)]
  [switch]$IncludePreview,

  [Parameter(Mandatory = $false)]
  [switch]$UseInstalledVersion,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  # Deployment API para Microsoft.Resources/deployments
  [Parameter(Mandatory = $false)]
  [string]$DeploymentApiVersion = "2021-04-01",

  [Parameter(Mandatory = $false)]
  [int]$DelaySecondsBetweenOperations = 3,

  [Parameter(Mandatory = $false)]
  [int]$MaxRetries = 5,

  [Parameter(Mandatory = $false)]
  [int]$RetryDelaySeconds = 5,

  [Parameter(Mandatory = $false)]
  [int]$UninstallWaitSeconds = 60,

  # Nuevo: Espera máxima a que termine el deployment del packagedContent
  [Parameter(Mandatory = $false)]
  [int]$DeploymentWaitSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa azure/login y permisos."
  }
  return $t
}

function Test-HasProperty {
  param([Parameter(Mandatory=$true)] $Object, [Parameter(Mandatory=$true)] [string]$PropertyName)
  return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $PropertyName
}

function Get-PreviewFlag {
  param([Parameter(Mandatory=$true)] $Package)
  if (-not (Test-HasProperty $Package "properties")) { return $false }
  if (-not (Test-HasProperty $Package.properties "isPreview")) { return $false }
  try { return [bool]$Package.properties.isPreview } catch { return $false }
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
    [Parameter(Mandatory = $true)][ValidateSet("GET","PUT","POST","DELETE")]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [Parameter(Mandatory = $false)]
    [object]$Body
  )

  $headers = @{
    Authorization = "Bearer $script:ArmToken"
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

      # 400 => request inválida: mostrar body y no reintentar
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

function Get-CatalogProductInfo {
  <#
    Catálogo: contentProductPackages. Expandible: properties/packagedContent [3](https://charbelnemnom.com/update-microsoft-sentinel-workbooks-at-scale/)[4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages?view=rest-securityinsights-2025-09-01)
    Devolvemos version, contentProductId, contentSchemaVersion y packagedContent (ARM template).
  #>
  param(
    [Parameter(Mandatory=$true)][string]$ContentId,
    [Parameter(Mandatory=$true)][string]$ContentKind,
    [Parameter(Mandatory=$false)][string]$PreferredVersion
  )

  $filter = "properties/contentId eq '$ContentId' and properties/contentKind eq '$ContentKind'"
  $encodedFilter = [System.Uri]::EscapeDataString($filter)

  # Importante: expand packagedContent para poder desplegar todos los items
  $catalogUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encodedFilter&`$expand=properties/packagedContent&`$top=50"
  Write-Verbose "GET catalog: $catalogUri" -Verbose

  $catalog = Invoke-ArmWithRetry -Method GET -Uri $catalogUri
  if (-not $catalog.value -or $catalog.value.Count -eq 0) {
    throw "No se encontró en catálogo: contentId=$ContentId kind=$ContentKind"
  }

  $candidates = $catalog.value

  if ($PreferredVersion) {
    $match = $candidates | Where-Object { $_.properties.version -eq $PreferredVersion } | Select-Object -First 1
    if ($match) {
      return @{
        version = $match.properties.version
        contentProductId = $match.properties.contentProductId
        contentSchemaVersion = $match.properties.contentSchemaVersion
        packagedContent = $match.properties.packagedContent
        displayName = $match.properties.displayName
      }
    }
    Write-Warning "PreferredVersion [$PreferredVersion] no aparece en catálogo. Usando latest."
  }

  # Latest semver
  $sorted = $candidates | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending
  $latest = $sorted | Select-Object -First 1

  return @{
    version = $latest.properties.version
    contentProductId = $latest.properties.contentProductId
    contentSchemaVersion = $latest.properties.contentSchemaVersion
    packagedContent = $latest.properties.packagedContent
    displayName = $latest.properties.displayName
  }
}

function Wait-Until-Uninstalled {
  param([Parameter(Mandatory=$true)][string]$PackageId)

  $pkgGetUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${PackageId}?api-version=$ApiVersion"
  $deadline = (Get-Date).AddSeconds($UninstallWaitSeconds)

  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-ArmWithRetry -Method GET -Uri $pkgGetUri | Out-Null
      Write-Verbose "Aún aparece instalado $PackageId, esperando..." -Verbose
      Start-Sleep -Seconds 5
    } catch {
      Write-Verbose "Confirmado: $PackageId ya no está instalado. Continuando..." -Verbose
      return
    }
  }

  Write-Warning "Timeout esperando uninstall de $PackageId. Continuamos igualmente."
}

function Start-PackagedContentDeployment {
  <#
    Despliega packagedContent (ARM template) con Microsoft.Resources/deployments mode=Incremental
    => Esto es lo que “materializa” los Installed content items. [2](https://techcommunity.microsoft.com/discussions/sharepointdev/the-remote-server-returned-an-error-400-bad-request/2332780)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$SolutionDisplayName,
    [Parameter(Mandatory=$true)]$PackagedContentTemplate
  )

  # Nombre de deployment con límite razonable
  $safeName = $SolutionDisplayName -replace '[^a-zA-Z0-9\-]', '-'
  $deploymentName = "ContentHub-Reinstall-$safeName"
  if ($deploymentName.Length -gt 62) { $deploymentName = $deploymentName.Substring(0, 62) }

  $deployUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$deploymentName?api-version=$DeploymentApiVersion"

  $deployBody = @{
    properties = @{
      mode = "Incremental"
      template = $PackagedContentTemplate
      parameters = @{
        workspace = @{ value = $WorkspaceName }
        "workspace-location" = @{ value = "" }
      }
    }
  }

  Write-Host "    Deploy packagedContent (Incremental) => $deploymentName" -ForegroundColor Cyan
  Invoke-ArmWithRetry -Method PUT -Uri $deployUri -Body $deployBody | Out-Null

  # Espera a que termine
  $deadline = (Get-Date).AddSeconds($DeploymentWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $get = Invoke-ArmWithRetry -Method GET -Uri $deployUri
    $state = $get.properties.provisioningState
    Write-Verbose "    Deployment state: $state" -Verbose

    if ($state -eq "Succeeded") { return }
    if ($state -in @("Failed","Canceled")) {
      $details = $get.properties.error | ConvertTo-Json -Depth 20
      throw "Deployment $deploymentName terminó en estado $state. Error: $details"
    }
    Start-Sleep -Seconds 10
  }

  Write-Warning "Timeout esperando el deployment $deploymentName. Puede seguir en ejecución."
}

# =========================
# MAIN
# =========================
Write-Host "== Reinstall Content Hub Solutions ==" -ForegroundColor Cyan
Write-Host "Subscription : $SubscriptionId"
Write-Host "RG          : $ResourceGroupName"
Write-Host "Workspace   : $WorkspaceName"
Write-Host "IncludePreview: $IncludePreview"
Write-Host "UseInstalledVersion: $UseInstalledVersion"
if ($SolutionDisplayName.Count -gt 0) {
  Write-Host ("Filtro displayName: " + ($SolutionDisplayName -join ", "))
} else {
  Write-Host "Filtro displayName: (todas)"
}

$script:ArmToken = Get-ArmToken

# List installed contentPackages 
$listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
Write-Verbose "GET $listUri" -Verbose
$installed = Invoke-ArmWithRetry -Method GET -Uri $listUri

if (-not $installed.value) {
  Write-Warning "No hay contentPackages instalados."
  return
}

$solutions = $installed.value | Where-Object {
  (Test-HasProperty $_ "properties") -and
  (Test-HasProperty $_.properties "contentKind") -and
  $_.properties.contentKind -eq "Solution"
}

if (-not $IncludePreview) {
  $solutions = $solutions | Where-Object { -not (Get-PreviewFlag -Package $_) }
}

if ($SolutionDisplayName.Count -gt 0) {
  $wanted = $SolutionDisplayName | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $solutions = $solutions | Where-Object { $wanted -contains $_.properties.displayName }
}

if (-not $solutions -or $solutions.Count -eq 0) {
  Write-Warning "No hay soluciones que cumplan los filtros."
  return
}

Write-Host "Soluciones a reinstalar: $($solutions.Count)" -ForegroundColor Yellow
$solutions | ForEach-Object {
  Write-Host " - $($_.properties.displayName)  (installed: $($_.properties.version), preview: $(Get-PreviewFlag -Package $_))"
}

foreach ($pkg in $solutions) {

  $packageId    = $pkg.name
  $displayName  = $pkg.properties.displayName
  $contentId    = $pkg.properties.contentId
  $contentKind  = $pkg.properties.contentKind
  $installedVer = $pkg.properties.version

  Write-Host ""
  Write-Host ">>> Reinstalando: $displayName" -ForegroundColor Green
  Write-Host "    packageId : $packageId"
  Write-Host "    contentId : $contentId"
  Write-Host "    installed : $installedVer"

  $preferred = $null
  if ($UseInstalledVersion) { $preferred = $installedVer }

  $catalogInfo = Get-CatalogProductInfo -ContentId $contentId -ContentKind $contentKind -PreferredVersion $preferred

  $targetVersion = $catalogInfo.version
  $targetProductId = $catalogInfo.contentProductId
  $targetSchemaVersion = $catalogInfo.contentSchemaVersion
  if (-not $targetSchemaVersion) { $targetSchemaVersion = "2.0" }

  $packagedContent = $catalogInfo.packagedContent
  if (-not $packagedContent) {
    throw "No se pudo obtener packagedContent del catálogo para $displayName (¿falta expand?)."
  }

  Write-Host "    targetVersion       : $targetVersion"
  Write-Host "    targetProductId     : $targetProductId"
  Write-Host "    contentSchemaVersion: $targetSchemaVersion"

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$ApiVersion"

  # Uninstall
  if ($PSCmdlet.ShouldProcess($displayName, "UNINSTALL $packageId")) {
    Invoke-ArmWithRetry -Method DELETE -Uri $pkgUri | Out-Null
    Write-Host "    Uninstall OK" -ForegroundColor DarkGreen
  }

  Wait-Until-Uninstalled -PackageId $packageId
  Start-Sleep -Seconds $DelaySecondsBetweenOperations

  # Install (incluye schemaVersion)
  $installBody = @{
    properties = @{
      contentId            = $contentId
      contentKind          = $contentKind
      contentProductId     = $targetProductId
      displayName          = $displayName
      version              = $targetVersion
      contentSchemaVersion = $targetSchemaVersion
    }
  }

  if ($PSCmdlet.ShouldProcess($displayName, "INSTALL $packageId")) {
    Invoke-ArmWithRetry -Method PUT -Uri $pkgUri -Body $installBody | Out-Null
    Write-Host "    Install OK" -ForegroundColor DarkGreen
  }

  Start-Sleep -Seconds $DelaySecondsBetweenOperations

  # ✅ Paso clave: desplegar packagedContent para instalar TODOS los items
  if ($PSCmdlet.ShouldProcess($displayName, "DEPLOY packagedContent (Installed content items)")) {
    Start-PackagedContentDeployment -SolutionDisplayName $displayName -PackagedContentTemplate $packagedContent
    Write-Host "    PackagedContent deployment OK" -ForegroundColor DarkGreen
  }

  Start-Sleep -Seconds $DelaySecondsBetweenOperations
}

Write-Host ""
Write-Host "Proceso finalizado." -ForegroundColor Cyan
