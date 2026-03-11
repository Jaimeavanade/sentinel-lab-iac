<#
.SYNOPSIS
Reinstala soluciones de Microsoft Sentinel Content Hub en un workspace (Uninstall + Install).

.DESCRIPTION
- Obtiene los Content Packages instalados en el workspace (contentPackages).
- Filtra los que son contentKind = 'Solution'.
- Opcionalmente excluye contenido Preview (si el campo existe).
- Opcionalmente filtra por displayName (lista).
- Reinstala cada solución: DELETE (Uninstall) y PUT (Install).

NOTA IMPORTANTE:
- El token ARM se obtiene vía Azure CLI (az account get-access-token) para evitar InvalidAuthenticationToken
  en runners de GitHub Actions con OIDC.

.PARAMETER SubscriptionId
Id de suscripción.

.PARAMETER ResourceGroupName
Nombre del RG.

.PARAMETER WorkspaceName
Nombre del Log Analytics workspace.

.PARAMETER SolutionDisplayName
Lista opcional de displayName a reinstalar (si no se indica, reinstala todas las soluciones instaladas).

.PARAMETER IncludePreview
Si se especifica, también reinstala soluciones marcadas como Preview.

.PARAMETER ApiVersion
Versión de API para contentPackages. Por defecto 2025-09-01.

.PARAMETER DelaySecondsBetweenOperations
Delay entre operaciones para evitar throttling.

.PARAMETER MaxRetries
Reintentos ante fallos transitorios (429/5xx).

.PARAMETER RetryDelaySeconds
Espera base entre reintentos.
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

  # Por defecto usamos latest del catálogo (recomendado).
  # Si pones -UseInstalledVersion, intentará reinstalar la versión instalada (si aún existe en catálogo).
  [Parameter(Mandatory = $false)]
  [switch]$UseInstalledVersion,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [int]$DelaySecondsBetweenOperations = 3,

  [Parameter(Mandatory = $false)]
  [int]$MaxRetries = 5,

  [Parameter(Mandatory = $false)]
  [int]$RetryDelaySeconds = 5,

  # Espera tras Uninstall hasta que el recurso deje de existir (o cambie estado)
  [Parameter(Mandatory = $false)]
  [int]$UninstallWaitSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  try {
    $t = az account get-access-token `
      --resource https://management.azure.com/ `
      --query accessToken -o tsv

    if (-not $t -or $t.Trim().Length -lt 100) {
      throw "Token ARM vacío/no válido devuelto por Azure CLI."
    }
    return $t
  } catch {
    throw "No se pudo obtener token ARM vía Azure CLI. Detalle: $($_.Exception.Message)"
  }
}

function Test-HasProperty {
  param(
    [Parameter(Mandatory=$true)] $Object,
    [Parameter(Mandatory=$true)] [string]$PropertyName
  )
  return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $PropertyName
}

function Get-PreviewFlag {
  param([Parameter(Mandatory=$true)] $Package)

  if (-not (Test-HasProperty -Object $Package -PropertyName "properties")) { return $false }
  if (-not (Test-HasProperty -Object $Package.properties -PropertyName "isPreview")) { return $false }

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
    [Parameter(Mandatory = $true)][ValidateSet("GET","PUT","DELETE")]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [Parameter(Mandatory = $false)]
    [object]$Body
  )

  $headers = @{
    "Authorization" = "Bearer $script:ArmToken"
    "Content-Type"  = "application/json"
  }

  $attempt = 0
  while ($true) {
    $attempt++
    try {
      Write-Verbose "$Method $Uri (attempt $attempt/$MaxRetries)" -Verbose
      if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 50
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
      }
    } catch {
      $msg = $_.Exception.Message
      $statusCode = $null

      try {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
          $statusCode = [int]$_.Exception.Response.StatusCode
        }
      } catch { }

      # Para 400, NO reintentar: es request inválida. Mejor mostrar body.
      if ($statusCode -eq 400) {
        $body = Get-ErrorBodyFromException -Exception $_.Exception
        if ($body) {
          throw "Fallo en $Method $Uri. StatusCode=400. Body=$body"
        }
        throw "Fallo en $Method $Uri. StatusCode=400. Error=$msg"
      }

      $isTransient = $false
      if ($statusCode -eq 429) { $isTransient = $true }
      if ($statusCode -ge 500 -and $statusCode -le 599) { $isTransient = $true }

      if ($attempt -ge $MaxRetries -or -not $isTransient) {
        $body = Get-ErrorBodyFromException -Exception $_.Exception
        if ($body) {
          throw "Fallo en $Method $Uri. StatusCode=$statusCode. Error=$msg. Body=$body"
        }
        throw "Fallo en $Method $Uri. StatusCode=$statusCode. Error=$msg"
      }

      $sleep = $RetryDelaySeconds * $attempt
      Write-Warning "Fallo transitorio (StatusCode=$statusCode). Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

function Get-CatalogProductInfo {
  <#
    Devuelve info de catálogo (latest o versión instalada si se solicita).
    Usa endpoint contentProductPackages (catálogo). [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$ContentId,
    [Parameter(Mandatory=$true)][string]$ContentKind,
    [Parameter(Mandatory=$false)][string]$PreferredVersion
  )

  # OData filter: properties/contentId eq '...' and properties/contentKind eq 'Solution'
  # Nota: el endpoint soporta $filter/$orderby/$top. [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
  $filter = "properties/contentId eq '$ContentId' and properties/contentKind eq '$ContentKind'"
  $encodedFilter = [System.Uri]::EscapeDataString($filter)

  $catalogUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encodedFilter&`$top=50"
  Write-Verbose "GET catalog: $catalogUri" -Verbose

  $catalog = Invoke-ArmWithRetry -Method GET -Uri $catalogUri
  if (-not $catalog.value -or $catalog.value.Count -eq 0) {
    throw "No se encontró el paquete en catálogo para contentId=$ContentId / kind=$ContentKind"
  }

  # Si se pide una versión concreta (installed), intentamos encontrarla; si no, cogemos latest (mayor).
  $candidates = $catalog.value

  # Elegir por PreferredVersion si existe en catálogo
  if ($PreferredVersion) {
    $match = $candidates | Where-Object {
      (Test-HasProperty -Object $_ -PropertyName "properties") -and
      (Test-HasProperty -Object $_.properties -PropertyName "version") -and
      $_.properties.version -eq $PreferredVersion
    } | Select-Object -First 1

    if ($match) {
      return @{
        version = $match.properties.version
        contentProductId = $match.properties.contentProductId
        displayName = $match.properties.displayName
      }
    }

    Write-Warning "La versión preferida [$PreferredVersion] no aparece en catálogo. Se usará latest."
  }

  # Orden semver: intentamos [version] (si falla, string)
  $sorted = $candidates | Sort-Object -Property @{
    Expression = {
      try { [version]$_.properties.version } catch { [version]"0.0.0" }
    }
  } -Descending

  $latest = $sorted | Select-Object -First 1
  return @{
    version = $latest.properties.version
    contentProductId = $latest.properties.contentProductId
    displayName = $latest.properties.displayName
  }
}

function Wait-Until-Uninstalled {
  param(
    [Parameter(Mandatory=$true)][string]$PackageId
  )

  $pkgGetUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${PackageId}?api-version=$ApiVersion"

  $deadline = (Get-Date).AddSeconds($UninstallWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-ArmWithRetry -Method GET -Uri $pkgGetUri | Out-Null
      Write-Verbose "Aún aparece instalado $PackageId, esperando..." -Verbose
      Start-Sleep -Seconds 5
    } catch {
      # Si devuelve 404 o similar, ya no está.
      Write-Verbose "Confirmado: $PackageId ya no está instalado (o no se puede obtener). Continuando..." -Verbose
      return
    }
  }

  Write-Warning "Timeout esperando a que se complete el uninstall de $PackageId. Continuamos igualmente."
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

# List installed contentPackages [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
$listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
Write-Verbose "GET $listUri" -Verbose
$installed = Invoke-ArmWithRetry -Method GET -Uri $listUri

if (-not $installed.value) {
  Write-Warning "No se han encontrado contentPackages instalados en el workspace."
  return
}

# Filter Solutions
$solutions = $installed.value | Where-Object {
  (Test-HasProperty -Object $_ -PropertyName "properties") -and
  (Test-HasProperty -Object $_.properties -PropertyName "contentKind") -and
  $_.properties.contentKind -eq "Solution"
}

if (-not $IncludePreview) {
  $solutions = $solutions | Where-Object { -not (Get-PreviewFlag -Package $_) }
}

if ($SolutionDisplayName.Count -gt 0) {
  $wanted = $SolutionDisplayName | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $solutions = $solutions | Where-Object {
    (Test-HasProperty -Object $_.properties -PropertyName "displayName") -and
    ($wanted -contains $_.properties.displayName)
  }
}

if (-not $solutions -or $solutions.Count -eq 0) {
  Write-Warning "No hay soluciones que cumplan los filtros (o no hay soluciones instaladas)."
  return
}

Write-Host "Soluciones a reinstalar: $($solutions.Count)" -ForegroundColor Yellow
$solutions | ForEach-Object {
  $dn = $_.properties.displayName
  $ver = $_.properties.version
  $prev = Get-PreviewFlag -Package $_
  Write-Host " - $dn  (installed version: $ver, preview: $prev)"
}

foreach ($pkg in $solutions) {

  $packageId      = $pkg.name
  $displayName    = $pkg.properties.displayName
  $contentId      = $pkg.properties.contentId
  $contentKind    = $pkg.properties.contentKind
  $installedVer   = $pkg.properties.version

  Write-Host ""
  Write-Host ">>> Reinstalando: $displayName" -ForegroundColor Green
  Write-Host "    packageId : $packageId"
  Write-Host "    contentId : $contentId"
  Write-Host "    installed : $installedVer"

  # Siempre resolvemos info desde catálogo para evitar 400 (version debe ser latest) [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
  $preferred = $null
  if ($UseInstalledVersion) { $preferred = $installedVer }

  $catalogInfo = Get-CatalogProductInfo -ContentId $contentId -ContentKind $contentKind -PreferredVersion $preferred
  $targetVersion = $catalogInfo.version
  $targetProductId = $catalogInfo.contentProductId

  Write-Host "    targetVersion    : $targetVersion"
  Write-Host "    targetProductId  : $targetProductId"

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${packageId}?api-version=$ApiVersion"

  # Uninstall [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/uninstall?view=rest-securityinsights-2025-09-01)
  if ($PSCmdlet.ShouldProcess($displayName, "UNINSTALL $packageId")) {
    Invoke-ArmWithRetry -Method DELETE -Uri $pkgUri | Out-Null
    Write-Host "    Uninstall OK" -ForegroundColor DarkGreen
  }

  # Esperar a que se refleje el uninstall para evitar estados intermedios
  Wait-Until-Uninstalled -PackageId $packageId
  Start-Sleep -Seconds $DelaySecondsBetweenOperations

  # Install (version debe ser latest) [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)
  $installBody = @{
    properties = @{
      contentId        = $contentId
      contentKind      = $contentKind
      contentProductId = $targetProductId
      displayName      = $displayName
      version          = $targetVersion
    }
  }

  if ($PSCmdlet.ShouldProcess($displayName, "INSTALL $packageId")) {
    Invoke-ArmWithRetry -Method PUT -Uri $pkgUri -Body $installBody | Out-Null
    Write-Host "    Install OK" -ForegroundColor DarkGreen
  }

  Start-Sleep -Seconds $DelaySecondsBetweenOperations
}

Write-Host ""
Write-Host "Proceso finalizado." -ForegroundColor Cyan
