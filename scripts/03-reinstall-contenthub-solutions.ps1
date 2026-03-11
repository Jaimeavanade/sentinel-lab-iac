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

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [int]$DelaySecondsBetweenOperations = 3,

  [Parameter(Mandatory = $false)]
  [int]$MaxRetries = 5,

  [Parameter(Mandatory = $false)]
  [int]$RetryDelaySeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  try {
    # Token ARM con Azure CLI (robusto en OIDC GitHub Actions)
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
    [Parameter(Mandatory=$true)]
    $Object,
    [Parameter(Mandatory=$true)]
    [string]$PropertyName
  )
  return $null -ne $Object -and $Object.PSObject.Properties.Name -contains $PropertyName
}

function Get-PreviewFlag {
  param(
    [Parameter(Mandatory=$true)]
    $Package
  )
  # Si no existe properties o no existe isPreview => asumimos False
  if (-not (Test-HasProperty -Object $Package -PropertyName "properties")) { return $false }
  if (-not (Test-HasProperty -Object $Package.properties -PropertyName "isPreview")) { return $false }

  # Convertimos a boolean por si viene como string/null
  try { return [bool]$Package.properties.isPreview } catch { return $false }
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

      $isTransient = $false
      if ($statusCode -eq 429) { $isTransient = $true }
      if ($statusCode -ge 500 -and $statusCode -le 599) { $isTransient = $true }

      if ($attempt -ge $MaxRetries -or -not $isTransient) {
        throw "Fallo en $Method $Uri. StatusCode=$statusCode. Error=$msg"
      }

      $sleep = $RetryDelaySeconds * $attempt
      Write-Warning "Fallo transitorio (StatusCode=$statusCode). Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

Write-Host "== Reinstall Content Hub Solutions ==" -ForegroundColor Cyan
Write-Host "Subscription : $SubscriptionId"
Write-Host "RG          : $ResourceGroupName"
Write-Host "Workspace   : $WorkspaceName"
Write-Host "IncludePreview: $IncludePreview"
if ($SolutionDisplayName.Count -gt 0) {
  Write-Host ("Filtro displayName: " + ($SolutionDisplayName -join ", "))
} else {
  Write-Host "Filtro displayName: (todas)"
}

$script:ArmToken = Get-ArmToken

# 1) Listar paquetes instalados
$listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
Write-Verbose "GET $listUri" -Verbose
$installed = Invoke-ArmWithRetry -Method GET -Uri $listUri

if (-not $installed.value) {
  Write-Warning "No se han encontrado contentPackages instalados en el workspace."
  return
}

# 2) Filtrar a soluciones (contentKind=Solution)
$solutions = $installed.value | Where-Object {
  # algunos objetos pueden no tener properties bien formadas => validamos
  (Test-HasProperty -Object $_ -PropertyName "properties") -and
  (Test-HasProperty -Object $_.properties -PropertyName "contentKind") -and
  $_.properties.contentKind -eq "Solution"
}

# 3) Excluir preview si no se ha solicitado (robusto si isPreview no existe)
if (-not $IncludePreview) {
  $solutions = $solutions | Where-Object { -not (Get-PreviewFlag -Package $_) }
}

# 4) Filtrar por displayName si se proporciona
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
  Write-Host " - $dn  (version: $ver, preview: $prev)"
}

foreach ($pkg in $solutions) {

  $packageId   = $pkg.name
  $displayName = $pkg.properties.displayName
  $contentId   = $pkg.properties.contentId
  $contentKind = $pkg.properties.contentKind
  $productId   = $pkg.properties.contentProductId
  $version     = $pkg.properties.version

  Write-Host ""
  Write-Host ">>> Reinstalando: $displayName" -ForegroundColor Green
  Write-Host "    packageId : $packageId"
  Write-Host "    contentId : $contentId"
  Write-Host "    version   : $version"

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$packageId?api-version=$ApiVersion"

  # Uninstall
  if ($PSCmdlet.ShouldProcess($displayName, "UNINSTALL $packageId")) {
    Invoke-ArmWithRetry -Method DELETE -Uri $pkgUri | Out-Null
    Write-Host "    Uninstall OK" -ForegroundColor DarkGreen
  }

  Start-Sleep -Seconds $DelaySecondsBetweenOperations

  # Install
  $installBody = @{
    properties = @{
      contentId        = $contentId
      contentKind      = $contentKind
      contentProductId = $productId
      displayName      = $displayName
      version          = $version
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
