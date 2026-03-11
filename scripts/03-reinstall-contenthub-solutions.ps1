<#
.SYNOPSIS
Reinstala soluciones de Microsoft Sentinel Content Hub en un workspace (Uninstall + Install).

.DESCRIPTION
- Obtiene los Content Packages instalados en el workspace.
- Filtra los que son contentKind = 'Solution'.
- Opcionalmente excluye contenido Preview.
- Opcionalmente filtra por displayName (lista).
- Reinstala cada solución: DELETE (Uninstall) y PUT (Install) con los campos requeridos.

Requisitos:
- Autenticación previa en Azure (GitHub Actions + azure/login OIDC o Connect-AzAccount).
- Permisos: Microsoft Sentinel Contributor a nivel de RG (recomendado) para instalar/actualizar contenido. [5](https://docs.azure.cn/en-us/sentinel/sentinel-solutions-deploy)

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

.PARAMETER WhatIf
Simula la ejecución sin aplicar cambios.

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
  [string]$ApiVersion = "2025-09-01"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  try {
    # Requiere Az.Accounts
    $t = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    if (-not $t) { throw "Token vacío." }
    return $t
  } catch {
    throw "No se pudo obtener token ARM. Asegúrate de estar autenticado (azure/login o Connect-AzAccount). Detalle: $($_.Exception.Message)"
  }
}

function Invoke-Arm {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","DELETE")]
    [string]$Method,
    [Parameter(Mandatory=$true)]
    [string]$Uri,
    [Parameter(Mandatory=$false)]
    [object]$Body
  )

  $headers = @{
    "Authorization" = "Bearer $script:ArmToken"
    "Content-Type"  = "application/json"
  }

  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 50
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
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

# 1) Listar paquetes instalados (contentPackages) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
$listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
Write-Verbose "GET $listUri" -Verbose

$installed = Invoke-Arm -Method GET -Uri $listUri

if (-not $installed.value) {
  Write-Warning "No se han encontrado contentPackages instalados en el workspace."
  return
}

# 2) Filtrar a soluciones
$solutions = $installed.value | Where-Object {
  $_.properties.contentKind -eq "Solution"
}

if (-not $IncludePreview) {
  $solutions = $solutions | Where-Object { -not $_.properties.isPreview }
}

if ($SolutionDisplayName.Count -gt 0) {
  $wanted = $SolutionDisplayName | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $solutions = $solutions | Where-Object { $wanted -contains $_.properties.displayName }
}

if ($solutions.Count -eq 0) {
  Write-Warning "No hay soluciones que cumplan los filtros (o no hay soluciones instaladas)."
  return
}

Write-Host "Soluciones a reinstalar: $($solutions.Count)" -ForegroundColor Yellow
$solutions | ForEach-Object { Write-Host " - $($_.properties.displayName)  (version: $($_.properties.version))" }

foreach ($pkg in $solutions) {

  $packageId     = $pkg.name
  $displayName   = $pkg.properties.displayName
  $contentId     = $pkg.properties.contentId
  $contentKind   = $pkg.properties.contentKind
  $productId     = $pkg.properties.contentProductId
  $version       = $pkg.properties.version

  Write-Host ""
  Write-Host ">>> Reinstalando: $displayName" -ForegroundColor Green
  Write-Host "    packageId : $packageId"
  Write-Host "    contentId : $contentId"
  Write-Host "    version   : $version"

  # 3) Uninstall (DELETE) [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/uninstall?view=rest-securityinsights-2025-09-01)
  $uninstallUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$packageId?api-version=$ApiVersion"

  if ($PSCmdlet.ShouldProcess($displayName, "UNINSTALL $packageId")) {
    Write-Verbose "DELETE $uninstallUri" -Verbose
    try {
      Invoke-Arm -Method DELETE -Uri $uninstallUri | Out-Null
      Write-Host "    Uninstall OK" -ForegroundColor DarkGreen
    } catch {
      throw "Error en Uninstall de [$displayName]. Detalle: $($_.Exception.Message)"
    }
  }

  # 4) Install (PUT) [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)
  $installUri = $uninstallUri  # mismo recurso, método PUT
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
    Write-Verbose "PUT $installUri" -Verbose
    try {
      Invoke-Arm -Method PUT -Uri $installUri -Body $installBody | Out-Null
      Write-Host "    Install OK" -ForegroundColor DarkGreen
    } catch {
      throw "Error en Install de [$displayName]. Detalle: $($_.Exception.Message)"
    }
  }
}

Write-Host ""
Write-Host "Proceso finalizado." -ForegroundColor Cyan
