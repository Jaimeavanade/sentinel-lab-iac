<#
.SYNOPSIS
Exporta el catálogo completo de Microsoft Sentinel Content Hub (Solutions) a CSV.

.DESCRIPTION
- Llama a contentProductPackages (catálogo).
- Paginación por nextLink.
- Filtra contentKind=Solution.
- Exporta a CSV: displayName, contentId, contentProductId, version, isPreview, installedVersion.

Notas:
- contentProductPackages soporta query options ($filter/$orderby/$top/$search/$skipToken) y paginación. [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
- $top debe ser entero >= 0 (OData), pero este servicio puede rechazar valores altos; usamos 50. [2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-odata/505b6322-c57f-4c37-94ef-daf8b6e2abd3)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$OutCsv = "contenthub-solutions-catalog.csv",

  [Parameter(Mandatory = $false)]
  [switch]$IncludePreview,

  # Opcional: filtra por término de búsqueda (si vacío, trae todo)
  [Parameter(Mandatory = $false)]
  [string]$Search = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de haber hecho azure/login (OIDC) antes."
  }
  return $t
}

function Invoke-ArmGet {
  param([Parameter(Mandatory=$true)][string]$Uri)

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  try {
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
  } catch {
    # Si ARM devuelve body con error, lo mostramos (ayuda a debug)
    $body = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd()
      }
    } catch {}
    if ($body) {
      throw "Fallo GET. Uri=$Uri. Body=$body"
    }
    throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
  }
}

