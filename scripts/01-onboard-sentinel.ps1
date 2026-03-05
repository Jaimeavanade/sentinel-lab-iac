param(
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [int]$MaxWaitSeconds = 180
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ctx = Get-AzContext
if (-not $ctx) { throw "No hay contexto Az. Asegura azure/login con enable-AzPSSession=true." }

$subId = $ctx.Subscription.Id
$api = "2025-09-01"

$onboardUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$api"

Write-Host "Onboarding Sentinel (PUT onboardingStates/default)..."
$payload = @{
  properties = @{
    customerManagedKey = $false
  }
} | ConvertTo-Json -Depth 5

# PUT = habilita Sentinel en el workspace (o lo deja igual si ya existe)
Invoke-AzRestMethod -Method PUT -Uri $onboardUri -Payload $payload | Out-Null
Write-Host "PUT OK (solicitado)."

# Confirmación: GET hasta que responda 200 o timeout
Write-Host "Verificando onboarding state (GET)..."
$deadline = (Get-Date).AddSeconds($MaxWaitSeconds)

do {
  try {
    $check = Invoke-AzRestMethod -Method GET -Uri $onboardUri
    if ($check.StatusCode -eq 200) {
      Write-Host "OK: Sentinel está habilitado (onboardingState existe)."
      Write-Host $check.Content
      exit 0
    }
  } catch {
    # seguimos reintentando hasta timeout
  }
  Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

throw "Timeout: no se pudo confirmar onboardingState tras $MaxWaitSeconds segundos."
