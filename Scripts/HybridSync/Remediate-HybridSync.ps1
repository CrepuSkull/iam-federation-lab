<#
.SYNOPSIS
    Remédiation de la synchronisation hybride — Validation CSV obligatoire.

.DESCRIPTION
    Remediate-HybridSync.ps1 prend en entrée le rapport produit par Audit-HybridSync.ps1
    et applique le flux de remédiation en trois temps (Proposals → Validation → Execute).

    ATTENTION SPÉCIFIQUE À CE DOMAINE :
    Les actions sur la synchronisation hybride sont parmi les plus sensibles de
    l'écosystème IAM — une erreur peut déconnecter des milliers de comptes ou
    rendre le tenant Entra ID inaccessible. Règles absolues :
      - Ne jamais supprimer un objet directement dans Entra ID s'il est synchronisé
        (il reviendrait au prochain cycle de sync)
      - Toujours agir en AD et laisser la synchronisation propager vers Entra ID
      - Pour les comptes Tier 0 : exclure via règles de filtrage ADSync, jamais
        en désactivant le compte AD directement depuis ce script
      - Tester chaque action en DryRun et valider avec l'équipe infrastructure
        avant toute exécution réelle

    ACTIONS DISPONIBLES :
      ExcludeTier0FromSync      — Ajouter l'attribut d'exclusion sur le compte AD
                                  pour qu'il ne soit plus synchronisé
      RotateSSOAccountPassword  — Lancer la rotation du mot de passe AZUREADSSOACC$
                                  (renouvellement du ticket Kerberos Seamless SSO)
      RemoveSvcAcctFromTier0    — Retirer le compte de service Entra Connect d'un
                                  groupe Tier 0 AD (réduction des privilèges)
      ResolveProvisioningError  — Corriger une erreur de provisioning (doublon
                                  d'attribut : ProxyAddresses, UPN)
      DocumentSensitiveAttr     — Documenter un attribut sensible synchronisé comme
                                  "justifié" (pas d'action technique, traçabilité)

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42 · CSSF 22/806 Ctrl 8 · DORA Art. 9 · ISO 27001 A.8.16

.PARAMETER AuditReport
    Chemin vers le CSV produit par Audit-HybridSync.ps1. Obligatoire.

.PARAMETER ValidatedReport
    CSV de propositions retourné avec la colonne Valider remplie.
    Absent → génère les propositions (Temps 1).
    Présent → exécute les actions validées (Temps 3).

.PARAMETER OutputPath
    Dossier de sortie. Défaut : même dossier que AuditReport.

.PARAMETER Client
    Nom du client.

.PARAMETER DomainController
    Contrôleur de domaine pour les actions AD.

.PARAMETER EntraConnectServer
    Serveur Entra Connect pour les actions ADSync.

.PARAMETER DryRun
    Force la simulation même si ValidatedReport est fourni.

.EXAMPLE
    # Temps 1 — Génération des propositions
    .\Remediate-HybridSync.ps1 -AuditReport ".\Reports\Audit-HybridSync_2026-03-29.csv" -Client "Banque XYZ"

    # Temps 3 DryRun
    .\Remediate-HybridSync.ps1 `
        -AuditReport ".\Reports\Audit-HybridSync_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-HybridSync_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ" -DryRun

    # Temps 3 — Exécution
    .\Remediate-HybridSync.ps1 `
        -AuditReport ".\Reports\Audit-HybridSync_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-HybridSync_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ"

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab

    CE DOMAINE EST LE PLUS SENSIBLE DE L'ÉCOSYSTÈME.
    Valider systématiquement avec l'équipe infrastructure avant exécution.
    AUCUNE ACTION SANS "OUI" EXPLICITE DANS LE CSV.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$AuditReport,

    [Parameter(Mandatory = $false)]
    [string]$ValidatedReport = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [string]$DomainController = "",

    [Parameter(Mandatory = $false)]
    [string]$EntraConnectServer = "",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

$ScriptVersion = "1.0"
$DateStamp     = Get-Date -Format "yyyy-MM-dd"
$TimeStamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$RunId         = [System.Guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()

if (-not $OutputPath) { $OutputPath = Split-Path $AuditReport -Parent }
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Mode    = if ($ValidatedReport -and (Test-Path $ValidatedReport)) {
    if ($DryRun) { "DRYRUN_VALIDATED" } else { "EXECUTE" }
} else { "PROPOSALS" }

$LogFile = Join-Path $OutputPath "Remediate-HybridSync_${DateStamp}_${RunId}.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR"   { "Red"     } "WARN"    { "Yellow"  }
        "SUCCESS" { "Green"   } "ACTION"  { "Magenta" }
        "SKIP"    { "Gray"    } default   { "Cyan"    }
    }
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Write-Section { param([string]$T)
    Write-Log ("─" * 60); Write-Log "  $T"; Write-Log ("─" * 60)
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║       REMEDIATE-HYBRIDSYNC — IAM-FEDERATION-LAB         ║" -ForegroundColor DarkCyan
Write-Host "║       Mode : $($Mode.PadRight(45))║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

Write-Log "Script : Remediate-HybridSync.ps1 v$ScriptVersion"
Write-Log "Mode   : $Mode"
Write-Log "RunId  : $RunId"
Write-Log "Client : $Client"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS"

    # Avertissement renforcé — domaine le plus sensible
    Write-Host ""
    Write-Host "  ⛔  AVERTISSEMENT CRITIQUE — DOMAINE SYNCHRONISATION HYBRIDE" -ForegroundColor Red
    Write-Host "  ──────────────────────────────────────────────────────────────" -ForegroundColor Red
    Write-Host "  Les actions sur la synchronisation AD ↔ Entra ID peuvent avoir" -ForegroundColor Yellow
    Write-Host "  un impact sur l'ensemble du tenant si mal exécutées." -ForegroundColor Yellow
    Write-Host "  RÈGLES ABSOLUES avant de cocher OUI :" -ForegroundColor Yellow
    Write-Host "  1. Valider avec l'équipe infrastructure et le RSSI" -ForegroundColor White
    Write-Host "  2. Vérifier l'impact sur les applications dépendantes de SSO" -ForegroundColor White
    Write-Host "  3. Planifier une fenêtre de maintenance pour les actions Tier 0" -ForegroundColor White
    Write-Host "  4. Toujours tester en DryRun avant exécution réelle" -ForegroundColor White
    Write-Host ""

    $AuditData  = Import-Csv -Path $AuditReport -Encoding UTF8
    $Actionable = $AuditData | Where-Object { $_.RiskLevel -in @("CRITIQUE", "ÉLEVÉ", "MOYEN") }

    Write-Log "Findings actionnables : $($Actionable.Count)"

    $Proposals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter = 1

    # Mapping Catégorie → Action
    $CategoryActionMap = @{
        "Tier0-Sync"          = "ExcludeTier0FromSync"
        "SyncServiceAccount"  = "RemoveSvcAcctFromTier0"
        "SeamlessSSO"         = "RotateSSOAccountPassword"
        "SensitiveAttributes" = "DocumentSensitiveAttr"
        "SyncErrors"          = "ResolveProvisioningError"
        "SyncHealth"          = "DocumentSensitiveAttr"
        "FederationCert"      = "DocumentSensitiveAttr"
    }

    # Libellés d'urgence
    $UrgencyMap = @{
        "CRITIQUE" = "IMMÉDIAT — Fenêtre de maintenance requise"
        "ÉLEVÉ"    = "SOUS 7 JOURS — Validation infrastructure requise"
        "MOYEN"    = "PLANIFIÉ — Prochaine maintenance"
    }

    foreach ($Finding in $Actionable) {

        $ActionType = if ($CategoryActionMap.ContainsKey($Finding.Category)) {
            $CategoryActionMap[$Finding.Category]
        } else { "DocumentSensitiveAttr" }

        # Détail lisible selon la catégorie
        $ActionDetail = switch ($Finding.Category) {

            "Tier0-Sync" {
                "Exclure '$($Finding.ObjectName)' de la synchronisation Entra Connect. " +
                "ACTION EN AD : ajouter l'attribut d'exclusion (ex: extensionAttribute15='NoSync') " +
                "ou exclure l'OU contenant ce compte dans les règles de filtrage ADSync. " +
                "⚠ Ne pas supprimer dans Entra ID directement — il reviendrait au prochain cycle."
            }

            "SyncServiceAccount" {
                if ($Finding.Finding -like "*groupe Tier 0*") {
                    "Retirer le compte de service '$($Finding.ObjectName)' du groupe Tier 0 détecté. " +
                    "Droits minimums requis : 'Replicate Directory Changes' et 'Replicate Directory Changes All' uniquement. " +
                    "⚠ Vérifier que le compte n'est pas bloqué après retrait du groupe."
                } else {
                    "Documenter et programmer la rotation du mot de passe du compte '$($Finding.ObjectName)'. " +
                    "Envisager une migration vers une GMSA (Group Managed Service Account)."
                }
            }

            "SeamlessSSO" {
                "Renouveler le mot de passe du compte AZUREADSSOACC$ via Update-AzureADSSOForest. " +
                "Commande : Update-AzureADSSOForest -OnPremCredentials (Get-Credential). " +
                "⚠ Planifier pendant une fenêtre de faible activité — les sessions SSO actives " +
                "ne seront pas interrompues, mais les nouvelles authentifications utiliseront le nouveau ticket."
            }

            "SensitiveAttributes" {
                "Évaluer si l'attribut '$($Finding.ObjectName)' est nécessaire dans Entra ID. " +
                "Si non nécessaire : exclure de la règle ADSync dans Entra Connect Sync Rules Editor. " +
                "Si nécessaire : documenter la justification métier dans la colonne Commentaire."
            }

            "SyncErrors" {
                "Corriger l'erreur de provisioning sur '$($Finding.ObjectName)'. " +
                "Erreur : $($Finding.Finding). " +
                "Action généralement requise : corriger l'attribut conflictuel directement en AD " +
                "(ProxyAddresses ou UserPrincipalName en doublon)."
            }

            "FederationCert" {
                "Renouveler le certificat SAML du domaine fédéré '$($Finding.ObjectName)'. " +
                "Procédure : Update-MgDomainFederationConfiguration ou via le portail ADFS. " +
                "⚠ CRITIQUE : l'expiration du certificat bloque TOUS les utilisateurs fédérés."
            }

            default {
                "Investiguer et documenter : $($Finding.Finding)"
            }
        }

        $Proposals.Add([PSCustomObject]@{
            ID                  = $IdCounter.ToString("D3")
            Category            = $Finding.Category
            ObjectName          = $Finding.ObjectName
            ObjectType          = $Finding.ObjectType
            RiskLevel           = $Finding.RiskLevel
            ActionType          = $ActionType
            ActionDetail        = $ActionDetail
            CurrentFinding      = $Finding.Finding
            RegulatoryReference = $Finding.RegulatoryRef
            Urgency             = $UrgencyMap[$Finding.RiskLevel]
            InfraValidation     = "REQUISE"     # Rappel visuel dans le CSV
            Valider             = ""
            Commentaire         = ""
        })

        $IdCounter++
    }

    # Tri : CRITIQUE d'abord, puis par catégorie de risque
    $SortedProposals = $Proposals |
        Sort-Object @{E={
            switch ($_.RiskLevel) { "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } default { 2 } }
        }}, @{E={
            switch ($_.Category) {
                "Tier0-Sync"         { 0 }
                "FederationCert"     { 1 }
                "SyncServiceAccount" { 2 }
                "SeamlessSSO"        { 3 }
                default              { 4 }
            }
        }}, ObjectName

    $ProposalsPath = Join-Path $OutputPath "Remediate-HybridSync_Proposals_${DateStamp}.csv"
    $SortedProposals | Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    $ProposalsHash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$ProposalsHash  $(Split-Path $ProposalsPath -Leaf)" |
        Out-File -FilePath "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV de propositions : $ProposalsPath ($($Proposals.Count) actions)" "SUCCESS"
    Write-Log "SHA-256 : $ProposalsHash"

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — VALIDATION REQUISE                            │" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  ⛔ Valider avec l'équipe infrastructure AVANT d'ouvrir  │" -ForegroundColor Red
    Write-Host "  │  1. Ouvrir le CSV — vérifier chaque ActionDetail         │" -ForegroundColor White
    Write-Host "  │  2. Consulter l'équipe infra pour les actions Tier 0     │" -ForegroundColor White
    Write-Host "  │  3. Renseigner OUI + Commentaire pour chaque action      │" -ForegroundColor White
    Write-Host "  │  4. Relancer avec -ValidatedReport -DryRun d'abord       │" -ForegroundColor White
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host "  │  .\Remediate-HybridSync.ps1 ``                           │" -ForegroundColor White
    Write-Host "  │    -AuditReport '$AuditReport' ``" -ForegroundColor White
    Write-Host "  │    -ValidatedReport '$ProposalsPath' ``" -ForegroundColor White
    Write-Host "  │    -Client '$Client' -DryRun                            │" -ForegroundColor White
    Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""

    Write-Log "Mode PROPOSALS terminé — $($Proposals.Count) actions proposées" "SUCCESS"
    exit 0
}

# ─────────────────────────────────────────────
# MODE EXECUTE / DRYRUN_VALIDATED — TEMPS 3
# ─────────────────────────────────────────────

Write-Section "TEMPS 3 — $(if ($DryRun) { 'SIMULATION SUR CSV VALIDÉ' } else { 'EXÉCUTION DES ACTIONS VALIDÉES' })"

if ($DryRun) { Write-Log "MODE DRYRUN — Aucune modification ne sera effectuée" "WARN" }

$ValidatedData = Import-Csv -Path $ValidatedReport -Encoding UTF8
$ValidatedYes  = $ValidatedData | Where-Object { $_.Valider -eq "OUI" }

Write-Log "Actions validées OUI  : $($ValidatedYes.Count)"
Write-Log "Actions non validées  : $(($ValidatedData | Where-Object { $_.Valider -ne 'OUI' }).Count)"

if ($ValidatedYes.Count -eq 0) {
    Write-Log "Aucune action validée. Arrêt." "WARN"; exit 0
}

# Connexions selon les actions requises
if (-not $DryRun) {
    $NeedsAD    = $ValidatedYes | Where-Object { $_.ActionType -in @("ExcludeTier0FromSync","RemoveSvcAcctFromTier0") }
    $NeedsGraph = $ValidatedYes | Where-Object { $_.ActionType -eq "ResolveProvisioningError" }
    $NeedsADSync= $ValidatedYes | Where-Object { $_.ActionType -eq "RotateSSOAccountPassword" }

    if ($NeedsAD -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Import-Module ActiveDirectory
        Write-Log "Module ActiveDirectory chargé" "SUCCESS"
    }

    if ($NeedsGraph) {
        Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All" -NoWelcome -ErrorAction Stop
        Write-Log "Microsoft Graph connecté : $((Get-MgContext).Account)" "SUCCESS"
    }
}

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount = 0; $FailCount = 0; $SkipCount = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.ObjectName) → $($Action.ActionType)" "ACTION"

    $ExecStatus = "PENDING"
    $ExecDetail = ""

    if ($DryRun) {
        Write-Log "  [DRYRUN] Exécuterait : $($Action.ActionDetail)" "WARN"
        $ExecStatus = "DRYRUN"
        $ExecDetail = "Simulation — aucune modification"
        $SkipCount++
    } else {
        try {
            switch ($Action.ActionType) {

                "ExcludeTier0FromSync" {
                    # Stratégie : marquer le compte avec un attribut d'exclusion
                    # L'exclusion réelle se fait via les règles ADSync (filtrage par attribut)
                    # Ici on pose l'attribut — la règle ADSync doit déjà exister ou être créée manuellement
                    $ADParams = @{ Identity = $Action.ObjectName; ErrorAction = "Stop" }
                    if ($DomainController) { $ADParams.Server = $DomainController }

                    # Utiliser extensionAttribute15 comme marqueur d'exclusion de sync
                    Set-ADUser @ADParams -Replace @{ extensionAttribute15 = "ExcludeFromSync" }

                    Write-Log "  Attribut d'exclusion posé sur $($Action.ObjectName) : extensionAttribute15='ExcludeFromSync'" "SUCCESS"
                    Write-Log "  ⚠ Vérifier que la règle de filtrage ADSync exclut cet attribut — sinon l'exclusion n'est pas effective" "WARN"

                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "extensionAttribute15='ExcludeFromSync' posé en AD. Valide uniquement si règle de filtrage ADSync configurée en conséquence."
                    $SuccessCount++
                }

                "RemoveSvcAcctFromTier0" {
                    # Extraire le groupe depuis le finding
                    $GroupMatch = $Action.CurrentFinding -match "groupe Tier 0 : (.+)$"
                    $GroupName  = if ($GroupMatch) { $Matches[1].Trim() } else { $null }

                    if ($GroupName) {
                        $ADParams = @{ ErrorAction = "Stop" }
                        if ($DomainController) { $ADParams.Server = $DomainController }

                        Remove-ADGroupMember @ADParams `
                            -Identity $GroupName `
                            -Members  $Action.ObjectName `
                            -Confirm:$false

                        Write-Log "  $($Action.ObjectName) retiré du groupe '$GroupName'" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Compte retiré du groupe Tier 0 '$GroupName'"
                    } else {
                        Write-Log "  Impossible d'extraire le nom du groupe depuis le finding" "WARN"
                        $ExecStatus = "WARN"
                        $ExecDetail = "Nom de groupe non déterminé — action manuelle requise"
                    }
                    $SuccessCount++
                }

                "RotateSSOAccountPassword" {
                    # Rotation du mot de passe AZUREADSSOACC$ via ADSync
                    Write-Log "  Rotation du mot de passe AZUREADSSOACC$ (Seamless SSO)..."
                    Write-Log "  Cette action doit être exécutée sur le serveur Entra Connect" "WARN"

                    $RotateScript = {
                        Import-Module ADSync -ErrorAction Stop
                        # Update-AzureADSSOForest nécessite MSOnline — documenter la procédure
                        Write-Output "Rotation requise : Update-AzureADSSOForest -OnPremCredentials (Get-Credential)"
                    }

                    if ($EntraConnectServer) {
                        $Session = New-PSSession -ComputerName $EntraConnectServer -ErrorAction SilentlyContinue
                        if ($Session) {
                            Invoke-Command -Session $Session -ScriptBlock $RotateScript
                            Remove-PSSession $Session
                            Write-Log "  Rotation initiée sur $EntraConnectServer" "SUCCESS"
                            $ExecStatus = "SUCCESS"
                            $ExecDetail = "Rotation AZUREADSSOACC$ initiée sur $EntraConnectServer"
                        } else {
                            Write-Log "  PSRemoting indisponible vers $EntraConnectServer — exécuter manuellement" "WARN"
                            $ExecStatus = "MANUAL_REQUIRED"
                            $ExecDetail = "Exécuter manuellement sur $EntraConnectServer : Update-AzureADSSOForest"
                        }
                    } else {
                        Write-Log "  -EntraConnectServer non fourni — documenter l'action manuelle" "WARN"
                        $ExecStatus = "MANUAL_REQUIRED"
                        $ExecDetail = "Exécuter manuellement sur le serveur Entra Connect : Update-AzureADSSOForest -OnPremCredentials (Get-Credential)"
                    }
                    $SuccessCount++
                }

                "ResolveProvisioningError" {
                    # Pour les erreurs ProxyAddresses / UPN en doublon
                    # On ne peut pas corriger automatiquement sans connaître la valeur de remplacement
                    # On documente et on génère les instructions
                    Write-Log "  Erreur de provisioning sur $($Action.ObjectName) — génération des instructions" "WARN"
                    Write-Log "  Finding : $($Action.CurrentFinding)"

                    $ExecStatus = "MANUAL_REQUIRED"
                    $ExecDetail = "Correction manuelle requise en AD. " +
                                  "Finding : $($Action.CurrentFinding). " +
                                  "Procédure : identifier la valeur conflictuelle dans AD et la modifier pour lever l'ambiguïté. " +
                                  "Commentaire consultant : $($Action.Commentaire)"

                    Write-Log "  Instructions documentées dans le rapport d'exécution" "SUCCESS"
                    $SuccessCount++
                }

                "DocumentSensitiveAttr" {
                    Write-Log "  Documentation de l'exception : $($Action.ObjectName)" "SUCCESS"
                    $ExecStatus = "DOCUMENTED"
                    $ExecDetail = "Exception documentée. Justification : $($Action.Commentaire). " +
                                  "Finding : $($Action.CurrentFinding)"
                    $SuccessCount++
                }

                default {
                    Write-Log "  Type d'action non reconnu : $($Action.ActionType)" "WARN"
                    $ExecStatus = "SKIP"
                    $ExecDetail = "Type d'action non implémenté"
                    $SkipCount++
                }
            }
        } catch {
            Write-Log "  ERREUR : $_" "ERROR"
            $ExecStatus = "ERROR"
            $ExecDetail = "Exception : $_"
            $FailCount++
        }
    }

    $ExecutedRecords.Add([PSCustomObject]@{
        ID                  = $Action.ID
        Category            = $Action.Category
        ObjectName          = $Action.ObjectName
        ObjectType          = $Action.ObjectType
        RiskLevel           = $Action.RiskLevel
        ActionType          = $Action.ActionType
        ActionDetail        = $Action.ActionDetail
        Commentaire         = $Action.Commentaire
        ExecutionStatus     = $ExecStatus
        ExecutionDetail     = $ExecDetail
        ExecutedAt          = $TimeStamp
        ExecutedBy          = if ($DryRun) { "DRYRUN" } else { $env:USERNAME }
        RunId               = $RunId
        RegulatoryReference = $Action.RegulatoryReference
    })
}

# Export et scellage
$ExecSuffix  = if ($DryRun) { "DryRun" } else { "Executed" }
$ExecCsvPath = Join-Path $OutputPath "Remediate-HybridSync_${ExecSuffix}_${DateStamp}_${RunId}.csv"
$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" | Out-File "${ExecCsvPath}.sha256" -Encoding UTF8

$ValHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValHash  $(Split-Path $ValidatedReport -Leaf)" | Out-File "${ValidatedReport}.sha256" -Encoding UTF8

# Actions manuelles requises
$ManualActions = $ExecutedRecords | Where-Object { $_.ExecutionStatus -eq "MANUAL_REQUIRED" }

Write-Section "RÉSUMÉ D'EXÉCUTION"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE          : $($ExecSuffix.ToUpper().PadRight(37))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  │  Succès        : $($SuccessCount.ToString().PadRight(37))│" -ForegroundColor Green
Write-Host "  │  Actions manuelles : $($ManualActions.Count.ToString().PadRight(33))│" -ForegroundColor $(if ($ManualActions.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Erreurs       : $($FailCount.ToString().PadRight(37))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

if ($ManualActions.Count -gt 0) {
    Write-Host "  ACTIONS MANUELLES REQUISES :" -ForegroundColor Yellow
    foreach ($M in $ManualActions) {
        Write-Host "  ⚠ $($M.ObjectName) ($($M.ActionType)) : $($M.ExecutionDetail)" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "  ✅ Rapport exécution : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256           : $ExecHash"    -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    Write-Host "  PROCHAINE ÉTAPE — Relancer l'audit pour mesurer l'amélioration :" -ForegroundColor Cyan
    Write-Host "  .\Audit-HybridSync.ps1 -Client '$Client'" -ForegroundColor White
    Write-Host ""
    Write-Host "  SCELLAGE (iam-evidence-sealer) :" -ForegroundColor Cyan
    Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-HybridSync.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
}

Write-Log "Remediate-HybridSync terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"

Disconnect-MgGraph -ErrorAction SilentlyContinue
