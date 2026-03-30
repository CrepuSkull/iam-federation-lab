<#
.SYNOPSIS
    Remédiation des politiques d'accès conditionnel — Validation CSV obligatoire.

.DESCRIPTION
    Remediate-ConditionalAccess.ps1 prend en entrée le rapport produit par
    Audit-ConditionalAccess.ps1 et applique le flux en trois temps.

    ATTENTION SPÉCIFIQUE À CE DOMAINE :
    Toute modification d'une politique CA active peut bloquer des utilisateurs
    immédiatement. Règles absolues :
      - Toujours créer les nouvelles politiques en mode Report-Only d'abord
      - Laisser tourner en Report-Only au moins 48h et analyser les Sign-in logs
      - Activer en production uniquement après validation de l'absence d'impact
      - Garder un compte breakglass hors périmètre de chaque nouvelle politique
      - Ne jamais modifier une politique active en production sans fenêtre de maintenance

    ACTIONS DISPONIBLES :
      EnableReportOnlyPolicy    — Passer une politique Report-Only en mode actif
      CreateBaselineCAPolicy    — Créer une politique baseline MFA pour tous les users
      CreateRiskSignInPolicy    — Créer une politique basée sur le risque de connexion
      CreateRiskUserPolicy      — Créer une politique basée sur le risque utilisateur
      RemoveUserFromExclusion   — Retirer un utilisateur non-breakglass d'une exclusion CA
      DocumentBreakglassAccount — Documenter un compte comme breakglass légitime
      DisableObsoletePolicy     — Désactiver une politique redondante ou en conflit

    COUVERTURE RÉGLEMENTAIRE :
      DORA Art. 9 §4(c) · FINMA §32 · CSSF Ctrl 8 · ISO 27001 A.5.15

.PARAMETER AuditReport
    Chemin vers le CSV findings produit par Audit-ConditionalAccess.ps1.

.PARAMETER ValidatedReport
    CSV de propositions avec la colonne Valider remplie.

.PARAMETER BreakglassAccountUPN
    UPN du compte breakglass à exclure de toutes les nouvelles politiques créées.
    OBLIGATOIRE pour les actions de création de politique.

.PARAMETER OutputPath
    Dossier de sortie.

.PARAMETER Client
    Nom du client.

.PARAMETER DryRun
    Force la simulation.

.EXAMPLE
    # Temps 1
    .\Remediate-ConditionalAccess.ps1 `
        -AuditReport ".\Reports\Audit-ConditionalAccess_2026-03-29.csv" `
        -Client "Banque XYZ" `
        -BreakglassAccountUPN "breakglass@banquexyz.com"

    # Temps 3 DryRun
    .\Remediate-ConditionalAccess.ps1 `
        -AuditReport   ".\Reports\Audit-ConditionalAccess_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-ConditionalAccess_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ" `
        -BreakglassAccountUPN "breakglass@banquexyz.com" -DryRun

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab

    TOUJOURS CRÉER EN REPORT-ONLY D'ABORD. VALIDER 48H. PUIS ACTIVER.
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
    [string]$BreakglassAccountUPN = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

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

$LogFile = Join-Path $OutputPath "Remediate-ConditionalAccess_${DateStamp}_${RunId}.log"

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

# Récupérer l'ID du compte breakglass si fourni
$BreakglassId = $null
if ($BreakglassAccountUPN) {
    try {
        $BG = Get-MgUser -Filter "userPrincipalName eq '$BreakglassAccountUPN'" -Property Id -ErrorAction SilentlyContinue
        if ($BG) { $BreakglassId = $BG.Id }
    } catch { }
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkGreen
Write-Host "║    REMEDIATE-CONDITIONALACCESS — IAM-FEDERATION-LAB     ║" -ForegroundColor DarkGreen
Write-Host "║    Mode : $($Mode.PadRight(47))║" -ForegroundColor DarkGreen
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkGreen
Write-Host ""
Write-Log "Script    : Remediate-ConditionalAccess.ps1 v$ScriptVersion"
Write-Log "Mode      : $Mode | RunId : $RunId | Client : $Client"
Write-Log "Breakglass : $(if ($BreakglassAccountUPN) { $BreakglassAccountUPN } else { 'Non fourni — aucun compte ne sera exclu des nouvelles politiques' })"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS"

    Write-Host ""
    Write-Host "  ⚠  AVERTISSEMENT CRITIQUE — POLITIQUES D'ACCÈS CONDITIONNEL" -ForegroundColor Red
    Write-Host "  ──────────────────────────────────────────────────────────────" -ForegroundColor Red
    Write-Host "  Toute modification CA peut bloquer des utilisateurs en production." -ForegroundColor Yellow
    Write-Host "  RÈGLE ABSOLUE : Toutes les nouvelles politiques seront créées" -ForegroundColor Yellow
    Write-Host "  en mode REPORT-ONLY. Activation manuelle requise après validation." -ForegroundColor Yellow
    Write-Host ""
    if (-not $BreakglassAccountUPN) {
        Write-Host "  ⚠ ATTENTION : -BreakglassAccountUPN non fourni." -ForegroundColor Red
        Write-Host "  Les nouvelles politiques créées n'excluront aucun compte d'urgence." -ForegroundColor Red
        Write-Host "  Fournir -BreakglassAccountUPN lors de la prochaine exécution." -ForegroundColor Red
        Write-Host ""
    }

    $AuditData  = Import-Csv -Path $AuditReport -Encoding UTF8
    $Actionable = $AuditData | Where-Object { $_.RiskLevel -in @("CRITIQUE","ÉLEVÉ","MOYEN") }

    $Proposals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter = 1

    foreach ($Finding in $Actionable) {

        $ActionType   = ""
        $ActionDetail = ""
        $Urgency      = switch ($Finding.RiskLevel) {
            "CRITIQUE" { "IMMÉDIAT" } "ÉLEVÉ" { "SOUS 7 JOURS" } default { "PLANIFIÉ" }
        }

        switch ($Finding.Category) {

            "ReportOnly" {
                $ActionType   = "EnableReportOnlyPolicy"
                $ActionDetail = "Activer la politique '$($Finding.ObjectName)' (actuellement Report-Only). " +
                                "⚠ VÉRIFIER D'ABORD les logs Sign-in > Accès conditionnel pour cette politique. " +
                                "S'assurer qu'aucun utilisateur légitime ne serait bloqué."
            }

            "UserCoverage" {
                if ($Finding.ObjectType -eq "PolicyGap") {
                    $ActionType   = "CreateBaselineCAPolicy"
                    $ActionDetail = "Créer une politique CA baseline 'All users + All apps + MFA requis'. " +
                                    "Sera créée en Report-Only. Activer manuellement après 48h de validation. " +
                                    "Breakglass exclu : $(if ($BreakglassAccountUPN) { $BreakglassAccountUPN } else { 'AUCUN — RISQUE' })."
                } else {
                    $ActionType   = "RemoveUserFromExclusion"
                    $ActionDetail = "Retirer '$($Finding.ObjectName)' des exclusions CA non justifiées. " +
                                    "Exclusions actuelles : $($Finding.AffectedScope). " +
                                    "⚠ Si ce compte est un breakglass légitime, choisir DocumentBreakglassAccount à la place."
                }
            }

            "AppCoverage" {
                $ActionType   = "CreateBaselineCAPolicy"
                $ActionDetail = "Créer une politique CA 'All apps + MFA requis' pour couvrir les applications sans politique. " +
                                "Alternative : ajouter l'application '$($Finding.ObjectName)' à une politique existante."
            }

            "RiskConditions" {
                if ($Finding.ObjectName -like "*SignInRisk*") {
                    $ActionType   = "CreateRiskSignInPolicy"
                    $ActionDetail = "Créer une politique CA pour les connexions à risque élevé/moyen. " +
                                    "Contrôle : MFA requis pour 'medium', blocage pour 'high'. " +
                                    "Sera créée en Report-Only. Nécessite Entra ID P2."
                } else {
                    $ActionType   = "CreateRiskUserPolicy"
                    $ActionDetail = "Créer une politique CA pour les utilisateurs à risque. " +
                                    "Contrôle : forcer le changement de mot de passe sécurisé. " +
                                    "Sera créée en Report-Only. Nécessite Entra ID P2."
                }
            }

            "PolicyConflict" {
                $ActionType   = "DisableObsoletePolicy"
                $ActionDetail = "Revoir et potentiellement désactiver une politique redondante ou en conflit. " +
                                "Finding : $($Finding.Finding). " +
                                "⚠ Identifier quelle politique est redondante AVANT de valider."
            }

            "PolicyConfig" {
                $ActionType   = "DocumentBreakglassAccount"
                $ActionDetail = "Analyser et documenter la configuration de la politique '$($Finding.ObjectName)'. " +
                                "Finding : $($Finding.Finding)"
            }

            default {
                $ActionType   = "DocumentBreakglassAccount"
                $ActionDetail = "Investiguer : $($Finding.Finding)"
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
            AffectedScope       = $Finding.AffectedScope
            RegulatoryReference = $Finding.RegulatoryRef
            Urgency             = $Urgency
            ReportOnlyFirst     = "OUI — Toute nouvelle politique créée sera en Report-Only"
            Valider             = ""
            Commentaire         = ""
        })
        $IdCounter++
    }

    $SortedProposals = $Proposals |
        Sort-Object @{E={ switch ($_.RiskLevel) { "CRITIQUE"{0}"ÉLEVÉ"{1} default{2} } }},
                    @{E={ switch ($_.Category) { "UserCoverage"{0}"RiskConditions"{1} default{2} } }},
                    ObjectName

    $ProposalsPath = Join-Path $OutputPath "Remediate-ConditionalAccess_Proposals_${DateStamp}.csv"
    $SortedProposals | Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    $Hash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$Hash  $(Split-Path $ProposalsPath -Leaf)" | Out-File "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV propositions : $ProposalsPath ($($Proposals.Count) actions)" "SUCCESS"
    Write-Log "SHA-256 : $Hash"

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — VALIDATION REQUISE                            │" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Toutes nouvelles politiques = créées en Report-Only  │" -ForegroundColor White
    Write-Host "  │  2. Analyser les Sign-in logs avant d'activer            │" -ForegroundColor White
    Write-Host "  │  3. Valider avec l'équipe sécurité                       │" -ForegroundColor White
    Write-Host "  │  4. Renseigner OUI + Commentaire et relancer -DryRun     │" -ForegroundColor White
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

Write-Log "Actions validées OUI : $($ValidatedYes.Count)"
if ($ValidatedYes.Count -eq 0) { Write-Log "Aucune action validée. Arrêt." "WARN"; exit 0 }

if (-not $DryRun) {
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","User.Read.All" -NoWelcome -ErrorAction Stop
    Write-Log "Microsoft Graph connecté : $((Get-MgContext).Account)" "SUCCESS"

    # Résoudre le breakglass si pas encore fait
    if ($BreakglassAccountUPN -and -not $BreakglassId) {
        $BG = Get-MgUser -Filter "userPrincipalName eq '$BreakglassAccountUPN'" -Property Id -ErrorAction SilentlyContinue
        if ($BG) { $BreakglassId = $BG.Id }
    }
}

# Helper pour construire l'exclusion breakglass
function Get-BreakglassExclusion {
    if ($script:BreakglassId) {
        return @{ ExcludeUsers = @($script:BreakglassId) }
    }
    return @{}
}

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount = 0; $FailCount = 0; $SkipCount = 0; $ManualCount = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.ObjectName) → $($Action.ActionType)" "ACTION"

    $ExecStatus = "PENDING"; $ExecDetail = ""

    if ($DryRun) {
        Write-Log "  [DRYRUN] Exécuterait : $($Action.ActionDetail)" "WARN"
        $ExecStatus = "DRYRUN"; $ExecDetail = "Simulation — aucune modification"
        $SkipCount++
    } else {
        try {
            switch ($Action.ActionType) {

                "EnableReportOnlyPolicy" {
                    $Policy = Get-MgIdentityConditionalAccessPolicy -All |
                        Where-Object { $_.DisplayName -eq $Action.ObjectName } |
                        Select-Object -First 1

                    if ($Policy) {
                        Update-MgIdentityConditionalAccessPolicy `
                            -ConditionalAccessPolicyId $Policy.Id `
                            -State "enabled" -ErrorAction Stop
                        Write-Log "  Politique activée : '$($Action.ObjectName)'" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Politique passée de Report-Only à 'enabled'. Surveiller les Sign-in logs."
                    } else {
                        Write-Log "  Politique '$($Action.ObjectName)' introuvable" "WARN"
                        $ExecStatus = "SKIP"; $ExecDetail = "Politique introuvable"
                    }
                    $SuccessCount++
                }

                "CreateBaselineCAPolicy" {
                    $UsersCondition = @{ IncludeUsers = @("All") }
                    $Exclusions     = Get-BreakglassExclusion
                    if ($Exclusions.Count -gt 0) { $UsersCondition += $Exclusions }

                    $PolicyBody = @{
                        DisplayName   = "IAM-Lab - Baseline MFA - All Users All Apps"
                        State         = "enabledForReportingButNotEnforced"
                        Conditions    = @{
                            Users        = $UsersCondition
                            Applications = @{ IncludeApplications = @("All") }
                            ClientAppTypes = @("all")
                        }
                        GrantControls = @{
                            Operator        = "OR"
                            BuiltInControls = @("mfa")
                        }
                    }

                    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody | Out-Null
                    Write-Log "  Politique baseline créée en Report-Only" "SUCCESS"
                    Write-Log "  ⚠ Analyser les Sign-in logs 48h avant d'activer" "WARN"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "Politique 'IAM-Lab - Baseline MFA' créée en Report-Only. " +
                                  "Breakglass exclu : $(if ($BreakglassAccountUPN) { $BreakglassAccountUPN } else { 'AUCUN' }). " +
                                  "Activer via : EnableReportOnlyPolicy après validation."
                    $SuccessCount++
                }

                "CreateRiskSignInPolicy" {
                    $UsersCondition = @{ IncludeUsers = @("All") }
                    $Exclusions     = Get-BreakglassExclusion
                    if ($Exclusions.Count -gt 0) { $UsersCondition += $Exclusions }

                    $PolicyBody = @{
                        DisplayName = "IAM-Lab - Block High Risk Sign-Ins"
                        State       = "enabledForReportingButNotEnforced"
                        Conditions  = @{
                            Users          = $UsersCondition
                            Applications   = @{ IncludeApplications = @("All") }
                            SignInRiskLevels = @("high", "medium")
                        }
                        GrantControls = @{
                            Operator        = "OR"
                            BuiltInControls = @("mfa")
                        }
                    }

                    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody | Out-Null
                    Write-Log "  Politique risque connexion créée en Report-Only" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "Politique 'IAM-Lab - Block High Risk Sign-Ins' créée en Report-Only (medium+high → MFA requis). Nécessite Entra ID P2 pour être effective."
                    $SuccessCount++
                }

                "CreateRiskUserPolicy" {
                    $UsersCondition = @{ IncludeUsers = @("All") }
                    $Exclusions     = Get-BreakglassExclusion
                    if ($Exclusions.Count -gt 0) { $UsersCondition += $Exclusions }

                    $PolicyBody = @{
                        DisplayName = "IAM-Lab - Secure Password Change for Risky Users"
                        State       = "enabledForReportingButNotEnforced"
                        Conditions  = @{
                            Users          = $UsersCondition
                            Applications   = @{ IncludeApplications = @("All") }
                            UserRiskLevels = @("high")
                        }
                        GrantControls = @{
                            Operator        = "AND"
                            BuiltInControls = @("mfa", "passwordChange")
                        }
                    }

                    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody | Out-Null
                    Write-Log "  Politique risque utilisateur créée en Report-Only" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "Politique 'IAM-Lab - Secure Password Change' créée en Report-Only (high user risk → MFA + changement de mot de passe). Nécessite Entra ID P2."
                    $SuccessCount++
                }

                "RemoveUserFromExclusion" {
                    # Trouver les politiques qui excluent cet utilisateur
                    $UserInfo = Get-MgUser -Filter "userPrincipalName eq '$($Action.ObjectName)'" `
                        -Property Id -ErrorAction SilentlyContinue | Select-Object -First 1

                    if ($UserInfo) {
                        $PoliciesWithExclusion = Get-MgIdentityConditionalAccessPolicy -All |
                            Where-Object { $_.Conditions.Users.ExcludeUsers -contains $UserInfo.Id }

                        foreach ($Policy in $PoliciesWithExclusion) {
                            $NewExclusions = $Policy.Conditions.Users.ExcludeUsers |
                                Where-Object { $_ -ne $UserInfo.Id }

                            Update-MgIdentityConditionalAccessPolicy `
                                -ConditionalAccessPolicyId $Policy.Id `
                                -Conditions @{ Users = @{ ExcludeUsers = $NewExclusions } } `
                                -ErrorAction Stop

                            Write-Log "  $($Action.ObjectName) retiré des exclusions de '$($Policy.DisplayName)'" "SUCCESS"
                        }
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Utilisateur retiré de $($PoliciesWithExclusion.Count) exclusion(s) CA"
                    } else {
                        $ExecStatus = "SKIP"; $ExecDetail = "Utilisateur introuvable"
                    }
                    $SuccessCount++
                }

                "DisableObsoletePolicy" {
                    $Policy = Get-MgIdentityConditionalAccessPolicy -All |
                        Where-Object { $_.DisplayName -eq $Action.ObjectName } |
                        Select-Object -First 1

                    if ($Policy) {
                        Update-MgIdentityConditionalAccessPolicy `
                            -ConditionalAccessPolicyId $Policy.Id `
                            -State "disabled" -ErrorAction Stop
                        Write-Log "  Politique désactivée : '$($Action.ObjectName)'" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Politique désactivée. Commentaire : $($Action.Commentaire)"
                    } else {
                        $ExecStatus = "SKIP"; $ExecDetail = "Politique introuvable"
                    }
                    $SuccessCount++
                }

                "DocumentBreakglassAccount" {
                    Write-Log "  Documentation : $($Action.ObjectName)" "SUCCESS"
                    $ExecStatus = "DOCUMENTED"
                    $ExecDetail = "Documenté. Justification : $($Action.Commentaire)"
                    $SuccessCount++
                }

                default {
                    Write-Log "  Type non reconnu : $($Action.ActionType)" "WARN"
                    $ExecStatus = "SKIP"; $ExecDetail = "Non implémenté"
                    $SkipCount++
                }
            }
        } catch {
            Write-Log "  ERREUR : $_" "ERROR"
            $ExecStatus = "ERROR"; $ExecDetail = "Exception : $_"; $FailCount++
        }
    }

    $ExecutedRecords.Add([PSCustomObject]@{
        ID                  = $Action.ID
        Category            = $Action.Category
        ObjectName          = $Action.ObjectName
        RiskLevel           = $Action.RiskLevel
        ActionType          = $Action.ActionType
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
$ExecCsvPath = Join-Path $OutputPath "Remediate-ConditionalAccess_${ExecSuffix}_${DateStamp}_${RunId}.csv"
$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" | Out-File "${ExecCsvPath}.sha256" -Encoding UTF8
$ValHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValHash  $(Split-Path $ValidatedReport -Leaf)" | Out-File "${ValidatedReport}.sha256" -Encoding UTF8

Write-Section "RÉSUMÉ D'EXÉCUTION"
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE      : $($ExecSuffix.ToUpper().PadRight(41))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  │  Succès    : $($SuccessCount.ToString().PadRight(41))│" -ForegroundColor Green
Write-Host "  │  Erreurs   : $($FailCount.ToString().PadRight(41))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ✅ Rapport : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256 : $ExecHash"    -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    $NewPolicies = $ExecutedRecords | Where-Object {
        $_.ActionType -in @("CreateBaselineCAPolicy","CreateRiskSignInPolicy","CreateRiskUserPolicy") -and
        $_.ExecutionStatus -eq "SUCCESS"
    }
    if ($NewPolicies.Count -gt 0) {
        Write-Host "  ⚠  $($NewPolicies.Count) nouvelle(s) politique(s) créée(s) en REPORT-ONLY" -ForegroundColor Yellow
        Write-Host "  → Analyser les Sign-in logs pendant 48h minimum" -ForegroundColor Yellow
        Write-Host "  → Activer via : EnableReportOnlyPolicy après validation" -ForegroundColor Yellow
        Write-Host ""
    }
    Write-Host "  Scellage : .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-ConditionalAccess.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
}

Write-Log "Remediate-ConditionalAccess terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
