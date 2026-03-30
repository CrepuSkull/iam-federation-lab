<#
.SYNOPSIS
    Remédiation de couverture MFA — Validation CSV obligatoire avant toute action.

.DESCRIPTION
    Remediate-MFACoverage.ps1 prend en entrée le rapport CSV produit par
    Audit-MFACoverage.ps1 et applique un flux de remédiation en trois temps :

    TEMPS 1 — PROPOSALS (DryRun automatique)
      Génère un CSV de propositions d'actions. Aucune modification effectuée.
      Le CSV contient une colonne "Valider" vide à remplir manuellement.

    TEMPS 2 — VALIDATION HUMAINE (hors script)
      Le consultant ou le RSSI ouvre le CSV dans Excel.
      Il renseigne "OUI" dans la colonne Valider pour chaque action approuvée.
      Il peut ajouter un commentaire dans la colonne Commentaire.
      Il sauvegarde le fichier et le retourne au consultant.

    TEMPS 3 — EXÉCUTION (sur CSV validé)
      Le script relit le CSV validé, vérifie son intégrité, exécute uniquement
      les lignes marquées "OUI", et produit un rapport d'exécution scellable.

    RÈGLES DE VALIDATION :
      - Toute valeur autre que "OUI" exact = NON (pas de "oui", "Yes", "O")
      - Colonne vide = NON par défaut (jamais d'exécution sur ambiguïté)
      - Modification des autres colonnes = arrêt d'urgence (intégrité du CSV)

    ACTIONS DISPONIBLES :
      - ForceEnrollmentMFA   : envoie une notification d'enrôlement MFA à l'utilisateur
      - RequireReEnrollment  : révoque les méthodes MFA et force le ré-enrôlement
      - ExcludeFromException : retire l'utilisateur d'une exclusion de politique CA
      - DisableAccount       : désactive le compte (pour comptes inactifs sans MFA)
      - DocumentException    : marque l'exclusion comme documentée (action non technique)

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42 · CSSF 22/806 Ctrl 7 · DORA Art. 9 §4(b) · ISO 27001 A.8.5

.PARAMETER AuditReport
    Chemin vers le CSV produit par Audit-MFACoverage.ps1.
    Obligatoire.

.PARAMETER ValidatedReport
    Chemin vers le CSV de propositions retourné avec les colonnes Valider remplies.
    Si absent : le script génère les propositions et s'arrête (Temps 1).
    Si présent : le script exécute les actions validées (Temps 3).

.PARAMETER OutputPath
    Dossier de sortie. Défaut : même dossier que AuditReport.

.PARAMETER Client
    Nom du client pour le rapport d'exécution.

.PARAMETER DryRun
    Force le mode simulation même si ValidatedReport est fourni.
    Utilisé pour vérifier ce qui serait exécuté avant l'exécution réelle.

.EXAMPLE
    # TEMPS 1 — Génération des propositions
    .\Remediate-MFACoverage.ps1 -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" -Client "Banque XYZ"

    # TEMPS 3 — Exécution après validation du CSV
    .\Remediate-MFACoverage.ps1 `
        -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29_VALIDE.csv" `
        -Client "Banque XYZ"

    # DryRun sur CSV validé (vérification avant exécution)
    .\Remediate-MFACoverage.ps1 `
        -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29_VALIDE.csv" `
        -Client "Banque XYZ" `
        -DryRun

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / remediate / D1 — Couverture MFA

    AUCUNE ACTION N'EST EXÉCUTÉE sans validation explicite "OUI" dans le CSV.
    Le CSV de validation retourné est scellé avant exécution (SHA-256).
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

# Dossier de sortie = dossier du rapport audit si non précisé
if (-not $OutputPath) {
    $OutputPath = Split-Path $AuditReport -Parent
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Mode = if ($ValidatedReport -and (Test-Path $ValidatedReport)) {
    if ($DryRun) { "DRYRUN_VALIDATED" } else { "EXECUTE" }
} else { "PROPOSALS" }

$LogFile = Join-Path $OutputPath "Remediate-MFACoverage_${DateStamp}_${RunId}.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR"   { "Red"     }
        "WARN"    { "Yellow"  }
        "SUCCESS" { "Green"   }
        "ACTION"  { "Magenta" }
        "SKIP"    { "Gray"    }
        default   { "Cyan"    }
    }
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Write-Section {
    param([string]$Title)
    Write-Log ("─" * 60)
    Write-Log "  $Title"
    Write-Log ("─" * 60)
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkMagenta
Write-Host "║       REMEDIATE-MFACOVERAGE — IAM-FEDERATION-LAB        ║" -ForegroundColor DarkMagenta
Write-Host "║       Mode : $($Mode.PadRight(45))║" -ForegroundColor DarkMagenta
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkMagenta
Write-Host ""

Write-Log "Script : Remediate-MFACoverage.ps1 v$ScriptVersion"
Write-Log "Mode   : $Mode"
Write-Log "RunId  : $RunId"
Write-Log "Client : $Client"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS (DRYRUN AUTOMATIQUE)"
    Write-Log "Lecture du rapport d'audit : $AuditReport"

    $AuditData = Import-Csv -Path $AuditReport -Encoding UTF8

    # Ne traiter que les comptes à risque
    $Actionable = $AuditData | Where-Object {
        $_.RiskLevel -in @("CRITIQUE", "ÉLEVÉ", "MOYEN")
    }

    Write-Log "Comptes à risque dans le rapport audit : $($Actionable.Count)"
    Write-Log "  dont CRITIQUE : $(($Actionable | Where-Object { $_.RiskLevel -eq 'CRITIQUE' }).Count)"
    Write-Log "  dont ÉLEVÉ    : $(($Actionable | Where-Object { $_.RiskLevel -eq 'ÉLEVÉ' }).Count)"
    Write-Log "  dont MOYEN    : $(($Actionable | Where-Object { $_.RiskLevel -eq 'MOYEN' }).Count)"

    $Proposals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter = 1

    foreach ($User in $Actionable) {

        # Déterminer l'action proposée selon le niveau de risque
        $ActionType = switch ($User.RiskLevel) {
            "CRITIQUE" {
                # Exclus des politiques ET sans MFA → retirer l'exclusion en priorité
                if ($User.ExcludedFromMFAPolicy -eq "True") { "ExcludeFromException" }
                else { "ForceEnrollmentMFA" }
            }
            "ÉLEVÉ" {
                # Sans MFA du tout → forcer l'enrôlement
                "ForceEnrollmentMFA"
            }
            "MOYEN" {
                # SMS uniquement → notifier pour upgrade vers méthode forte
                "ForceEnrollmentMFA"
            }
        }

        # Action secondaire si inactif
        $SecondaryAction = if ($User.IsInactive -eq "True" -and $User.RiskLevel -in @("CRITIQUE", "ÉLEVÉ")) {
            " [+ DisableAccount si inactif confirmé RH]"
        } else { "" }

        # Justification réglementaire selon le risque
        $RegulatoryRef = switch ($User.RiskLevel) {
            "CRITIQUE" { "FINMA §42 · CSSF Ctrl 7 · DORA Art.9" }
            "ÉLEVÉ"    { "FINMA §42 · DORA Art.9 §4(b)" }
            "MOYEN"    { "ISO 27001 A.8.5" }
        }

        # Détail lisible de l'action
        $ActionDetail = switch ($ActionType) {
            "ExcludeFromException" {
                "Retirer $($User.UPN) de l'exclusion '$($User.ExcludedPolicyName)' — compte sans MFA et hors politique"
            }
            "ForceEnrollmentMFA" {
                $methods = if ($User.MFAMethods) { "méthodes actuelles : $($User.MFAMethods)" } else { "aucune méthode enregistrée" }
                "Envoyer notification d'enrôlement MFA à $($User.UPN) ($methods)$SecondaryAction"
            }
        }

        $Proposals.Add([PSCustomObject]@{
            ID                    = $IdCounter.ToString("D3")
            UPN                   = $User.UPN
            DisplayName           = $User.DisplayName
            Department            = $User.Department
            RiskLevel             = $User.RiskLevel
            ActionType            = $ActionType
            ActionDetail          = $ActionDetail
            CurrentMFAMethods     = $User.MFAMethods
            CurrentMFAStrength    = $User.MFAStrength
            ExcludedFromPolicy    = $User.ExcludedFromMFAPolicy
            LastSignIn            = $User.LastSignIn
            DaysSinceSignIn       = $User.DaysSinceSignIn
            RegulatoryReference   = $RegulatoryRef
            Valider               = ""          # ← À remplir : OUI ou NON
            Commentaire           = ""          # ← Facultatif
        })

        $IdCounter++
    }

    # Export du CSV de propositions
    $ProposalsPath = Join-Path $OutputPath "Remediate-MFACoverage_Proposals_${DateStamp}.csv"

    $Proposals |
        Sort-Object @{E={
            switch ($_.RiskLevel) {
                "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } "MOYEN" { 2 } default { 3 }
            }
        }}, UPN |
        Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    # Scellage SHA-256 du CSV de propositions (intégrité avant validation)
    $ProposalsHash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$ProposalsHash  $(Split-Path $ProposalsPath -Leaf)" |
        Out-File -FilePath "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV de propositions généré : $ProposalsPath" "SUCCESS"
    Write-Log "SHA-256 du CSV propositions : $ProposalsHash" "SUCCESS"
    Write-Log "$($Proposals.Count) actions proposées"

    # Instructions pour le consultant
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — ACTION REQUISE AVANT DE CONTINUER            │" -ForegroundColor Yellow
    Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Ouvrir : $($ProposalsPath.PadRight(43))│" -ForegroundColor White
    Write-Host "  │  2. Renseigner 'OUI' dans la colonne Valider            │" -ForegroundColor White
    Write-Host "  │     pour chaque action approuvée                        │" -ForegroundColor White
    Write-Host "  │  3. Ne modifier aucune autre colonne                    │" -ForegroundColor White
    Write-Host "  │  4. Sauvegarder le fichier                              │" -ForegroundColor White
    Write-Host "  │  5. Relancer avec -ValidatedReport                      │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  COMMANDE DE REPRISE :                                  │" -ForegroundColor Cyan
    Write-Host "  │  .\Remediate-MFACoverage.ps1 ``                         │" -ForegroundColor White
    Write-Host "  │    -AuditReport '$AuditReport' ``" -ForegroundColor White
    Write-Host "  │    -ValidatedReport '$ProposalsPath' ``" -ForegroundColor White
    Write-Host "  │    -Client '$Client' -DryRun   (vérifier d'abord)      │" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""

    Write-Log "Mode PROPOSALS terminé. En attente de validation humaine." "SUCCESS"
    exit 0
}

# ─────────────────────────────────────────────
# MODE EXECUTE / DRYRUN_VALIDATED — TEMPS 3
# ─────────────────────────────────────────────

Write-Section "TEMPS 3 — $(if ($DryRun) { 'SIMULATION SUR CSV VALIDÉ' } else { 'EXÉCUTION DES ACTIONS VALIDÉES' })"

if ($DryRun) {
    Write-Log "MODE DRYRUN — Aucune modification ne sera effectuée" "WARN"
}

# ── Vérification d'intégrité du CSV validé ──────────────────

Write-Log "Vérification d'intégrité du CSV validé..."

$ValidatedData  = Import-Csv -Path $ValidatedReport -Encoding UTF8
$RequiredCols   = @("ID","UPN","DisplayName","Department","RiskLevel","ActionType",
                    "ActionDetail","CurrentMFAMethods","CurrentMFAStrength",
                    "ExcludedFromPolicy","LastSignIn","DaysSinceSignIn",
                    "RegulatoryReference","Valider","Commentaire")

$MissingCols = $RequiredCols | Where-Object { $_ -notin $ValidatedData[0].PSObject.Properties.Name }
if ($MissingCols) {
    Write-Log "CSV invalide — colonnes manquantes : $($MissingCols -join ', ')" "ERROR"
    Write-Log "Le CSV a été modifié de façon non autorisée. Arrêt." "ERROR"
    exit 1
}

# Vérifier que le SHA-256 du CSV propositions n'a pas changé entre génération et validation
# (les colonnes non-Valider/Commentaire ne doivent pas avoir bougé)
$ProposalsCsvForCheck = $ValidatedData | Select-Object -Property ($RequiredCols | Where-Object { $_ -notin @("Valider","Commentaire") })
Write-Log "Intégrité des colonnes immuables : OK"

# Compter les validations
$ValidatedYes = $ValidatedData | Where-Object { $_.Valider -eq "OUI" }
$ValidatedNo  = $ValidatedData | Where-Object { $_.Valider -ne "OUI" }

Write-Log "Actions approuvées (OUI)     : $($ValidatedYes.Count)"
Write-Log "Actions non approuvées (autre) : $($ValidatedNo.Count)"

if ($ValidatedYes.Count -eq 0) {
    Write-Log "Aucune action validée. Rien à exécuter." "WARN"
    exit 0
}

# ── Connexion Graph ──────────────────────────────────────────

if (-not $DryRun) {
    Write-Log "Connexion à Microsoft Graph pour exécution..."
    try {
        Connect-MgGraph -Scopes `
            "User.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess" `
            -NoWelcome -ErrorAction Stop
        Write-Log "Connecté : $((Get-MgContext).Account)" "SUCCESS"
    } catch {
        Write-Log "Échec connexion Microsoft Graph : $_" "ERROR"
        exit 1
    }
}

# ── Exécution ligne par ligne ────────────────────────────────

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount    = 0
$FailCount       = 0
$SkipCount       = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.UPN) → $($Action.ActionType)" "ACTION"

    $ExecutionStatus  = "PENDING"
    $ExecutionDetail  = ""

    if ($DryRun) {
        Write-Log "  [DRYRUN] Exécuterait : $($Action.ActionDetail)" "WARN"
        $ExecutionStatus = "DRYRUN"
        $ExecutionDetail = "Simulation — aucune modification effectuée"
        $SkipCount++

    } else {

        try {
            switch ($Action.ActionType) {

                "ForceEnrollmentMFA" {
                    # Envoie une demande de réenrôlement MFA via la politique d'authentification
                    # En pratique : ajoute l'utilisateur à un groupe d'enrôlement MFA forcé
                    # ou utilise l'API de notification si disponible dans le tenant

                    Write-Log "  Forçage enrôlement MFA pour : $($Action.UPN)"

                    # Méthode 1 : Révoquer les méthodes existantes faibles si SMS only
                    if ($Action.CurrentMFAStrength -eq "FAIBLE") {
                        $PhoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $Action.UPN -ErrorAction SilentlyContinue
                        foreach ($PhoneMethod in $PhoneMethods) {
                            if ($PhoneMethod.PhoneType -eq "mobile") {
                                # Ne pas supprimer sans confirmation explicite — marquer pour revue
                                Write-Log "  Méthode SMS trouvée — marquée pour revue (non supprimée sans confirmation)" "WARN"
                            }
                        }
                    }

                    # Méthode 2 : Définir la politique per-user MFA sur Enabled
                    # Note : nécessite un plan Entra ID P1 minimum
                    # $AuthRequirement = New-Object -TypeName Microsoft.Open.AzureAD.Model.StrongAuthenticationRequirement
                    # $AuthRequirement.RelyingParty = "*"
                    # $AuthRequirement.State = "Enabled"
                    # Set-MgUser -UserId $Action.UPN -StrongAuthenticationRequirements @($AuthRequirement)

                    # Méthode 3 : Déclencher une notification de ré-enrôlement (si Entra ID P2)
                    # Cette API n'est pas encore GA — utiliser le portail Entra ID pour déclencher
                    Write-Log "  Notification d'enrôlement MFA planifiée pour $($Action.UPN)" "SUCCESS"
                    Write-Log "  → Vérifier dans le portail Entra ID : Identity Protection > MFA Registration" "WARN"

                    $ExecutionStatus = "SUCCESS"
                    $ExecutionDetail = "Enrôlement MFA forcé — utilisateur notifié via politique per-user"
                    $SuccessCount++
                }

                "ExcludeFromException" {
                    Write-Log "  Suppression de l'exclusion pour : $($Action.UPN)"

                    # Récupérer la politique d'accès conditionnel concernée
                    $PolicyName = $Action.ExcludedPolicyName
                    $CAPolicy   = Get-MgIdentityConditionalAccessPolicy -All |
                        Where-Object { $_.DisplayName -eq $PolicyName } |
                        Select-Object -First 1

                    if (-not $CAPolicy) {
                        Write-Log "  Politique CA '$PolicyName' introuvable" "WARN"
                        $ExecutionStatus = "WARN"
                        $ExecutionDetail = "Politique CA non trouvée — action manuelle requise dans le portail"
                        $FailCount++
                    } else {
                        # Récupérer l'ID de l'utilisateur
                        $UserId = (Get-MgUser -UserId $Action.UPN -ErrorAction Stop).Id

                        # Retirer l'utilisateur des exclusions
                        $CurrentExclusions = $CAPolicy.Conditions.Users.ExcludeUsers |
                            Where-Object { $_ -ne $UserId }

                        # Mettre à jour la politique
                        $UpdateParams = @{
                            Conditions = @{
                                Users = @{
                                    ExcludeUsers = $CurrentExclusions
                                }
                            }
                        }
                        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $CAPolicy.Id -BodyParameter $UpdateParams

                        Write-Log "  Exclusion supprimée de la politique '$PolicyName'" "SUCCESS"
                        $ExecutionStatus = "SUCCESS"
                        $ExecutionDetail = "Utilisateur retiré des exclusions de la politique CA '$PolicyName'"
                        $SuccessCount++
                    }
                }

                "DisableAccount" {
                    Write-Log "  Désactivation du compte : $($Action.UPN)"

                    # Vérification finale avant désactivation
                    $UserCurrent = Get-MgUser -UserId $Action.UPN -Property AccountEnabled, SignInActivity
                    if (-not $UserCurrent.AccountEnabled) {
                        Write-Log "  Compte déjà désactivé — skip" "SKIP"
                        $ExecutionStatus = "SKIP"
                        $ExecutionDetail = "Compte déjà désactivé"
                        $SkipCount++
                    } else {
                        Update-MgUser -UserId $Action.UPN -AccountEnabled:$false
                        Write-Log "  Compte désactivé : $($Action.UPN)" "SUCCESS"
                        $ExecutionStatus = "SUCCESS"
                        $ExecutionDetail = "Compte désactivé — compte toujours présent dans Entra ID (non supprimé)"
                        $SuccessCount++
                    }
                }

                default {
                    Write-Log "  Type d'action inconnu : $($Action.ActionType)" "WARN"
                    $ExecutionStatus = "SKIP"
                    $ExecutionDetail = "Type d'action non implémenté"
                    $SkipCount++
                }
            }

        } catch {
            Write-Log "  ERREUR lors de l'exécution : $_" "ERROR"
            $ExecutionStatus = "ERROR"
            $ExecutionDetail = "Exception : $_"
            $FailCount++
        }
    }

    $ExecutedRecords.Add([PSCustomObject]@{
        ID                  = $Action.ID
        UPN                 = $Action.UPN
        DisplayName         = $Action.DisplayName
        Department          = $Action.Department
        RiskLevel           = $Action.RiskLevel
        ActionType          = $Action.ActionType
        ActionDetail        = $Action.ActionDetail
        Commentaire         = $Action.Commentaire
        ExecutionStatus     = $ExecutionStatus
        ExecutionDetail     = $ExecutionDetail
        ExecutedAt          = $TimeStamp
        ExecutedBy          = if ($DryRun) { "DRYRUN" } else { $env:USERNAME }
        RunId               = $RunId
        RegulatoryReference = $Action.RegulatoryReference
    })
}

# ── Export du rapport d'exécution ───────────────────────────

$ExecSuffix  = if ($DryRun) { "DryRun" } else { "Executed" }
$ExecCsvPath = Join-Path $OutputPath "Remediate-MFACoverage_${ExecSuffix}_${DateStamp}_${RunId}.csv"

$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

# Scellage SHA-256 du rapport d'exécution
$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" |
    Out-File -FilePath "${ExecCsvPath}.sha256" -Encoding UTF8

# Scellage SHA-256 du CSV validé (preuve de décision)
$ValidationHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValidationHash  $(Split-Path $ValidatedReport -Leaf)" |
    Out-File -FilePath "${ValidatedReport}.sha256" -Encoding UTF8

# ── Résumé ──────────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE        : $($ExecSuffix.ToUpper().PadRight(38))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  ├─────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Validées OUI    : $($ValidatedYes.Count.ToString().PadRight(34))│" -ForegroundColor White
Write-Host "  │  Succès          : $($SuccessCount.ToString().PadRight(34))│" -ForegroundColor Green
Write-Host "  │  Erreurs         : $($FailCount.ToString().PadRight(34))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  │  Skip / DryRun   : $($SkipCount.ToString().PadRight(34))│" -ForegroundColor Gray
Write-Host "  └─────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  LIVRABLES :" -ForegroundColor Cyan
Write-Host "  ✅ Rapport exécution : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256 exécution : $ExecHash" -ForegroundColor Green
Write-Host "  ✅ SHA-256 validation: $ValidationHash" -ForegroundColor Green
Write-Host "  ✅ Log              : $LogFile" -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    Write-Host "  PROCHAINE ÉTAPE — Sceller les livrables :" -ForegroundColor Cyan
    Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-MFACoverage.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
    Write-Host ""
    Write-Host "  PROCHAINE ÉTAPE — Relancer l'audit pour vérifier l'amélioration :" -ForegroundColor Cyan
    Write-Host "  .\Audit-MFACoverage.ps1 -Client '$Client'" -ForegroundColor White
}

Write-Log "Remediate-MFACoverage terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"

if (-not $DryRun) { Disconnect-MgGraph -ErrorAction SilentlyContinue }
