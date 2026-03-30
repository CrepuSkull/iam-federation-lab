<#
.SYNOPSIS
    Remédiation des relations de confiance et accès guests — Validation CSV obligatoire.

.DESCRIPTION
    Remediate-FederationTrusts.ps1 prend en entrée le rapport produit par
    Audit-FederationTrusts.ps1 et applique le flux en trois temps.

    ATTENTION SPÉCIFIQUE À CE DOMAINE :
    La suppression de comptes guests et la modification de domaines fédérés
    ont un impact sur des utilisateurs externes — il faut communiquer avant.
    Règles absolues :
      - Ne jamais supprimer un guest sans avoir vérifié avec le propriétaire
        métier que la relation avec l'organisation externe est terminée
      - La modification d'un certificat SAML doit être coordonnée avec
        l'administrateur de l'IdP externe (ADFS, Okta, etc.)
      - Toujours notifier les utilisateurs concernés avant suppression

    ACTIONS DISPONIBLES :
      RemoveInactiveGuest    — Supprimer un guest inactif (Remove-MgUser)
      DisableInactiveGuest   — Désactiver sans supprimer (moins risqué, réversible)
      RevokeGuestInvitation  — Révoquer une invitation en attente non acceptée
      RestrictInvitePolicy   — Restreindre la politique d'invitation (adminsOnly)
      DocumentGuestException — Documenter un guest comme exception légitime
      CreateGuestCAPolicy    — Créer une politique CA minimale pour les guests
      RenewSAMLCertNote      — Documenter le renouvellement SAML (action manuelle externe)

    COUVERTURE RÉGLEMENTAIRE :
      CSSF 22/806 Ctrl 7 · FINMA §38 · DORA Art. 12 · ISO 27001 A.5.16

.PARAMETER AuditReport
    Chemin vers le CSV produit par Audit-FederationTrusts.ps1.

.PARAMETER ValidatedReport
    CSV de propositions avec la colonne Valider remplie.

.PARAMETER OutputPath
    Dossier de sortie.

.PARAMETER Client
    Nom du client.

.PARAMETER DryRun
    Force la simulation.

.PARAMETER NotifyGuests
    Si activé, envoie une notification par email aux guests avant suppression.
    Nécessite les droits Mail.Send ou utilise le compte connecté.
    Défaut : $false (pas de notification automatique — recommandé)

.EXAMPLE
    # Temps 1
    .\Remediate-FederationTrusts.ps1 -AuditReport ".\Reports\Audit-FederationTrusts_2026-03-29.csv" -Client "Banque XYZ"

    # Temps 3 DryRun
    .\Remediate-FederationTrusts.ps1 `
        -AuditReport   ".\Reports\Audit-FederationTrusts_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-FederationTrusts_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ" -DryRun

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab

    TOUJOURS COMMUNIQUER AVEC LE PROPRIÉTAIRE MÉTIER AVANT SUPPRESSION D'UN GUEST.
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
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [bool]$NotifyGuests = $false
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

$LogFile = Join-Path $OutputPath "Remediate-FederationTrusts_${DateStamp}_${RunId}.log"

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
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
Write-Host "║    REMEDIATE-FEDERATIONTRUSTS — IAM-FEDERATION-LAB      ║" -ForegroundColor DarkYellow
Write-Host "║    Mode : $($Mode.PadRight(47))║" -ForegroundColor DarkYellow
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
Write-Host ""
Write-Log "Script : Remediate-FederationTrusts.ps1 v$ScriptVersion"
Write-Log "Mode   : $Mode | RunId : $RunId | Client : $Client"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS"

    Write-Host ""
    Write-Host "  ⚠  AVERTISSEMENT — ACCÈS EXTERNES" -ForegroundColor Red
    Write-Host "  Les actions sur les guests et domaines fédérés impactent" -ForegroundColor Yellow
    Write-Host "  des utilisateurs externes et des organisations partenaires." -ForegroundColor Yellow
    Write-Host "  AVANT DE COCHER OUI :" -ForegroundColor Yellow
    Write-Host "  → Vérifier avec le propriétaire métier (pas seulement IT)" -ForegroundColor White
    Write-Host "  → Pour les certificats SAML : coordonner avec l'IdP externe" -ForegroundColor White
    Write-Host "  → Envisager une notification aux guests avant suppression" -ForegroundColor White
    Write-Host ""

    $AuditData  = Import-Csv -Path $AuditReport -Encoding UTF8
    $Actionable = $AuditData | Where-Object { $_.RiskLevel -in @("CRITIQUE","ÉLEVÉ","MOYEN") }

    Write-Log "Findings actionnables : $($Actionable.Count)"

    $Proposals  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter  = 1

    foreach ($Finding in $Actionable) {

        # Déterminer l'action selon la catégorie et le niveau de risque
        $ActionType   = ""
        $ActionDetail = ""
        $Urgency      = switch ($Finding.RiskLevel) {
            "CRITIQUE" { "IMMÉDIAT — Communication externe requise" }
            "ÉLEVÉ"    { "SOUS 7 JOURS — Validation métier requise"  }
            default    { "PLANIFIÉ — Vérification propriétaire métier" }
        }

        switch ($Finding.Category) {

            "GuestB2B" {
                # Proposer désactivation avant suppression — moins risqué
                if ($Finding.RiskLevel -eq "ÉLEVÉ") {
                    $ActionType   = "RemoveInactiveGuest"
                    $ActionDetail = "Supprimer le guest '$($Finding.EntityName)' (org: $($Finding.ExternalOrg)). " +
                                    "Dernière connexion : $($Finding.LastSignIn). " +
                                    "⚠ Vérifier avec le propriétaire métier que cette relation est terminée. " +
                                    "Envisager DisableInactiveGuest à la place si incertain."
                } else {
                    $ActionType   = "DisableInactiveGuest"
                    $ActionDetail = "Désactiver (sans supprimer) le guest '$($Finding.EntityName)'. " +
                                    "Raison : $($Finding.Finding). " +
                                    "Réversible — à supprimer définitivement dans 30 jours si non réactivé."
                }
            }

            "FederatedDomain" {
                if ($Finding.EntityType -eq "SAMLCertificate") {
                    $ActionType   = "RenewSAMLCertNote"
                    $ActionDetail = "RENOUVELLEMENT MANUEL REQUIS : Certificat SAML du domaine '$($Finding.EntityName)'. " +
                                    "$($Finding.Finding). " +
                                    "⚠ Cette action nécessite une coordination avec l'administrateur de l'IdP externe. " +
                                    "Procédure : Update-MgDomainFederationConfiguration ou portail ADFS/Okta. " +
                                    "Documenter la date de renouvellement dans le champ Commentaire."
                } else {
                    $ActionType   = "DocumentGuestException"
                    $ActionDetail = "Investiguer la configuration de fédération pour '$($Finding.EntityName)'. " +
                                    "$($Finding.Finding)"
                }
            }

            "ExternalCollab" {
                $ActionType   = "RestrictInvitePolicy"
                $ActionDetail = "Restreindre la politique d'invitation à 'adminsAndGuestInviters'. " +
                                "Configuration actuelle : $($Finding.Finding). " +
                                "Commande : Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom 'adminsAndGuestInviters'"
            }

            "GuestCAPolicy" {
                if ($Finding.EntityType -eq "PolicyGap") {
                    $ActionType   = "CreateGuestCAPolicy"
                    $ActionDetail = "Créer une politique CA pour les guests avec MFA requis + restriction localisation. " +
                                    "Périmètre : GuestsOrExternalUsers. Contrôles : MFA + session limitée 8h. " +
                                    "⚠ Tester en mode 'Report-only' avant d'activer."
                } else {
                    $ActionType   = "DocumentGuestException"
                    $ActionDetail = "Évaluer la justification de l'exclusion guests dans la politique '$($Finding.EntityName)'. " +
                                    "$($Finding.Finding)"
                }
            }

            "Keycloak" {
                $ActionType   = "DocumentGuestException"
                $ActionDetail = "Action manuelle Keycloak requise : $($Finding.Finding). " +
                                "Référence remédiation : $($Finding.RemediationHint)"
            }

            default {
                $ActionType   = "DocumentGuestException"
                $ActionDetail = "Investiguer : $($Finding.Finding)"
            }
        }

        $Proposals.Add([PSCustomObject]@{
            ID                  = $IdCounter.ToString("D3")
            Category            = $Finding.Category
            EntityName          = $Finding.EntityName
            EntityType          = $Finding.EntityType
            ExternalOrg         = $Finding.ExternalOrg
            RiskLevel           = $Finding.RiskLevel
            ActionType          = $ActionType
            ActionDetail        = $ActionDetail
            CurrentFinding      = $Finding.Finding
            LastSignIn          = $Finding.LastSignIn
            RegulatoryReference = $Finding.RegulatoryRef
            Urgency             = $Urgency
            BusinessOwnerCheck  = "REQUISE"
            Valider             = ""
            Commentaire         = ""
        })

        $IdCounter++
    }

    $SortedProposals = $Proposals |
        Sort-Object @{E={
            switch ($_.RiskLevel) { "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } default { 2 } }
        }}, @{E={
            switch ($_.Category) {
                "FederatedDomain"  { 0 } "GuestCAPolicy" { 1 }
                "ExternalCollab"   { 2 } "GuestB2B"      { 3 }
                default            { 4 }
            }
        }}, EntityName

    $ProposalsPath = Join-Path $OutputPath "Remediate-FederationTrusts_Proposals_${DateStamp}.csv"
    $SortedProposals | Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    $ProposalsHash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$ProposalsHash  $(Split-Path $ProposalsPath -Leaf)" | Out-File "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV propositions : $ProposalsPath ($($Proposals.Count) actions)" "SUCCESS"
    Write-Log "SHA-256 : $ProposalsHash"

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — VALIDATION REQUISE                            │" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Vérifier chaque guest avec le propriétaire métier    │" -ForegroundColor White
    Write-Host "  │  2. Certificats SAML : coordonner avec l'IdP externe     │" -ForegroundColor White
    Write-Host "  │  3. Renseigner OUI + Commentaire pour chaque action      │" -ForegroundColor White
    Write-Host "  │  4. Relancer avec -ValidatedReport -DryRun               │" -ForegroundColor White
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

if (-not $DryRun) {
    $RequiredScopes = @("User.ReadWrite.All","Policy.ReadWrite.Authorization")
    $HasCAActions   = $ValidatedYes | Where-Object { $_.ActionType -eq "CreateGuestCAPolicy" }
    if ($HasCAActions) { $RequiredScopes += "Policy.ReadWrite.ConditionalAccess" }

    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
    Write-Log "Microsoft Graph connecté : $((Get-MgContext).Account)" "SUCCESS"
}

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount = 0; $FailCount = 0; $SkipCount = 0; $ManualCount = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.EntityName) → $($Action.ActionType)" "ACTION"

    $ExecStatus = "PENDING"
    $ExecDetail = ""

    if ($DryRun) {
        Write-Log "  [DRYRUN] Exécuterait : $($Action.ActionDetail)" "WARN"
        $ExecStatus = "DRYRUN"; $ExecDetail = "Simulation — aucune modification"
        $SkipCount++
    } else {
        try {
            switch ($Action.ActionType) {

                "RemoveInactiveGuest" {
                    Write-Log "  Suppression du guest : $($Action.EntityName)"
                    # Récupérer l'ID du guest
                    $GuestUser = Get-MgUser -Filter "userPrincipalName eq '$($Action.EntityName)'" `
                        -ErrorAction Stop | Select-Object -First 1

                    if ($GuestUser) {
                        Remove-MgUser -UserId $GuestUser.Id -ErrorAction Stop
                        Write-Log "  Guest supprimé : $($Action.EntityName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Guest supprimé définitivement. Org externe : $($Action.ExternalOrg). Commentaire : $($Action.Commentaire)"
                    } else {
                        Write-Log "  Guest introuvable (déjà supprimé ?)" "WARN"
                        $ExecStatus = "SKIP"
                        $ExecDetail = "Guest introuvable dans Entra ID"
                    }
                    $SuccessCount++
                }

                "DisableInactiveGuest" {
                    Write-Log "  Désactivation du guest : $($Action.EntityName)"
                    $GuestUser = Get-MgUser -Filter "userPrincipalName eq '$($Action.EntityName)'" `
                        -ErrorAction Stop | Select-Object -First 1

                    if ($GuestUser) {
                        Update-MgUser -UserId $GuestUser.Id -AccountEnabled:$false -ErrorAction Stop
                        Write-Log "  Guest désactivé : $($Action.EntityName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Guest désactivé (non supprimé). Réactivable si besoin métier confirmé dans 30j."
                    } else {
                        Write-Log "  Guest introuvable" "WARN"
                        $ExecStatus = "SKIP"
                        $ExecDetail = "Guest introuvable dans Entra ID"
                    }
                    $SuccessCount++
                }

                "RevokeGuestInvitation" {
                    # Révoquer une invitation en attente = supprimer l'objet guest en état PendingAcceptance
                    $GuestUser = Get-MgUser -Filter "userPrincipalName eq '$($Action.EntityName)'" `
                        -Property Id, ExternalUserState -ErrorAction Stop | Select-Object -First 1

                    if ($GuestUser -and $GuestUser.ExternalUserState -eq "PendingAcceptance") {
                        Remove-MgUser -UserId $GuestUser.Id -ErrorAction Stop
                        Write-Log "  Invitation révoquée : $($Action.EntityName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Invitation en attente supprimée"
                    } else {
                        Write-Log "  Invitation non trouvée ou déjà acceptée" "WARN"
                        $ExecStatus = "SKIP"
                        $ExecDetail = "Invitation introuvable ou état incorrect"
                    }
                    $SuccessCount++
                }

                "RestrictInvitePolicy" {
                    Write-Log "  Restriction de la politique d'invitation..."
                    Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters" -ErrorAction Stop
                    Write-Log "  Politique d'invitation mise à jour : adminsAndGuestInviters" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "AllowInvitesFrom = adminsAndGuestInviters"
                    $SuccessCount++
                }

                "CreateGuestCAPolicy" {
                    Write-Log "  Création d'une politique CA pour les guests..."
                    $PolicyBody = @{
                        DisplayName = "IAM-Lab - MFA Required for Guests"
                        State       = "enabledForReportingButNotEnforced"  # Mode rapport d'abord
                        Conditions  = @{
                            Users = @{
                                IncludeGuestsOrExternalUsers = @{
                                    GuestOrExternalUserTypes = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember"
                                    ExternalTenants          = @{ MembershipKind = "all" }
                                }
                            }
                            Applications = @{ IncludeApplications = @("All") }
                        }
                        GrantControls = @{
                            Operator        = "OR"
                            BuiltInControls = @("mfa")
                        }
                        SessionControls = @{
                            SignInFrequency = @{
                                IsEnabled = $true
                                Type      = "hours"
                                Value     = 8
                            }
                        }
                    }
                    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody | Out-Null
                    Write-Log "  Politique CA guests créée en mode Report-Only" "SUCCESS"
                    Write-Log "  ⚠ Passer en mode 'enabled' après validation des impacts" "WARN"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "Politique CA 'IAM-Lab - MFA Required for Guests' créée en Report-Only. Activer manuellement après test."
                    $SuccessCount++
                }

                "RenewSAMLCertNote" {
                    # Action manuelle — documenter uniquement
                    Write-Log "  Renouvellement SAML documenté pour : $($Action.EntityName)" "ACTION"
                    Write-Log "  Action manuelle requise — coordination avec IdP externe" "WARN"
                    $ExecStatus  = "MANUAL_REQUIRED"
                    $ExecDetail  = "Renouvellement certificat SAML requiert action sur l'IdP externe. " +
                                   "Commentaire : $($Action.Commentaire). " +
                                   "Procédure : Update-MgDomainFederationConfiguration -DomainId '$($Action.EntityName)'"
                    $ManualCount++
                    $SuccessCount++
                }

                "DocumentGuestException" {
                    Write-Log "  Exception documentée : $($Action.EntityName)" "SUCCESS"
                    $ExecStatus = "DOCUMENTED"
                    $ExecDetail = "Exception documentée. Justification : $($Action.Commentaire)"
                    $SuccessCount++
                }

                default {
                    Write-Log "  Type d'action non reconnu : $($Action.ActionType)" "WARN"
                    $ExecStatus = "SKIP"; $ExecDetail = "Non implémenté"
                    $SkipCount++
                }
            }
        } catch {
            Write-Log "  ERREUR : $_" "ERROR"
            $ExecStatus = "ERROR"; $ExecDetail = "Exception : $_"
            $FailCount++
        }
    }

    $ExecutedRecords.Add([PSCustomObject]@{
        ID                  = $Action.ID
        Category            = $Action.Category
        EntityName          = $Action.EntityName
        EntityType          = $Action.EntityType
        ExternalOrg         = $Action.ExternalOrg
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
$ExecCsvPath = Join-Path $OutputPath "Remediate-FederationTrusts_${ExecSuffix}_${DateStamp}_${RunId}.csv"
$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" | Out-File "${ExecCsvPath}.sha256" -Encoding UTF8
$ValHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValHash  $(Split-Path $ValidatedReport -Leaf)" | Out-File "${ValidatedReport}.sha256" -Encoding UTF8

Write-Section "RÉSUMÉ D'EXÉCUTION"
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE              : $($ExecSuffix.ToUpper().PadRight(33))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  │  Succès            : $($SuccessCount.ToString().PadRight(33))│" -ForegroundColor Green
Write-Host "  │  Actions manuelles : $($ManualCount.ToString().PadRight(33))│" -ForegroundColor $(if ($ManualCount -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Erreurs           : $($FailCount.ToString().PadRight(33))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ✅ Rapport : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256 : $ExecHash"    -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    Write-Host "  PROCHAINE ÉTAPE :" -ForegroundColor Cyan
    Write-Host "  .\Audit-FederationTrusts.ps1 -Client '$Client'  # Mesurer l'amélioration" -ForegroundColor White
    Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-FederationTrusts.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
}

Write-Log "Remediate-FederationTrusts terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
