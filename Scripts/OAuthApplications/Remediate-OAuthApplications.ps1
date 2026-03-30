<#
.SYNOPSIS
    Remédiation des applications OAuth/OIDC — Validation CSV obligatoire.

.DESCRIPTION
    Remediate-OAuthApplications.ps1 prend en entrée le rapport produit par
    Audit-OAuthApplications.ps1 et applique le flux en trois temps.

    ATTENTION SPÉCIFIQUE À CE DOMAINE :
    La révocation de permissions ou la suppression d'applications peut casser
    des intégrations en production. Règles absolues :
      - Identifier le propriétaire de l'application AVANT toute action
      - Pour les applications avec permissions Application *.All :
        contacter l'équipe responsable et documenter la justification
      - Tester le renouvellement des secrets en environnement de dev/preprod
        avant de changer en production
      - La révocation de consentements OAuth déconnecte immédiatement
        les utilisateurs concernés

    ACTIONS DISPONIBLES :
      RevokeUserConsent         — Révoquer les consentements OAuth d'une application
      RenewAppSecret            — Créer un nouveau secret d'application
      RemoveExpiredCredential   — Supprimer un secret ou certificat expiré
      DisableImplicitFlow       — Désactiver le flux implicite OAuth2
      DisableApp                — Désactiver une application orpheline
      RemoveApp                 — Supprimer une application orpheline confirmée
      DocumentPermException     — Documenter une permission *.All comme justifiée
      RemoveWildcardRedirectUri — Corriger les URI de redirection wildcard

    COUVERTURE RÉGLEMENTAIRE :
      ISO 27001 A.5.15 · CSSF Ctrl 7 · DORA Art. 9 · FINMA §38

.PARAMETER AuditReport
    Chemin vers le CSV produit par Audit-OAuthApplications.ps1.

.PARAMETER ValidatedReport
    CSV de propositions avec la colonne Valider remplie.

.PARAMETER OutputPath
    Dossier de sortie.

.PARAMETER Client
    Nom du client.

.PARAMETER DryRun
    Force la simulation.

.EXAMPLE
    # Temps 1
    .\Remediate-OAuthApplications.ps1 `
        -AuditReport ".\Reports\Audit-OAuthApplications_2026-03-29.csv" -Client "Banque XYZ"

    # Temps 3 DryRun
    .\Remediate-OAuthApplications.ps1 `
        -AuditReport   ".\Reports\Audit-OAuthApplications_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-OAuthApplications_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ" -DryRun

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab

    IDENTIFIER LE PROPRIÉTAIRE DE L'APPLICATION AVANT TOUTE ACTION.
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

$LogFile = Join-Path $OutputPath "Remediate-OAuthApplications_${DateStamp}_${RunId}.log"

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
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkBlue
Write-Host "║    REMEDIATE-OAUTHAPPLICATIONS — IAM-FEDERATION-LAB     ║" -ForegroundColor DarkBlue
Write-Host "║    Mode : $($Mode.PadRight(47))║" -ForegroundColor DarkBlue
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkBlue
Write-Host ""
Write-Log "Script : Remediate-OAuthApplications.ps1 v$ScriptVersion"
Write-Log "Mode   : $Mode | RunId : $RunId | Client : $Client"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS"

    Write-Host ""
    Write-Host "  ⚠  AVERTISSEMENT — APPLICATIONS ET PERMISSIONS" -ForegroundColor Red
    Write-Host "  Révoquer des permissions ou supprimer des applications" -ForegroundColor Yellow
    Write-Host "  peut casser des intégrations en production." -ForegroundColor Yellow
    Write-Host "  AVANT DE COCHER OUI :" -ForegroundColor Yellow
    Write-Host "  → Identifier le propriétaire via Get-MgApplicationOwner" -ForegroundColor White
    Write-Host "  → Tester en environnement non-prod si possible" -ForegroundColor White
    Write-Host "  → Pour les secrets : tester avant de supprimer l'ancien" -ForegroundColor White
    Write-Host ""

    $AuditData  = Import-Csv -Path $AuditReport -Encoding UTF8
    $Actionable = $AuditData | Where-Object { $_.RiskLevel -in @("CRITIQUE","ÉLEVÉ","MOYEN") }

    Write-Log "Findings actionnables : $($Actionable.Count)"

    $Proposals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter = 1

    foreach ($Finding in $Actionable) {

        $ActionType   = ""
        $ActionDetail = ""
        $Urgency      = switch ($Finding.RiskLevel) {
            "CRITIQUE" { "IMMÉDIAT — Validation propriétaire requise" }
            "ÉLEVÉ"    { "SOUS 7 JOURS — Test en preprod requis" }
            default    { "PLANIFIÉ — Identifier propriétaire d'abord" }
        }

        switch ($Finding.Category) {

            "HighRiskPermissions" {
                if ($Finding.AppType -like "*Application*" -or $Finding.AppType -like "*daemon*") {
                    $ActionType   = "DocumentPermException"
                    $ActionDetail = "Documenter la justification des permissions Application *.All pour '$($Finding.AppName)'. " +
                                    "Permissions détectées : $($Finding.Detail). " +
                                    "⚠ Si aucune justification ne peut être fournie : contacter le propriétaire et réduire les permissions. " +
                                    "Commande pour lister les propriétaires : Get-MgApplicationOwner -ApplicationId '<ID>'"
                } else {
                    $ActionType   = "DocumentPermException"
                    $ActionDetail = "Vérifier si les permissions déléguées de '$($Finding.AppName)' sont toujours utilisées. " +
                                    "Permissions : $($Finding.Detail). " +
                                    "Si l'app est inactive : envisager RemoveApp ou réduction des permissions."
                }
            }

            "ExpiredSecret" {
                $ActionType   = "RemoveExpiredCredential"
                $ActionDetail = "Supprimer le secret/certificat expiré de '$($Finding.AppName)'. " +
                                "Détail : $($Finding.Detail). " +
                                "⚠ S'assurer que l'application utilise déjà un secret valide avant de supprimer."
            }

            "ExpiringSecret" {
                $ActionType   = "RenewAppSecret"
                $ActionDetail = "Renouveler le secret/certificat de '$($Finding.AppName)' avant expiration. " +
                                "Expiration : $($Finding.ExpiryDate). " +
                                "Procédure : 1) Créer nouveau secret, 2) Mettre à jour l'app cliente, 3) Valider, 4) Supprimer l'ancien. " +
                                "⚠ Ne jamais supprimer l'ancien avant validation du nouveau."
            }

            "UserConsent" {
                $ActionType   = "RevokeUserConsent"
                $ActionDetail = "Révoquer les consentements OAuth utilisateurs pour '$($Finding.AppName)'. " +
                                "Scopes consentis : $($Finding.Detail). " +
                                "⚠ Les utilisateurs seront déconnectés de l'application immédiatement. " +
                                "Vérifier que l'application est légitime avant de révoquer — si légitime, re-consentir en admin."
            }

            "OrphanApp" {
                $ActionType   = "DisableApp"
                $ActionDetail = "Désactiver (sans supprimer) l'application '$($Finding.AppName)'. " +
                                "Raison : $($Finding.Finding). " +
                                "Identifier le propriétaire : Get-MgApplicationOwner -ApplicationId '<ID>'. " +
                                "Si aucun propriétaire identifié après 30j : passer à RemoveApp."
            }

            "RiskyAuthFlow" {
                if ($Finding.Detail -like "*ImplicitGrant*") {
                    $ActionType   = "DisableImplicitFlow"
                    $ActionDetail = "Désactiver le flux implicite OAuth2 pour '$($Finding.AppName)'. " +
                                    "⚠ Coordonner avec l'équipe dev — l'application devra migrer vers Authorization Code + PKCE."
                } else {
                    $ActionType   = "RemoveWildcardRedirectUri"
                    $ActionDetail = "Corriger les URI de redirection wildcard/HTTP de '$($Finding.AppName)'. " +
                                    "URIs problématiques : $($Finding.Detail). " +
                                    "⚠ Coordonner avec l'équipe dev pour les URI de remplacement exactes."
                }
            }

            default {
                $ActionType   = "DocumentPermException"
                $ActionDetail = "Investiguer : $($Finding.Finding)"
            }
        }

        $Proposals.Add([PSCustomObject]@{
            ID                  = $IdCounter.ToString("D3")
            Category            = $Finding.Category
            AppName             = $Finding.AppName
            AppId               = $Finding.AppId
            AppType             = $Finding.AppType
            RiskLevel           = $Finding.RiskLevel
            ActionType          = $ActionType
            ActionDetail        = $ActionDetail
            CurrentFinding      = $Finding.Finding
            Detail              = $Finding.Detail
            ExpiryDate          = $Finding.ExpiryDate
            RegulatoryReference = $Finding.RegulatoryRef
            Urgency             = $Urgency
            OwnerCheck          = "REQUISE — Get-MgApplicationOwner -ApplicationId '<ID_APP>'"
            Valider             = ""
            Commentaire         = ""
        })
        $IdCounter++
    }

    $SortedProposals = $Proposals |
        Sort-Object @{E={ switch ($_.RiskLevel) { "CRITIQUE"{0}"ÉLEVÉ"{1} default{2} } }},
                    @{E={ switch ($_.Category) {
                        "ExpiredSecret"{0}"ExpiringSecret"{1}"HighRiskPermissions"{2}
                        "UserConsent"{3}"RiskyAuthFlow"{4} default{5}
                    } }}, AppName

    $ProposalsPath = Join-Path $OutputPath "Remediate-OAuthApplications_Proposals_${DateStamp}.csv"
    $SortedProposals | Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    $Hash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$Hash  $(Split-Path $ProposalsPath -Leaf)" | Out-File "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV propositions : $ProposalsPath ($($Proposals.Count) actions)" "SUCCESS"
    Write-Log "SHA-256 : $Hash"

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — VALIDATION REQUISE                            │" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Identifier les propriétaires (colonne OwnerCheck)    │" -ForegroundColor White
    Write-Host "  │  2. Pour les secrets : tester le nouveau avant supprimer │" -ForegroundColor White
    Write-Host "  │  3. Pour les consentements : confirmer si app légitime   │" -ForegroundColor White
    Write-Host "  │  4. Renseigner OUI + Commentaire puis relancer -DryRun   │" -ForegroundColor White
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
    $Scopes = @("Application.ReadWrite.All", "Directory.ReadWrite.All")
    $NeedsConsent = $ValidatedYes | Where-Object { $_.ActionType -eq "RevokeUserConsent" }
    if ($NeedsConsent) { $Scopes += "DelegatedPermissionGrant.ReadWrite.All" }

    Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
    Write-Log "Microsoft Graph connecté : $((Get-MgContext).Account)" "SUCCESS"
}

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount = 0; $FailCount = 0; $SkipCount = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.AppName) → $($Action.ActionType)" "ACTION"

    $ExecStatus = "PENDING"; $ExecDetail = ""

    if ($DryRun) {
        Write-Log "  [DRYRUN] Exécuterait : $($Action.ActionDetail)" "WARN"
        $ExecStatus = "DRYRUN"; $ExecDetail = "Simulation — aucune modification"
        $SkipCount++
    } else {
        try {
            # Résoudre l'application par AppId
            $App = Get-MgApplication -Filter "appId eq '$($Action.AppId)'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
            $SP  = Get-MgServicePrincipal -Filter "appId eq '$($Action.AppId)'" -ErrorAction SilentlyContinue |
                Select-Object -First 1

            switch ($Action.ActionType) {

                "RevokeUserConsent" {
                    if (-not $SP) {
                        Write-Log "  Service Principal introuvable pour $($Action.AppId)" "WARN"
                        $ExecStatus = "SKIP"; $ExecDetail = "SP introuvable"
                        $SkipCount++
                    } else {
                        $Grants = Get-MgOauth2PermissionGrant `
                            -Filter "clientId eq '$($SP.Id)' and consentType eq 'Principal'" `
                            -ErrorAction Stop

                        $Revoked = 0
                        foreach ($Grant in $Grants) {
                            Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $Grant.Id -ErrorAction Stop
                            $Revoked++
                        }

                        Write-Log "  $Revoked consentement(s) révoqué(s) pour $($Action.AppName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "$Revoked consentement(s) OAuth utilisateur révoqué(s). Les utilisateurs concernés seront déconnectés."
                        $SuccessCount++
                    }
                }

                "RemoveExpiredCredential" {
                    if (-not $App) {
                        Write-Log "  Application introuvable pour $($Action.AppId)" "WARN"
                        $ExecStatus = "SKIP"; $ExecDetail = "Application introuvable"
                        $SkipCount++
                    } else {
                        # Supprimer les secrets expirés
                        $Now     = Get-Date
                        $Removed = 0

                        foreach ($Cred in $App.PasswordCredentials | Where-Object { $_.EndDateTime -lt $Now }) {
                            Remove-MgApplicationPassword -ApplicationId $App.Id -KeyId $Cred.KeyId -ErrorAction Stop
                            Write-Log "  Secret expiré supprimé : $($Cred.DisplayName ?? $Cred.KeyId)" "SUCCESS"
                            $Removed++
                        }

                        foreach ($Cert in $App.KeyCredentials | Where-Object { $_.EndDateTime -lt $Now }) {
                            Remove-MgApplicationKey -ApplicationId $App.Id `
                                -KeyId $Cert.KeyId -Proof "" -ErrorAction SilentlyContinue
                            Write-Log "  Certificat expiré supprimé : $($Cert.DisplayName ?? $Cert.KeyId)" "SUCCESS"
                            $Removed++
                        }

                        $ExecStatus = if ($Removed -gt 0) { "SUCCESS" } else { "SKIP" }
                        $ExecDetail = "$Removed credential(s) expiré(s) supprimé(s)"
                        $SuccessCount++
                    }
                }

                "RenewAppSecret" {
                    if (-not $App) {
                        $ExecStatus = "SKIP"; $ExecDetail = "Application introuvable"
                        $SkipCount++
                    } else {
                        # Créer un nouveau secret avec durée de validité 1 an
                        $NewSecretName = "IAM-Lab-Renewed-$(Get-Date -Format 'yyyyMMdd')"
                        $NewCred = New-MgApplicationPassword -ApplicationId $App.Id `
                            -PasswordCredential @{
                                DisplayName = $NewSecretName
                                EndDateTime = (Get-Date).AddYears(1)
                            } -ErrorAction Stop

                        Write-Log "  Nouveau secret créé : $NewSecretName" "SUCCESS"
                        Write-Log "  ⚠ NOTER LA VALEUR DU SECRET — elle ne sera plus visible après cette session" "WARN"
                        Write-Log "  Valeur : [MASQUÉE — récupérer dans le portail Azure ou via la console]" "WARN"

                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Nouveau secret '$NewSecretName' créé, expire le $(((Get-Date).AddYears(1)).ToString('yyyy-MM-dd')). " +
                                      "⚠ Mettre à jour l'application cliente avec la nouvelle valeur, PUIS supprimer l'ancien via RemoveExpiredCredential."
                        $SuccessCount++
                    }
                }

                "DisableApp" {
                    if (-not $SP) {
                        $ExecStatus = "SKIP"; $ExecDetail = "Service Principal introuvable"
                        $SkipCount++
                    } else {
                        Update-MgServicePrincipal -ServicePrincipalId $SP.Id `
                            -AccountEnabled:$false -ErrorAction Stop
                        Write-Log "  Application désactivée : $($Action.AppName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Service Principal désactivé. L'application ne peut plus s'authentifier. Réactivable si besoin confirmé."
                        $SuccessCount++
                    }
                }

                "RemoveApp" {
                    if (-not $App) {
                        $ExecStatus = "SKIP"; $ExecDetail = "Application introuvable (peut-être déjà supprimée)"
                        $SkipCount++
                    } else {
                        Remove-MgApplication -ApplicationId $App.Id -ErrorAction Stop
                        Write-Log "  Application supprimée : $($Action.AppName)" "SUCCESS"
                        Write-Log "  ⚠ Récupérable pendant 30j via les objets supprimés" "WARN"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Application supprimée définitivement (récupérable 30j). Commentaire : $($Action.Commentaire)"
                        $SuccessCount++
                    }
                }

                "DisableImplicitFlow" {
                    if (-not $App) {
                        $ExecStatus = "SKIP"; $ExecDetail = "Application introuvable"
                        $SkipCount++
                    } else {
                        Update-MgApplication -ApplicationId $App.Id `
                            -Web @{
                                ImplicitGrantSettings = @{
                                    EnableAccessTokenIssuance = $false
                                    EnableIdTokenIssuance     = $false
                                }
                            } -ErrorAction Stop
                        Write-Log "  Flux implicite désactivé : $($Action.AppName)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "ImplicitGrantSettings désactivé (AccessToken + IdToken). L'application doit migrer vers Authorization Code + PKCE."
                        $SuccessCount++
                    }
                }

                "RemoveWildcardRedirectUri" {
                    Write-Log "  Correction URI de redirection — action manuelle requise" "WARN"
                    Write-Log "  Les URI de remplacement exactes doivent être fournies par l'équipe dev" "WARN"
                    $ExecStatus = "MANUAL_REQUIRED"
                    $ExecDetail = "Les URI wildcard/HTTP ne peuvent pas être corrigées automatiquement sans les URI de remplacement exactes. " +
                                  "Contacter l'équipe dev de '$($Action.AppName)' pour obtenir les URI production correctes."
                    $SuccessCount++
                }

                "DocumentPermException" {
                    Write-Log "  Exception documentée : $($Action.AppName)" "SUCCESS"
                    $ExecStatus = "DOCUMENTED"
                    $ExecDetail = "Exception documentée. Justification : $($Action.Commentaire)"
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
        AppName             = $Action.AppName
        AppId               = $Action.AppId
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
$ExecCsvPath = Join-Path $OutputPath "Remediate-OAuthApplications_${ExecSuffix}_${DateStamp}_${RunId}.csv"
$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" | Out-File "${ExecCsvPath}.sha256" -Encoding UTF8
$ValHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValHash  $(Split-Path $ValidatedReport -Leaf)" | Out-File "${ValidatedReport}.sha256" -Encoding UTF8

$ManualActions = $ExecutedRecords | Where-Object { $_.ExecutionStatus -eq "MANUAL_REQUIRED" }

Write-Section "RÉSUMÉ D'EXÉCUTION"
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE              : $($ExecSuffix.ToUpper().PadRight(33))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  │  Succès            : $($SuccessCount.ToString().PadRight(33))│" -ForegroundColor Green
Write-Host "  │  Actions manuelles : $($ManualActions.Count.ToString().PadRight(33))│" -ForegroundColor $(if ($ManualActions.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Erreurs           : $($FailCount.ToString().PadRight(33))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ✅ Rapport : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256 : $ExecHash"    -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    Write-Host "  Prochaine étape — Relancer l'audit :" -ForegroundColor Cyan
    Write-Host "  .\Audit-OAuthApplications.ps1 -Client '$Client'" -ForegroundColor White
    Write-Host "  Scellage :" -ForegroundColor Cyan
    Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-OAuthApplications.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
}

Write-Log "Remediate-OAuthApplications terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
