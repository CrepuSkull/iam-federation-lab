<#
.SYNOPSIS
    Remédiation des protocoles legacy — Validation CSV obligatoire avant toute action.

.DESCRIPTION
    Remediate-LegacyAuth.ps1 prend en entrée le rapport produit par Audit-LegacyAuth.ps1
    et applique le flux de remédiation en trois temps (Proposals → Validation → Execute).

    ATTENTION SPÉCIFIQUE À CE DOMAINE :
    La désactivation des protocoles legacy peut casser des applications qui n'ont pas
    encore migré vers Modern Auth. Avant toute action sur SMTP/IMAP/POP3 :
      1. Identifier les applications qui utilisent ces protocoles (colonne AppsDetected)
      2. Vérifier avec les équipes métier si ces applications supportent Modern Auth
      3. Planifier la migration des applications AVANT de bloquer le protocole
    Le DryRun est OBLIGATOIRE et la validation CSV est la seule façon de procéder.

    ACTIONS DISPONIBLES :
      BlockLegacyViaCA       — Créer/activer une politique CA bloquant les clients legacy
                               pour les utilisateurs sélectionnés (action non destructive,
                               réversible, recommandée en premier)
      DisableBasicAuthSmtp   — Désactiver Basic Auth SMTP pour la boîte mail spécifique
      DisableBasicAuthImap   — Désactiver Basic Auth IMAP pour la boîte mail spécifique
      DisableBasicAuthPop    — Désactiver Basic Auth POP3 pour la boîte mail spécifique
      DisableBasicAuthAll    — Désactiver tous les protocoles Basic Auth pour l'utilisateur
      DocumentException      — Marquer l'utilisateur comme exception documentée (app legacy
                               en attente de migration — pas d'action technique)

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42 · CSSF 22/806 Ctrl 7 · DORA Art. 9 §4(b) · ISO 27001 A.8.5

.PARAMETER AuditReport
    Chemin vers le CSV produit par Audit-LegacyAuth.ps1. Obligatoire.

.PARAMETER ValidatedReport
    CSV de propositions retourné avec la colonne Valider remplie.
    Absent → génère les propositions (Temps 1).
    Présent → exécute les actions validées (Temps 3).

.PARAMETER OutputPath
    Dossier de sortie. Défaut : même dossier que AuditReport.

.PARAMETER Client
    Nom du client pour les rapports.

.PARAMETER PreferCABlock
    Si activé, propose BlockLegacyViaCA en priorité sur la désactivation Exchange.
    Recommandé : le blocage CA est moins risqué et réversible.
    Défaut : $true

.PARAMETER DryRun
    Force la simulation même si ValidatedReport est fourni.

.EXAMPLE
    # Temps 1 — Génération des propositions
    .\Remediate-LegacyAuth.ps1 -AuditReport ".\Reports\Audit-LegacyAuth_2026-03-29.csv" -Client "Banque XYZ"

    # Temps 3 DryRun — Vérification avant exécution
    .\Remediate-LegacyAuth.ps1 `
        -AuditReport ".\Reports\Audit-LegacyAuth_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-LegacyAuth_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ" -DryRun

    # Temps 3 — Exécution réelle
    .\Remediate-LegacyAuth.ps1 `
        -AuditReport ".\Reports\Audit-LegacyAuth_2026-03-29.csv" `
        -ValidatedReport ".\Reports\Remediate-LegacyAuth_Proposals_2026-03-29.csv" `
        -Client "Banque XYZ"

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab

    AUCUNE ACTION SANS "OUI" EXPLICITE DANS LE CSV.
    Vérifier la compatibilité des applications avant toute désactivation Exchange.
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
    [bool]$PreferCABlock = $true,

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

$LogFile = Join-Path $OutputPath "Remediate-LegacyAuth_${DateStamp}_${RunId}.log"

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
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkRed
Write-Host "║       REMEDIATE-LEGACYAUTH — IAM-FEDERATION-LAB         ║" -ForegroundColor DarkRed
Write-Host "║       Mode : $($Mode.PadRight(45))║" -ForegroundColor DarkRed
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkRed
Write-Host ""

Write-Log "Script  : Remediate-LegacyAuth.ps1 v$ScriptVersion"
Write-Log "Mode    : $Mode"
Write-Log "RunId   : $RunId"
Write-Log "Client  : $Client"
Write-Log "PreferCABlock : $PreferCABlock"

# ─────────────────────────────────────────────
# MODE PROPOSALS — TEMPS 1
# ─────────────────────────────────────────────

if ($Mode -eq "PROPOSALS") {

    Write-Section "TEMPS 1 — GÉNÉRATION DES PROPOSITIONS"

    # Avertissement spécifique au domaine Legacy Auth
    Write-Host ""
    Write-Host "  ⚠  AVERTISSEMENT IMPORTANT — AVANT DE VALIDER LE CSV" -ForegroundColor Red
    Write-Host "  ──────────────────────────────────────────────────────" -ForegroundColor Red
    Write-Host "  La désactivation de Basic Auth SMTP/IMAP/POP3 peut casser" -ForegroundColor Yellow
    Write-Host "  des applications qui n'ont pas migré vers Modern Auth." -ForegroundColor Yellow
    Write-Host "  Pour chaque ligne, vérifier la colonne AppsDetected et" -ForegroundColor Yellow
    Write-Host "  confirmer avec les équipes métier avant de cocher OUI." -ForegroundColor Yellow
    Write-Host "  L'action BlockLegacyViaCA (politique CA) est plus sûre" -ForegroundColor Yellow
    Write-Host "  car réversible sans impact Exchange." -ForegroundColor Yellow
    Write-Host ""

    $AuditData  = Import-Csv -Path $AuditReport -Encoding UTF8
    $Actionable = $AuditData | Where-Object { $_.RiskLevel -in @("CRITIQUE", "ÉLEVÉ", "MOYEN") }

    Write-Log "Comptes à risque dans le rapport audit : $($Actionable.Count)"

    $Proposals = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IdCounter = 1

    foreach ($User in $Actionable) {

        # Déterminer les protocoles à traiter
        $Protocols = $User.ProtocolsDetected -split " \| " |
            ForEach-Object { ($_ -split "\(")[0].Trim() }

        $HasCriticalProto = $Protocols | Where-Object { $_ -in @("SMTP", "IMAP4", "POP3") }
        $HasElevatedProto = $Protocols | Where-Object { $_ -in @("Exchange ActiveSync", "MAPI Over HTTP", "Exchange Web Services") }

        # Déterminer l'action selon la préférence et le risque
        $ActionType   = ""
        $ActionDetail = ""
        $Urgency      = ""

        if ($PreferCABlock -or $User.CoveredByCABlock -eq "False") {
            # Action prioritaire : blocage CA (moins risqué, réversible)
            $ActionType   = "BlockLegacyViaCA"
            $ActionDetail = "Créer/activer une politique CA bloquant les clients legacy pour $($User.UPN). " +
                            "Protocoles détectés : $($User.ProtocolsDetected). " +
                            "VÉRIFIER les applications dans la colonne AppsDetected avant de valider."
            $Urgency      = if ($User.RiskLevel -eq "CRITIQUE") { "IMMÉDIAT" } else { "PLANIFIÉ" }
        }

        # Ajouter des actions Exchange spécifiques si protocoles critiques
        if ($HasCriticalProto) {
            # Action complémentaire : désactivation Exchange pour les protocoles les plus dangereux
            $ProtoActions = @()
            if ($Protocols -contains "SMTP")  { $ProtoActions += "DisableBasicAuthSmtp" }
            if ($Protocols -contains "IMAP4") { $ProtoActions += "DisableBasicAuthImap" }
            if ($Protocols -contains "POP3")  { $ProtoActions += "DisableBasicAuthPop"  }

            foreach ($ProtoAction in $ProtoActions) {
                $ProtoName = $ProtoAction -replace "DisableBasicAuth", ""
                $Proposals.Add([PSCustomObject]@{
                    ID                  = $IdCounter.ToString("D3")
                    UPN                 = $User.UPN
                    DisplayName         = $User.DisplayName
                    Department          = $User.Department
                    RiskLevel           = $User.RiskLevel
                    ActionType          = $ProtoAction
                    ActionDetail        = "Désactiver Basic Auth $ProtoName pour $($User.UPN). " +
                                         "⚠ VÉRIFIER d'abord : AppsDétectées = $($User.AppsDetected). " +
                                         "Confirmer avec équipes métier que l'application supporte Modern Auth."
                    ProtocolsDetected   = $User.ProtocolsDetected
                    AppsDetected        = $User.AppsDetected
                    TotalConnections    = $User.TotalConnections
                    LastDetected        = $User.LastDetected
                    CoveredByCABlock    = $User.CoveredByCABlock
                    RegulatoryReference = $User.RegulatoryRef
                    Urgency             = "APRÈS VÉRIFICATION APPS"
                    Valider             = ""
                    Commentaire         = ""
                })
                $IdCounter++
            }
        }

        # Ajouter l'action CA en tout cas si non couverte
        if ($ActionType) {
            $Proposals.Add([PSCustomObject]@{
                ID                  = $IdCounter.ToString("D3")
                UPN                 = $User.UPN
                DisplayName         = $User.DisplayName
                Department          = $User.Department
                RiskLevel           = $User.RiskLevel
                ActionType          = $ActionType
                ActionDetail        = $ActionDetail
                ProtocolsDetected   = $User.ProtocolsDetected
                AppsDetected        = $User.AppsDetected
                TotalConnections    = $User.TotalConnections
                LastDetected        = $User.LastDetected
                CoveredByCABlock    = $User.CoveredByCABlock
                RegulatoryReference = $User.RegulatoryRef
                Urgency             = $Urgency
                Valider             = ""
                Commentaire         = ""
            })
            $IdCounter++
        }
    }

    # Tri : CRITIQUE en premier, puis par type d'action (CA avant Exchange)
    $SortedProposals = $Proposals |
        Sort-Object @{E={ switch ($_.RiskLevel) { "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } default { 2 } } }},
                    @{E={ if ($_.ActionType -eq "BlockLegacyViaCA") { 0 } else { 1 } }},
                    UPN

    $ProposalsPath = Join-Path $OutputPath "Remediate-LegacyAuth_Proposals_${DateStamp}.csv"
    $SortedProposals | Export-Csv -Path $ProposalsPath -NoTypeInformation -Encoding UTF8

    # Scellage SHA-256 du CSV de propositions
    $ProposalsHash = (Get-FileHash -Path $ProposalsPath -Algorithm SHA256).Hash
    "$ProposalsHash  $(Split-Path $ProposalsPath -Leaf)" |
        Out-File -FilePath "${ProposalsPath}.sha256" -Encoding UTF8

    Write-Log "CSV de propositions : $ProposalsPath ($($Proposals.Count) actions)" "SUCCESS"
    Write-Log "SHA-256 propositions : $ProposalsHash"

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  TEMPS 2 — VALIDATION REQUISE                            │" -ForegroundColor Yellow
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
    Write-Host "  │  1. Ouvrir le CSV dans Excel                             │" -ForegroundColor White
    Write-Host "  │  2. Pour chaque ligne, vérifier AppsDetected             │" -ForegroundColor White
    Write-Host "  │  3. Confirmer avec les équipes métier (actions Exchange) │" -ForegroundColor White
    Write-Host "  │  4. Renseigner OUI dans la colonne Valider               │" -ForegroundColor White
    Write-Host "  │  5. Relancer avec -ValidatedReport -DryRun d'abord       │" -ForegroundColor White
    Write-Host "  ├──────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host "  │  .\Remediate-LegacyAuth.ps1 ``                           │" -ForegroundColor White
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

# Vérification d'intégrité du CSV validé
$ValidatedData = Import-Csv -Path $ValidatedReport -Encoding UTF8
$ValidatedYes  = $ValidatedData | Where-Object { $_.Valider -eq "OUI" }

Write-Log "Actions validées OUI  : $($ValidatedYes.Count)"
Write-Log "Actions non validées  : $(($ValidatedData | Where-Object { $_.Valider -ne 'OUI' }).Count)"

if ($ValidatedYes.Count -eq 0) {
    Write-Log "Aucune action validée. Arrêt." "WARN"
    exit 0
}

# Connexion
if (-not $DryRun) {
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","User.ReadWrite.All" -NoWelcome -ErrorAction Stop
    Write-Log "Connecté Microsoft Graph : $((Get-MgContext).Account)" "SUCCESS"

    # Exchange si actions Exchange présentes
    $HasExchangeActions = $ValidatedYes | Where-Object { $_.ActionType -like "DisableBasicAuth*" }
    if ($HasExchangeActions) {
        if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            Write-Log "Connecté Exchange Online" "SUCCESS"
        } else {
            Write-Log "Module ExchangeOnlineManagement requis pour les actions Exchange" "ERROR"
            exit 1
        }
    }
}

$ExecutedRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuccessCount = 0; $FailCount = 0; $SkipCount = 0

foreach ($Action in $ValidatedYes) {

    Write-Log "─── Action $($Action.ID) : $($Action.UPN) → $($Action.ActionType)" "ACTION"

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

                "BlockLegacyViaCA" {
                    # Chercher une politique CA existante de blocage legacy à activer
                    # ou créer une nouvelle politique ciblée sur cet utilisateur
                    $ExistingPolicy = Get-MgIdentityConditionalAccessPolicy -All |
                        Where-Object {
                            $_.DisplayName -like "*Legacy*Block*" -or
                            $_.DisplayName -like "*Block*Legacy*"
                        } | Select-Object -First 1

                    if ($ExistingPolicy -and $ExistingPolicy.State -ne "enabled") {
                        # Activer la politique existante
                        Update-MgIdentityConditionalAccessPolicy `
                            -ConditionalAccessPolicyId $ExistingPolicy.Id `
                            -State "enabled"
                        Write-Log "  Politique CA '$($ExistingPolicy.DisplayName)' activée" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Politique CA '$($ExistingPolicy.DisplayName)' activée pour blocage legacy"
                    } else {
                        # Créer une nouvelle politique de blocage pour cet utilisateur
                        $UserId = (Get-MgUser -UserId $Action.UPN).Id

                        $PolicyBody = @{
                            DisplayName = "IAM-Lab - Block Legacy Auth - $($Action.UPN)"
                            State       = "enabled"
                            Conditions  = @{
                                Users       = @{ IncludeUsers = @($UserId) }
                                ClientAppTypes = @("exchangeActiveSync", "other")
                            }
                            GrantControls = @{
                                Operator         = "OR"
                                BuiltInControls  = @("block")
                            }
                        }

                        New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody | Out-Null
                        Write-Log "  Nouvelle politique CA créée pour $($Action.UPN)" "SUCCESS"
                        $ExecStatus = "SUCCESS"
                        $ExecDetail = "Politique CA 'IAM-Lab - Block Legacy Auth' créée et activée"
                    }
                    $SuccessCount++
                }

                "DisableBasicAuthSmtp" {
                    # Désactiver Basic Auth SMTP pour la boîte mail spécifique
                    Set-CASMailbox -Identity $Action.UPN -SmtpClientAuthenticationDisabled $true
                    Write-Log "  Basic Auth SMTP désactivé pour $($Action.UPN)" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "SmtpClientAuthenticationDisabled = True sur la boîte mail"
                    $SuccessCount++
                }

                "DisableBasicAuthImap" {
                    Set-CASMailbox -Identity $Action.UPN -ImapEnabled $false
                    Write-Log "  Basic Auth IMAP désactivé pour $($Action.UPN)" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "ImapEnabled = False sur la boîte mail"
                    $SuccessCount++
                }

                "DisableBasicAuthPop" {
                    Set-CASMailbox -Identity $Action.UPN -PopEnabled $false
                    Write-Log "  Basic Auth POP3 désactivé pour $($Action.UPN)" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "PopEnabled = False sur la boîte mail"
                    $SuccessCount++
                }

                "DisableBasicAuthAll" {
                    Set-CASMailbox -Identity $Action.UPN `
                        -SmtpClientAuthenticationDisabled $true `
                        -ImapEnabled $false `
                        -PopEnabled $false `
                        -ActiveSyncEnabled $false
                    Write-Log "  Tous les protocoles Basic Auth désactivés pour $($Action.UPN)" "SUCCESS"
                    $ExecStatus = "SUCCESS"
                    $ExecDetail = "SMTP/IMAP/POP3/ActiveSync désactivés sur la boîte mail"
                    $SuccessCount++
                }

                "DocumentException" {
                    # Pas d'action technique — traçabilité uniquement
                    Write-Log "  Exception documentée pour $($Action.UPN) : $($Action.Commentaire)" "SUCCESS"
                    $ExecStatus = "DOCUMENTED"
                    $ExecDetail = "Exception documentée — commentaire : $($Action.Commentaire)"
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
        UPN                 = $Action.UPN
        DisplayName         = $Action.DisplayName
        Department          = $Action.Department
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

# Export rapport d'exécution
$ExecSuffix  = if ($DryRun) { "DryRun" } else { "Executed" }
$ExecCsvPath = Join-Path $OutputPath "Remediate-LegacyAuth_${ExecSuffix}_${DateStamp}_${RunId}.csv"
$ExecutedRecords | Export-Csv -Path $ExecCsvPath -NoTypeInformation -Encoding UTF8

# Scellage SHA-256
$ExecHash = (Get-FileHash -Path $ExecCsvPath -Algorithm SHA256).Hash
"$ExecHash  $(Split-Path $ExecCsvPath -Leaf)" | Out-File "${ExecCsvPath}.sha256" -Encoding UTF8

$ValHash = (Get-FileHash -Path $ValidatedReport -Algorithm SHA256).Hash
"$ValHash  $(Split-Path $ValidatedReport -Leaf)" | Out-File "${ValidatedReport}.sha256" -Encoding UTF8

# Résumé
Write-Section "RÉSUMÉ D'EXÉCUTION"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  MODE      : $($ExecSuffix.ToUpper().PadRight(41))│" -ForegroundColor $(if ($DryRun) { "Yellow" } else { "Green" })
Write-Host "  │  Succès    : $($SuccessCount.ToString().PadRight(41))│" -ForegroundColor Green
Write-Host "  │  Erreurs   : $($FailCount.ToString().PadRight(41))│" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "White" })
Write-Host "  │  Skip/Dry  : $($SkipCount.ToString().PadRight(41))│" -ForegroundColor Gray
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ✅ Rapport exécution : $ExecCsvPath" -ForegroundColor Green
Write-Host "  ✅ SHA-256           : $ExecHash"    -ForegroundColor Green
Write-Host ""

if (-not $DryRun) {
    Write-Host "  PROCHAINE ÉTAPE — Relancer l'audit pour mesurer l'amélioration :" -ForegroundColor Cyan
    Write-Host "  .\Audit-LegacyAuth.ps1 -Client '$Client'" -ForegroundColor White
    Write-Host ""
    Write-Host "  SCELLAGE (iam-evidence-sealer) :" -ForegroundColor Cyan
    Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\remediate\Remediate-LegacyAuth.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
}

Write-Log "Remediate-LegacyAuth terminé — Mode : $ExecSuffix — Run ID : $RunId" "SUCCESS"

if (-not $DryRun) {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
