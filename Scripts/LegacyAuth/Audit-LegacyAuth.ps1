<#
.SYNOPSIS
    Audit des protocoles d'authentification legacy — Lecture seule absolue.

.DESCRIPTION
    Audit-LegacyAuth.ps1 détecte tous les protocoles d'authentification obsolètes
    encore actifs dans un environnement hybride AD + Entra ID.

    POURQUOI C'EST CRITIQUE :
    Les protocoles legacy (Basic Auth, NTLM, SMTP AUTH, POP3, IMAP, MAPI, ROPC)
    ne passent PAS par le flux d'authentification moderne d'Entra ID.
    Conséquence directe : ils CONTOURNENT le MFA.
    Un attaquant avec un mot de passe peut s'authentifier via SMTP AUTH
    même si l'utilisateur a le MFA activé et une politique CA en place.

    Ce script ne modifie rien. Il analyse quatre périmètres :
      [1] Logs de connexion Entra ID — qui utilise quoi (30 derniers jours)
      [2] Politiques CA — couverture du blocage legacy
      [3] Configuration Exchange Online — état des protocoles par boîte mail
      [4] Flux ROPC — applications utilisant le flux Password grant (contourne MFA)

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42  — Authentification forte obligatoire
      CSSF 22/806 Ctrl 7      — Contrôle des méthodes d'accès
      DORA Art. 9 §4(b)       — Protection contre accès non autorisé
      ISO 27001:2022 A.8.5    — Authentification sécurisée

    PRÉREQUIS :
      - Module Microsoft.Graph    : Install-Module Microsoft.Graph
      - Module ExchangeOnlineManagement : Install-Module ExchangeOnlineManagement
      - Rôle Entra ID : Security Reader + Reports Reader
      - Rôle Exchange : View-Only Recipients (lecture seule Exchange)
      - Licence Entra ID P1 minimum (pour les logs de connexion)

.PARAMETER OutputPath
    Dossier de sortie. Défaut : .\Reports

.PARAMETER Client
    Nom du client — intégré dans le JSON et le log.

.PARAMETER DaysBack
    Nombre de jours de logs à analyser.
    Défaut : 30. Maximum recommandé : 90 (rétention Entra ID P1).

.PARAMETER SkipExchange
    Ignore l'analyse Exchange Online (si non applicable ou droits insuffisants).

.PARAMETER SkipSignInLogs
    Ignore l'analyse des logs de connexion (si licence insuffisante).

.PARAMETER ExportAll
    Exporte tous les utilisateurs, y compris ceux sans legacy auth détecté.
    Par défaut : uniquement les utilisateurs à risque.

.EXAMPLE
    .\Audit-LegacyAuth.ps1 -Client "Banque XYZ"
    .\Audit-LegacyAuth.ps1 -Client "Assurance ABC" -DaysBack 90 -SkipExchange
    .\Audit-LegacyAuth.ps1 -Client "Client FR" -SkipSignInLogs

.OUTPUTS
    Reports/Audit-LegacyAuth_<date>.csv   — détail par utilisateur et protocole
    Reports/Audit-LegacyAuth_<date>.json  — score + findings + mapping réglementaire
    Reports/Audit-LegacyAuth_<date>.log   — journal d'exécution

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D2 — Legacy Authentication

    LECTURE SEULE — Ce script ne modifie aucun objet.
    Pour la remédiation : utiliser Remediate-LegacyAuth.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false)]
    [switch]$SkipExchange,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSignInLogs,

    [Parameter(Mandatory = $false)]
    [switch]$ExportAll
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
$BaseFileName  = "Audit-LegacyAuth_${DateStamp}"
$StartDate     = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddT00:00:00Z")

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile = Join-Path $OutputPath "${BaseFileName}.log"

# Protocoles legacy connus — toute connexion via ces clients est un risque
$LegacyClientApps = @(
    "Exchange ActiveSync",
    "IMAP4",
    "MAPI Over HTTP",
    "Offline Address Book",
    "Other clients",
    "POP3",
    "Reporting Web Services",
    "SMTP",
    "Exchange Web Services",
    "Autodiscover"
)

# Libellés de risque par protocole
$ProtocolRisk = @{
    "SMTP"                 = "CRITIQUE"   # Bypasse MFA, utilisé pour phishing, exfiltration mail
    "IMAP4"                = "CRITIQUE"   # Bypasse MFA, accès boîte mail sans Modern Auth
    "POP3"                 = "CRITIQUE"   # Bypasse MFA, protocole obsolète
    "Exchange ActiveSync"  = "ÉLEVÉ"      # Peut bypasser MFA selon config MDM
    "MAPI Over HTTP"       = "ÉLEVÉ"      # Legacy Outlook — dépend de la config
    "Exchange Web Services"= "ÉLEVÉ"      # API legacy, applications tierces
    "Other clients"        = "MOYEN"      # Indéterminé — investigation requise
    "Autodiscover"         = "FAIBLE"     # Découverte automatique — rarement direct
    "Offline Address Book" = "FAIBLE"     # Carnet d'adresses — risque limité
    "Reporting Web Services"= "FAIBLE"    # Rapports — contexte spécifique
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR"   { "Red"     }
        "WARN"    { "Yellow"  }
        "SUCCESS" { "Green"   }
        "FOUND"   { "Magenta" }
        default   { "Cyan"    }
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
Write-Host "║         AUDIT-LEGACYAUTH — IAM-FEDERATION-LAB           ║" -ForegroundColor DarkRed
Write-Host "║         Lecture seule · Aucune modification              ║" -ForegroundColor DarkRed
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkRed
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script     : Audit-LegacyAuth.ps1 v$ScriptVersion"
Write-Log "Client     : $Client"
Write-Log "Run ID     : $RunId"
Write-Log "Période    : $DaysBack jours ($StartDate → aujourd'hui)"
Write-Log "Exchange   : $(if ($SkipExchange) { 'IGNORÉ (-SkipExchange)' } else { 'Inclus' })"
Write-Log "Sign-in logs: $(if ($SkipSignInLogs) { 'IGNORÉS (-SkipSignInLogs)' } else { 'Inclus' })"

# ─────────────────────────────────────────────
# CONNEXION MICROSOFT GRAPH
# ─────────────────────────────────────────────

Write-Section "CONNEXION MICROSOFT GRAPH"

try {
    $Scopes = @(
        "User.Read.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All",
        "Application.Read.All"
    )
    Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
    $Context = Get-MgContext
    Write-Log "Connecté : $($Context.Account) → Tenant : $($Context.TenantId)" "SUCCESS"
} catch {
    Write-Log "Échec connexion Microsoft Graph : $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 1 — LOGS DE CONNEXION ENTRA ID
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 1 — LOGS DE CONNEXION ($DaysBack jours)"

# Dictionnaire : UPN → liste de protocoles détectés
$UserLegacyMap = @{}
$TotalLegacySignIns = 0
$ProtocolCounts = @{}

if ($SkipSignInLogs) {
    Write-Log "Analyse des logs ignorée (-SkipSignInLogs)" "WARN"
} else {
    Write-Log "Récupération des logs de connexion legacy depuis $DaysBack jours..."
    Write-Log "Filtrage sur clientAppUsed in (protocoles legacy connus)..."

    try {
        # Construire le filtre OData pour les protocoles legacy
        # Entra ID signe les connexions legacy avec des valeurs spécifiques de clientAppUsed
        $FilterParts = $LegacyClientApps | ForEach-Object {
            "clientAppUsed eq '$_'"
        }
        $Filter = "createdDateTime ge $StartDate and (" + ($FilterParts -join " or ") + ")"

        $SignInLogs = Get-MgAuditLogSignIn `
            -Filter $Filter `
            -All `
            -Property userPrincipalName, clientAppUsed, createdDateTime, `
                      ipAddress, location, status, appDisplayName, userDisplayName `
            -ErrorAction Stop

        Write-Log "Connexions legacy détectées : $($SignInLogs.Count)" $(
            if ($SignInLogs.Count -gt 0) { "FOUND" } else { "SUCCESS" }
        )

        foreach ($Log in $SignInLogs) {
            $UPN      = $Log.UserPrincipalName.ToLower()
            $Protocol = $Log.ClientAppUsed
            $Date     = $Log.CreatedDateTime
            $Country  = $Log.Location.CountryOrRegion
            $IP       = $Log.IpAddress
            $App      = $Log.AppDisplayName
            $Success  = ($Log.Status.ErrorCode -eq 0)

            $TotalLegacySignIns++

            # Comptage par protocole
            if (-not $ProtocolCounts.ContainsKey($Protocol)) {
                $ProtocolCounts[$Protocol] = @{ Total = 0; Success = 0; Users = @{} }
            }
            $ProtocolCounts[$Protocol].Total++
            if ($Success) { $ProtocolCounts[$Protocol].Success++ }
            $ProtocolCounts[$Protocol].Users[$UPN] = $true

            # Agrégation par utilisateur
            if (-not $UserLegacyMap.ContainsKey($UPN)) {
                $UserLegacyMap[$UPN] = @{
                    Protocols      = @{}
                    LastSeen       = $Date
                    Countries      = @{}
                    Apps           = @{}
                    SuccessCount   = 0
                    FailureCount   = 0
                }
            }

            # Protocoles par utilisateur
            if (-not $UserLegacyMap[$UPN].Protocols.ContainsKey($Protocol)) {
                $UserLegacyMap[$UPN].Protocols[$Protocol] = 0
            }
            $UserLegacyMap[$UPN].Protocols[$Protocol]++

            # Mise à jour dernière vue
            if ($Date -gt $UserLegacyMap[$UPN].LastSeen) {
                $UserLegacyMap[$UPN].LastSeen = $Date
            }

            # Pays
            if ($Country) { $UserLegacyMap[$UPN].Countries[$Country] = $true }

            # Applications
            if ($App)     { $UserLegacyMap[$UPN].Apps[$App] = $true }

            if ($Success) { $UserLegacyMap[$UPN].SuccessCount++ }
            else          { $UserLegacyMap[$UPN].FailureCount++ }
        }

        Write-Log "Utilisateurs distincts avec legacy auth : $($UserLegacyMap.Count)"
        foreach ($Proto in $ProtocolCounts.Keys | Sort-Object) {
            $Count = $ProtocolCounts[$Proto]
            Write-Log "  $Proto : $($Count.Total) connexions, $($Count.Users.Count) users" $(
                if ($ProtocolRisk[$Proto] -eq "CRITIQUE") { "FOUND" } else { "WARN" }
            )
        }

    } catch {
        Write-Log "Erreur récupération logs : $_" "WARN"
        Write-Log "→ Vérifier la licence Entra ID (P1 minimum requis pour les sign-in logs)" "WARN"
    }
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 2 — POLITIQUES CA DE BLOCAGE LEGACY
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 2 — POLITIQUES D'ACCÈS CONDITIONNEL (BLOCAGE LEGACY)"

$CAPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue

# Politiques qui bloquent explicitement les clients legacy
$LegacyBlockingPolicies = $CAPolicies | Where-Object {
    $_.State -eq "enabled" -and
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
    $_.Conditions.ClientAppTypes -contains "other" -and
    $_.GrantControls.Operator -eq "OR" -and
    $_.GrantControls.BuiltInControls -contains "block"
}

# Analyse de la couverture
$PoliciesBlockingLegacy    = @()
$PoliciesReportOnlyLegacy  = @()

foreach ($Policy in $CAPolicies) {
    $ClientApps = $Policy.Conditions.ClientAppTypes
    $IsBlocking = $Policy.GrantControls.BuiltInControls -contains "block"
    $IsReportOnly = $Policy.State -eq "enabledForReportingButNotEnforced"
    $TargetsLegacy = $ClientApps -contains "exchangeActiveSync" -or $ClientApps -contains "other"

    if ($TargetsLegacy -and $IsBlocking -and $Policy.State -eq "enabled") {
        $PoliciesBlockingLegacy += $Policy
    } elseif ($TargetsLegacy -and $IsReportOnly) {
        $PoliciesReportOnlyLegacy += $Policy
    }
}

$HasLegacyBlockingPolicy   = $PoliciesBlockingLegacy.Count -gt 0
$HasReportOnlyLegacyPolicy = $PoliciesReportOnlyLegacy.Count -gt 0

Write-Log "Total politiques CA        : $($CAPolicies.Count)"
Write-Log "Politiques bloquant legacy : $($PoliciesBlockingLegacy.Count)" $(
    if ($HasLegacyBlockingPolicy) { "SUCCESS" } else { "FOUND" }
)
Write-Log "Politiques rapport seul    : $($PoliciesReportOnlyLegacy.Count)" $(
    if ($PoliciesReportOnlyLegacy.Count -gt 0) { "WARN" } else { "INFO" }
)

if (-not $HasLegacyBlockingPolicy) {
    Write-Log "AUCUNE politique CA active ne bloque les protocoles legacy !" "FOUND"
    Write-Log "→ Tous les utilisateurs sont exposés au contournement MFA via legacy auth" "FOUND"
}

foreach ($P in $PoliciesBlockingLegacy) {
    $UsersScope = if ($P.Conditions.Users.IncludeUsers -contains "All") {
        "Tous les utilisateurs"
    } else {
        "$($P.Conditions.Users.IncludeUsers.Count) users + $($P.Conditions.Users.IncludeGroups.Count) groupes"
    }
    Write-Log "  Politique active : '$($P.DisplayName)' → Périmètre : $UsersScope" "SUCCESS"
}

foreach ($P in $PoliciesReportOnlyLegacy) {
    Write-Log "  Rapport seul (non bloquant) : '$($P.DisplayName)'" "WARN"
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 3 — EXCHANGE ONLINE
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 3 — CONFIGURATION EXCHANGE ONLINE"

$ExchangeData = @{}

if ($SkipExchange) {
    Write-Log "Analyse Exchange ignorée (-SkipExchange)" "WARN"
} else {
    # Vérifier si ExchangeOnlineManagement est disponible
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Log "Module ExchangeOnlineManagement non installé — analyse Exchange ignorée" "WARN"
        Write-Log "→ Install-Module ExchangeOnlineManagement -Scope CurrentUser" "WARN"
    } else {
        try {
            Write-Log "Connexion Exchange Online..."
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            Write-Log "Connecté Exchange Online" "SUCCESS"

            # Politique d'authentification globale
            Write-Log "Lecture de la politique d'authentification globale..."
            $AuthPolicies = Get-AuthenticationPolicy -ErrorAction SilentlyContinue

            foreach ($Policy in $AuthPolicies) {
                Write-Log "  Politique : '$($Policy.Name)'"
                Write-Log "    AllowBasicAuthActiveSync       : $($Policy.AllowBasicAuthActiveSync)"
                Write-Log "    AllowBasicAuthImap             : $($Policy.AllowBasicAuthImap)"
                Write-Log "    AllowBasicAuthPop              : $($Policy.AllowBasicAuthPop)"
                Write-Log "    AllowBasicAuthSmtp             : $($Policy.AllowBasicAuthSmtp)"
                Write-Log "    AllowBasicAuthWebServices      : $($Policy.AllowBasicAuthWebServices)"
                Write-Log "    AllowBasicAuthOutlookService   : $($Policy.AllowBasicAuthOutlookService)"

                $ExchangeData[$Policy.Name] = @{
                    BasicAuthActiveSync     = $Policy.AllowBasicAuthActiveSync
                    BasicAuthImap           = $Policy.AllowBasicAuthImap
                    BasicAuthPop            = $Policy.AllowBasicAuthPop
                    BasicAuthSmtp           = $Policy.AllowBasicAuthSmtp
                    BasicAuthWebServices    = $Policy.AllowBasicAuthWebServices
                    BasicAuthOutlook        = $Policy.AllowBasicAuthOutlookService
                }

                # Alertes
                if ($Policy.AllowBasicAuthSmtp) {
                    Write-Log "    ⚠ CRITIQUE : Basic Auth SMTP activé — vecteur d'exfiltration mail" "FOUND"
                }
                if ($Policy.AllowBasicAuthImap) {
                    Write-Log "    ⚠ CRITIQUE : Basic Auth IMAP activé — accès boîte mail sans MFA" "FOUND"
                }
                if ($Policy.AllowBasicAuthPop) {
                    Write-Log "    ⚠ CRITIQUE : Basic Auth POP3 activé — protocole obsolète" "FOUND"
                }
            }

            # Configuration SMTP AUTH globale
            Write-Log "Lecture de la configuration SMTP AUTH..."
            $TransportConfig = Get-TransportConfig -ErrorAction SilentlyContinue
            if ($TransportConfig) {
                Write-Log "  SmtpClientAuthenticationDisabled : $($TransportConfig.SmtpClientAuthenticationDisabled)"
                if (-not $TransportConfig.SmtpClientAuthenticationDisabled) {
                    Write-Log "  ⚠ SMTP AUTH activé au niveau global du tenant" "FOUND"
                } else {
                    Write-Log "  SMTP AUTH désactivé globalement" "SUCCESS"
                }
            }

            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

        } catch {
            Write-Log "Erreur analyse Exchange : $_" "WARN"
            Write-Log "→ Vérifier les droits Exchange (View-Only Recipients minimum)" "WARN"
        }
    }
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 4 — FLUX ROPC (Resource Owner Password Credentials)
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 4 — APPLICATIONS UTILISANT LE FLUX ROPC"

Write-Log "Analyse des applications avec flux ROPC (Password Grant)..."
Write-Log "Le flux ROPC transmets les credentials directement — contourne le MFA"

$ROPCApps = @()

try {
    # Récupérer les applications inscrites
    $AppRegistrations = Get-MgApplication -All `
        -Property DisplayName, AppId, SignInAudience, PublicClient `
        -ErrorAction Stop

    foreach ($App in $AppRegistrations) {
        # Les applications Public Client avec flux de mot de passe activé peuvent utiliser ROPC
        if ($App.PublicClient -and $App.PublicClient.RedirectUris.Count -gt 0) {
            # Vérifier si le flux ROPC est explicitement autorisé
            # (dans les propriétés de l'application via MS Graph beta endpoint)
            $ROPCApps += [PSCustomObject]@{
                AppName          = $App.DisplayName
                AppId            = $App.AppId
                SignInAudience   = $App.SignInAudience
                IsPublicClient   = $true
                ROPCRisk         = "MOYEN"
                Note             = "Application cliente publique — flux ROPC potentiellement actif"
            }
        }
    }

    Write-Log "Applications Public Client détectées : $($ROPCApps.Count)" $(
        if ($ROPCApps.Count -gt 0) { "WARN" } else { "SUCCESS" }
    )

    # Chercher dans les logs de connexion les flux ROPC (grantType = password)
    if (-not $SkipSignInLogs) {
        Write-Log "Recherche de connexions ROPC dans les logs..."
        try {
            $ROPCSignIns = Get-MgAuditLogSignIn `
                -Filter "createdDateTime ge $StartDate and authenticationProtocol eq 'ropc'" `
                -All -ErrorAction Stop

            if ($ROPCSignIns.Count -gt 0) {
                Write-Log "Connexions ROPC détectées : $($ROPCSignIns.Count)" "FOUND"
                $ROPCAppsFromLogs = $ROPCSignIns | Group-Object AppDisplayName |
                    Select-Object Name, Count |
                    Sort-Object Count -Descending

                foreach ($App in $ROPCAppsFromLogs) {
                    Write-Log "  Application ROPC confirmée : '$($App.Name)' — $($App.Count) connexions" "FOUND"
                }
            } else {
                Write-Log "Aucune connexion ROPC confirmée dans les logs" "SUCCESS"
            }
        } catch {
            Write-Log "Impossible de filtrer sur authenticationProtocol — endpoint peut nécessiter beta" "WARN"
        }
    }

} catch {
    Write-Log "Erreur analyse ROPC : $_" "WARN"
}

# ─────────────────────────────────────────────
# CONSOLIDATION DES RÉSULTATS
# ─────────────────────────────────────────────

Write-Section "CONSOLIDATION DES RÉSULTATS"

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Récupérer tous les utilisateurs pour enrichissement
Write-Log "Récupération des informations utilisateurs pour enrichissement..."
$AllUsers = Get-MgUser -All `
    -Filter "accountEnabled eq true and userType eq 'Member'" `
    -Property Id, UserPrincipalName, DisplayName, Department `
    -ErrorAction SilentlyContinue

$UserDict = @{}
foreach ($U in $AllUsers) { $UserDict[$U.UserPrincipalName.ToLower()] = $U }

# Construire les résultats par utilisateur
foreach ($UPN in $UserLegacyMap.Keys) {
    $UserInfo  = $UserDict[$UPN]
    $UserData  = $UserLegacyMap[$UPN]

    # Protocoles triés par risque
    $Protocols     = $UserData.Protocols.Keys
    $WorstRisk     = "FAIBLE"
    $ProtocolsList = @()

    foreach ($Proto in $Protocols) {
        $Risk = if ($ProtocolRisk.ContainsKey($Proto)) { $ProtocolRisk[$Proto] } else { "MOYEN" }
        $ProtocolsList += "$Proto($($UserData.Protocols[$Proto])x)"

        # Escalade du niveau de risque global
        $WorstRisk = switch ($true) {
            { $Risk -eq "CRITIQUE" }                              { "CRITIQUE"; break }
            { $Risk -eq "ÉLEVÉ" -and $WorstRisk -ne "CRITIQUE" } { "ÉLEVÉ";   break }
            { $Risk -eq "MOYEN"  -and $WorstRisk -notin @("CRITIQUE","ÉLEVÉ") } { "MOYEN"; break }
            default { $WorstRisk }
        }
    }

    # Vérifier si l'utilisateur est couvert par une politique CA bloquant legacy
    $CoveredByCABlock = $false
    foreach ($Policy in $PoliciesBlockingLegacy) {
        $IncludeAll    = $Policy.Conditions.Users.IncludeUsers -contains "All"
        $ExcludedUsers = $Policy.Conditions.Users.ExcludeUsers

        if ($IncludeAll -and ($UserInfo -and $ExcludedUsers -notcontains $UserInfo.Id)) {
            $CoveredByCABlock = $true
            break
        }
    }

    # Escalade si non couvert par CA
    if (-not $CoveredByCABlock -and $WorstRisk -ne "CRITIQUE") {
        if ($WorstRisk -eq "ÉLEVÉ") { $WorstRisk = "CRITIQUE" }
        if ($WorstRisk -eq "MOYEN") { $WorstRisk = "ÉLEVÉ" }
    }

    $Record = [PSCustomObject]@{
        UPN                   = $UPN
        DisplayName           = if ($UserInfo) { $UserInfo.DisplayName } else { "INCONNU" }
        Department            = if ($UserInfo) { $UserInfo.Department  } else { "INCONNU" }
        ProtocolsDetected     = $ProtocolsList -join " | "
        ProtocolCount         = $Protocols.Count
        TotalConnections      = ($UserData.Protocols.Values | Measure-Object -Sum).Sum
        SuccessfulConnections = $UserData.SuccessCount
        FailedConnections     = $UserData.FailureCount
        LastDetected          = $UserData.LastSeen.ToString("yyyy-MM-dd")
        CountriesDetected     = ($UserData.Countries.Keys -join ", ")
        AppsDetected          = ($UserData.Apps.Keys | Select-Object -First 3) -join " | "
        CoveredByCABlock      = $CoveredByCABlock
        RiskLevel             = $WorstRisk
        RegulatoryRef         = switch ($WorstRisk) {
            "CRITIQUE" { "FINMA §42 · CSSF Ctrl 7 · DORA Art.9 §4(b)" }
            "ÉLEVÉ"    { "FINMA §42 · DORA Art.9 §4(b)" }
            default    { "ISO 27001 A.8.5" }
        }
    }

    if ($ExportAll -or $WorstRisk -in @("CRITIQUE", "ÉLEVÉ", "MOYEN")) {
        $Results.Add($Record)
    }
}

Write-Log "Résultats consolidés : $($Results.Count) utilisateurs à risque"

# ─────────────────────────────────────────────
# CALCUL DU SCORE
# ─────────────────────────────────────────────

Write-Section "CALCUL DU SCORE DE CONFORMITÉ"

$TotalUsers        = $AllUsers.Count
$UsersWithLegacy   = $UserLegacyMap.Count
$CritiqueCount     = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" }).Count
$EleveCount        = ($Results | Where-Object { $_.RiskLevel -eq "ÉLEVÉ"    }).Count
$MoyenCount        = ($Results | Where-Object { $_.RiskLevel -eq "MOYEN"    }).Count

# Score basé sur :
# - Taux d'utilisateurs sans legacy auth actif (70% du score)
# - Présence d'une politique CA de blocage active (30% du score)
$UserScore  = if ($TotalUsers -gt 0) {
    [math]::Round((1 - ($UsersWithLegacy / $TotalUsers)) * 70, 0)
} else { 70 }

$PolicyScore = if ($HasLegacyBlockingPolicy) { 30 } elseif ($HasReportOnlyLegacyPolicy) { 10 } else { 0 }
$Score       = $UserScore + $PolicyScore

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

# Top findings
$TopFindings = [System.Collections.Generic.List[string]]::new()

if (-not $HasLegacyBlockingPolicy) {
    $TopFindings.Add("CRITIQUE : Aucune politique CA active ne bloque les protocoles legacy — le MFA est contournable pour TOUS les utilisateurs")
}
if ($HasReportOnlyLegacyPolicy) {
    $TopFindings.Add("$($PoliciesReportOnlyLegacy.Count) politique(s) de blocage legacy en mode rapport seul — non bloquante(s), activation requise")
}
if ($CritiqueCount -gt 0) {
    $Sample = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" } | Select-Object -First 3 -ExpandProperty UPN) -join ", "
    $TopFindings.Add("$CritiqueCount utilisateur(s) CRITIQUE : connexions legacy non bloquées par CA → $Sample")
}
if ($ExchangeData.Values | Where-Object { $_.BasicAuthSmtp }) {
    $TopFindings.Add("CRITIQUE : Basic Auth SMTP activé dans la politique Exchange — exfiltration mail possible sans MFA")
}
if ($ExchangeData.Values | Where-Object { $_.BasicAuthImap }) {
    $TopFindings.Add("CRITIQUE : Basic Auth IMAP activé — accès boîte mail sans MFA")
}
if ($TotalLegacySignIns -gt 0) {
    $TopFindings.Add("$TotalLegacySignIns connexions legacy détectées sur $DaysBack jours ($UsersWithLegacy utilisateurs)")
}
if ($ROPCApps.Count -gt 0) {
    $TopFindings.Add("$($ROPCApps.Count) application(s) potentiellement ROPC détectée(s) — investigation manuelle requise")
}

# Répartition par protocole
$ProtoSummary = $ProtocolCounts.GetEnumerator() |
    Sort-Object { $_.Value.Total } -Descending |
    Select-Object -First 5 |
    ForEach-Object { "$($_.Key) : $($_.Value.Total) connexions ($($_.Value.Users.Count) users)" }

Write-Log "Score Legacy Auth : $Score/100 ($ScoreLabel)"
Write-Log "Utilisateurs avec legacy auth actif : $UsersWithLegacy / $TotalUsers"
Write-Log "Politique CA de blocage active      : $HasLegacyBlockingPolicy"
Write-Log "CRITIQUE : $CritiqueCount | ÉLEVÉ : $EleveCount | MOYEN : $MoyenCount"

# ─────────────────────────────────────────────
# EXPORT CSV
# ─────────────────────────────────────────────

Write-Section "EXPORT CSV"

$CsvPath = Join-Path $OutputPath "${BaseFileName}.csv"

$Results |
    Sort-Object @{E={
        switch ($_.RiskLevel) {
            "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } "MOYEN" { 2 } default { 3 }
        }
    }}, UPN |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Log "CSV exporté : $CsvPath ($($Results.Count) lignes)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

Write-Section "EXPORT JSON"

$JsonReport = [ordered]@{
    "_schema"              = "iam-federation-lab/audit-legacyauth/v1.0"
    "RunId"                = $RunId
    "Domain"               = "D2 — Legacy Authentication"
    "Client"               = $Client
    "Date"                 = $DateStamp
    "GeneratedAt"          = $TimeStamp
    "AnalysisPeriodDays"   = $DaysBack
    "Score"                = $Score
    "ScoreLabel"           = $ScoreLabel
    "Statistics"           = [ordered]@{
        "TotalUsersInTenant"      = $TotalUsers
        "UsersWithLegacyAuth"     = $UsersWithLegacy
        "TotalLegacySignIns"      = $TotalLegacySignIns
        "LegacyAsPercentOfUsers"  = if ($TotalUsers -gt 0) { [math]::Round($UsersWithLegacy / $TotalUsers * 100, 1) } else { 0 }
        "ROPCAppsDetected"        = $ROPCApps.Count
    }
    "RiskBreakdown"        = [ordered]@{
        "CRITIQUE" = $CritiqueCount
        "ÉLEVÉ"    = $EleveCount
        "MOYEN"    = $MoyenCount
    }
    "CABlockingPolicy"     = [ordered]@{
        "HasActiveBlockingPolicy" = $HasLegacyBlockingPolicy
        "HasReportOnlyPolicy"     = $HasReportOnlyLegacyPolicy
        "ActivePoliciesCount"     = $PoliciesBlockingLegacy.Count
        "ReportOnlyCount"         = $PoliciesReportOnlyLegacy.Count
    }
    "ProtocolBreakdown"    = $ProtoSummary
    "ExchangeConfig"       = $ExchangeData
    "TopFindings"          = $TopFindings
    "RegulatoryMapping"    = [ordered]@{
        "FINMA_2023_1_S42"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "CSSF_22806_Ctrl7"  = if ($HasLegacyBlockingPolicy -and $Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "DORA_Art9_S4b"     = if ($UsersWithLegacy -eq 0 -and $HasLegacyBlockingPolicy) { "CONFORME" } elseif ($HasLegacyBlockingPolicy) { "PARTIEL" } else { "NON_CONFORME" }
        "ISO27001_A85"      = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"             = "Remediate-LegacyAuth.ps1 -AuditReport '$CsvPath' -DryRun"
}

$JsonPath = Join-Path $OutputPath "${BaseFileName}.json"
$JsonReport | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-Log "JSON exporté : $JsonPath" "SUCCESS"

# ─────────────────────────────────────────────
# RÉSUMÉ CONSOLE
# ─────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

$ScoreColor = switch ($ScoreLabel) {
    "OPTIMAL"     { "Green"  } "CONFORME" { "Green"  }
    "PARTIEL"     { "Yellow" } "INSUFFISANT" { "Red" } "CRITIQUE" { "Red" }
    default       { "White"  }
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCORE LEGACY AUTH : $($Score.ToString().PadRight(3))/100 — $($ScoreLabel.PadRight(13))│" -ForegroundColor $ScoreColor
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Utilisateurs avec legacy auth : $($UsersWithLegacy.ToString().PadRight(21))│" -ForegroundColor $(if ($UsersWithLegacy -gt 0) { "Red" } else { "Green" })
Write-Host "  │  Connexions legacy ($($DaysBack)j)    : $($TotalLegacySignIns.ToString().PadRight(21))│" -ForegroundColor $(if ($TotalLegacySignIns -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Politique CA blocage active   : $((if ($HasLegacyBlockingPolicy) {'OUI'} else {'NON'}).PadRight(21))│" -ForegroundColor $(if ($HasLegacyBlockingPolicy) { "Green" } else { "Red" })
Write-Host "  │  CRITIQUE : $($CritiqueCount.ToString().PadRight(5)) ÉLEVÉ : $($EleveCount.ToString().PadRight(5)) MOYEN : $($MoyenCount.ToString().PadRight(9))│" -ForegroundColor White
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

if ($TopFindings.Count -gt 0) {
    Write-Host "  POINTS D'ATTENTION :" -ForegroundColor Red
    foreach ($F in $TopFindings) { Write-Host "  → $F" -ForegroundColor Yellow }
    Write-Host ""
}

Write-Host "  LIVRABLES :" -ForegroundColor Cyan
Write-Host "  ✅ CSV  : $CsvPath" -ForegroundColor Green
Write-Host "  ✅ JSON : $JsonPath" -ForegroundColor Green
Write-Host "  ✅ LOG  : $LogFile" -ForegroundColor Green
Write-Host ""
Write-Host "  PROCHAINE ÉTAPE :" -ForegroundColor Cyan
Write-Host "  .\Remediate-LegacyAuth.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""

Write-Log "Audit Legacy Auth terminé — Score : $Score/100 ($ScoreLabel) — Run ID : $RunId" "SUCCESS"

Disconnect-MgGraph -ErrorAction SilentlyContinue
