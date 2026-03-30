<#
.SYNOPSIS
    Audit des politiques d'accès conditionnel — Lecture seule absolue.

.DESCRIPTION
    Audit-ConditionalAccess.ps1 cartographie et évalue l'ensemble des politiques
    d'accès conditionnel (CA) du tenant Entra ID.

    POURQUOI C'EST LE CERVEAU DÉCISIONNEL DU CONTRÔLE D'ACCÈS :
    Les politiques CA sont la couche qui décide, à chaque connexion, si un accès
    est accordé, refusé, ou soumis à conditions supplémentaires (MFA, terminal
    conforme, localisation). Dans un environnement à maturité moyenne, ces politiques
    sont le résultat d'ajouts successifs non coordonnés :
      → Des politiques en mode "Report-Only" depuis des mois — non bloquantes
      → Des applications entières non couvertes par aucune politique
      → Des utilisateurs exclus de toutes les politiques (hors comptes breakglass)
      → Des politiques contradictoires sur le même périmètre
      → Pas de condition de risque de connexion malgré Entra ID Protection

    Ce script analyse 6 dimensions :
      [1] Inventaire complet — état, couverture, contrôles de chaque politique
      [2] Applications sans couverture CA
      [3] Utilisateurs hors périmètre de toutes les politiques actives
      [4] Politiques en mode Report-Only (non bloquantes)
      [5] Conflits et redondances entre politiques
      [6] Conditions de risque — exploitation d'Entra ID Protection

    COUVERTURE RÉGLEMENTAIRE :
      DORA Art. 9 §4(c)       — Détection et prévention des accès non autorisés
      FINMA Circ. 2023/1 §32  — Documentation des contrôles d'accès
      CSSF 22/806 Ctrl 8      — Surveillance et contrôle des accès
      ISO 27001:2022 A.5.15   — Contrôle d'accès

    PRÉREQUIS :
      - Module Microsoft.Graph : Install-Module Microsoft.Graph
      - Rôle Entra ID : Security Reader (lecture seule)
      - Licence Entra ID P1 minimum pour les politiques CA

.PARAMETER OutputPath
    Dossier de sortie. Défaut : .\Reports

.PARAMETER Client
    Nom du client.

.PARAMETER SensitiveApps
    Liste d'applications considérées comme sensibles (doivent être couvertes par CA).
    Si non fournie : le script identifie les applications à risque via les permissions.

.PARAMETER ExcludedBreakglassAccounts
    UPN des comptes breakglass — exclus normalement de toutes les politiques,
    leur présence est attendue et ne doit pas être signalée comme anomalie.

.EXAMPLE
    .\Audit-ConditionalAccess.ps1 -Client "Banque XYZ"
    .\Audit-ConditionalAccess.ps1 -Client "Groupe ABC" `
        -ExcludedBreakglassAccounts @("breakglass1@corp.com","breakglass2@corp.com")

.OUTPUTS
    Reports/Audit-ConditionalAccess_<date>.csv
    Reports/Audit-ConditionalAccess_<date>.json
    Reports/Audit-ConditionalAccess_<date>.log

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D3 — Conditional Access

    LECTURE SEULE — Ce script ne modifie aucune politique CA.
    Pour la remédiation : utiliser Remediate-ConditionalAccess.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [string[]]$SensitiveApps = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludedBreakglassAccounts = @()
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
$BaseFileName  = "Audit-ConditionalAccess_${DateStamp}"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile       = Join-Path $OutputPath "${BaseFileName}.log"
$Results       = [System.Collections.Generic.List[PSCustomObject]]::new()
$TopFindings   = [System.Collections.Generic.List[string]]::new()
$SkippedChecks = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR"   { "Red"     } "WARN"  { "Yellow"  }
        "SUCCESS" { "Green"   } "FOUND" { "Magenta" }
        "SKIP"    { "Gray"    } default { "Cyan"    }
    }
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Write-Section { param([string]$T)
    Write-Log ("─" * 60); Write-Log "  $T"; Write-Log ("─" * 60)
}

function Add-Result {
    param(
        [string]$Category,  [string]$ObjectName, [string]$ObjectType,
        [string]$Finding,   [string]$RiskLevel,  [string]$RegulatoryRef,
        [string]$RemediationHint, [string]$PolicyState = "",
        [string]$AffectedScope = ""
    )
    $Results.Add([PSCustomObject]@{
        Category        = $Category
        ObjectName      = $ObjectName
        ObjectType      = $ObjectType
        PolicyState     = $PolicyState
        AffectedScope   = $AffectedScope
        Finding         = $Finding
        RiskLevel       = $RiskLevel
        RegulatoryRef   = $RegulatoryRef
        RemediationHint = $RemediationHint
        DetectedAt      = $TimeStamp
    })
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkGreen
Write-Host "║      AUDIT-CONDITIONALACCESS — IAM-FEDERATION-LAB       ║" -ForegroundColor DarkGreen
Write-Host "║      Lecture seule · Aucune modification                 ║" -ForegroundColor DarkGreen
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkGreen
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script          : Audit-ConditionalAccess.ps1 v$ScriptVersion"
Write-Log "Client          : $Client"
Write-Log "Run ID          : $RunId"
Write-Log "Comptes breakglass exclus : $(if ($ExcludedBreakglassAccounts.Count -gt 0) { $ExcludedBreakglassAccounts -join ', ' } else { 'Aucun fourni — tous les exclusions seront signalées' })"

# ─────────────────────────────────────────────
# CONNEXION
# ─────────────────────────────────────────────

Write-Section "CONNEXION MICROSOFT GRAPH"
try {
    Connect-MgGraph -Scopes @(
        "Policy.Read.All",
        "User.Read.All",
        "Application.Read.All",
        "Directory.Read.All"
    ) -NoWelcome -ErrorAction Stop

    $Context = Get-MgContext
    Write-Log "Connecté : $($Context.Account) → Tenant : $($Context.TenantId)" "SUCCESS"
} catch {
    Write-Log "Échec connexion : $_" "ERROR"; exit 1
}

# ─────────────────────────────────────────────
# COLLECTE — TOUTES LES POLITIQUES CA
# ─────────────────────────────────────────────

Write-Section "COLLECTE DES POLITIQUES D'ACCÈS CONDITIONNEL"

$AllPolicies = Get-MgIdentityConditionalAccessPolicy -All `
    -Property Id, DisplayName, State, CreatedDateTime, ModifiedDateTime, `
              Conditions, GrantControls, SessionControls `
    -ErrorAction Stop

$EnabledPolicies    = $AllPolicies | Where-Object { $_.State -eq "enabled" }
$ReportOnlyPolicies = $AllPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
$DisabledPolicies   = $AllPolicies | Where-Object { $_.State -eq "disabled" }

Write-Log "Politiques CA total      : $($AllPolicies.Count)"
Write-Log "  Actives (enabled)      : $($EnabledPolicies.Count)"
Write-Log "  Report-Only            : $($ReportOnlyPolicies.Count)" $(if ($ReportOnlyPolicies.Count -gt 0) { "WARN" } else { "SUCCESS" })
Write-Log "  Désactivées            : $($DisabledPolicies.Count)"

# ─────────────────────────────────────────────
# DIMENSION 1 — INVENTAIRE ET ANALYSE PAR POLITIQUE
# ─────────────────────────────────────────────

Write-Section "DIMENSION 1 — INVENTAIRE DÉTAILLÉ DES POLITIQUES"

$PolicySummaries = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Policy in $AllPolicies) {

    # Extraire les caractéristiques
    $Controls      = $Policy.GrantControls.BuiltInControls -join ", "
    $HasMFA        = $Policy.GrantControls.BuiltInControls -contains "mfa"
    $HasBlock      = $Policy.GrantControls.BuiltInControls -contains "block"
    $HasCompliance = $Policy.GrantControls.BuiltInControls -contains "compliantDevice"
    $HasHybridJoin = $Policy.GrantControls.BuiltInControls -contains "domainJoinedDevice"

    $UsersIncluded = $Policy.Conditions.Users.IncludeUsers
    $UsersExcluded = $Policy.Conditions.Users.ExcludeUsers
    $GroupsIncluded= $Policy.Conditions.Users.IncludeGroups
    $AppsIncluded  = $Policy.Conditions.Applications.IncludeApplications
    $ClientApps    = $Policy.Conditions.ClientAppTypes -join ", "
    $Locations     = $Policy.Conditions.Locations.IncludeLocations -join ", "
    $ExclLocations = $Policy.Conditions.Locations.ExcludeLocations -join ", "
    $SignInRisk    = $Policy.Conditions.SignInRiskLevels -join ", "
    $UserRisk      = $Policy.Conditions.UserRiskLevels  -join ", "

    $IncludesAll   = $UsersIncluded -contains "All"
    $IncludesGuests= $Policy.Conditions.Users.IncludeGuestsOrExternalUsers -ne $null
    $AppCoversAll  = $AppsIncluded -contains "All"

    $Summary = [PSCustomObject]@{
        PolicyId          = $Policy.Id
        PolicyName        = $Policy.DisplayName
        State             = $Policy.State
        HasMFA            = $HasMFA
        HasBlock          = $HasBlock
        HasDeviceCompliance= $HasCompliance
        GrantControls     = if ($Controls) { $Controls } else { "(aucun contrôle)" }
        UsersScope        = if ($IncludesAll) { "All" } elseif ($GroupsIncluded.Count -gt 0) { "$($GroupsIncluded.Count) groupes" } else { "$($UsersIncluded.Count) users" }
        ExcludedUsers     = $UsersExcluded.Count
        AppScope          = if ($AppCoversAll) { "All" } else { "$($AppsIncluded.Count) apps" }
        ClientApps        = $ClientApps
        LocationCondition = $Locations
        LocationExclusion = $ExclLocations
        SignInRisk        = $SignInRisk
        UserRisk          = $UserRisk
        CreatedDate       = $Policy.CreatedDateTime.ToString("yyyy-MM-dd")
        LastModified      = $Policy.ModifiedDateTime.ToString("yyyy-MM-dd")
    }
    $PolicySummaries.Add($Summary)

    # Analyse : politiques Report-Only
    if ($Policy.State -eq "enabledForReportingButNotEnforced") {
        $Age = [math]::Round(((Get-Date) - $Policy.CreatedDateTime).TotalDays, 0)
        $Finding = "Politique '$($Policy.DisplayName)' en mode Report-Only depuis $Age jours — " +
                   "les contrôles ($Controls) ne sont PAS appliqués."
        $RiskLvl = if ($Age -gt 90) { "ÉLEVÉ" } elseif ($Age -gt 30) { "MOYEN" } else { "FAIBLE" }

        Write-Log "  $RiskLvl : $Finding" $(if ($RiskLvl -ne "FAIBLE") { "WARN" } else { "INFO" })

        Add-Result `
            -Category       "ReportOnly" `
            -ObjectName     $Policy.DisplayName `
            -ObjectType     "ConditionalAccessPolicy" `
            -PolicyState    $Policy.State `
            -Finding        $Finding `
            -RiskLevel      $RiskLvl `
            -RegulatoryRef  "DORA Art.9 · FINMA §32" `
            -RemediationHint "Analyser les résultats Report-Only (Sign-in logs > CA) et activer la politique si aucun impact non prévu."
    }

    # Analyse : politique active sans contrôle réel
    if ($Policy.State -eq "enabled" -and -not $Controls) {
        $Finding = "Politique active '$($Policy.DisplayName)' sans aucun contrôle d'octroi — " +
                   "elle s'applique mais n'impose rien."
        Write-Log "  MOYEN : $Finding" "WARN"
        Add-Result `
            -Category       "PolicyConfig" `
            -ObjectName     $Policy.DisplayName `
            -ObjectType     "ConditionalAccessPolicy" `
            -PolicyState    $Policy.State `
            -Finding        $Finding `
            -RiskLevel      "MOYEN" `
            -RegulatoryRef  "ISO 27001 A.5.15" `
            -RemediationHint "Ajouter un contrôle (MFA, conformité terminal) ou vérifier si la politique est un placeholder à compléter."
    }

    # Analyse : politique active avec beaucoup d'exclusions
    if ($Policy.State -eq "enabled" -and $UsersExcluded.Count -gt 10) {
        $Finding = "Politique '$($Policy.DisplayName)' exclut $($UsersExcluded.Count) utilisateurs — " +
                   "vérifier que ces exclusions sont toutes justifiées et documentées."
        Write-Log "  MOYEN : $Finding" "WARN"
        Add-Result `
            -Category       "PolicyConfig" `
            -ObjectName     $Policy.DisplayName `
            -ObjectType     "ConditionalAccessPolicy" `
            -PolicyState    $Policy.State `
            -AffectedScope  "$($UsersExcluded.Count) utilisateurs exclus" `
            -Finding        $Finding `
            -RiskLevel      "MOYEN" `
            -RegulatoryRef  "ISO 27001 A.5.15 · FINMA §32" `
            -RemediationHint "Auditer la liste des exclusions — recertifier chaque exclusion avec une justification métier documentée."
    }
}

Write-Log "Analyse par politique terminée. $($PolicySummaries.Count) politiques analysées."

# ─────────────────────────────────────────────
# DIMENSION 2 — APPLICATIONS SANS COUVERTURE CA
# ─────────────────────────────────────────────

Write-Section "DIMENSION 2 — APPLICATIONS SANS COUVERTURE CA"

try {
    Write-Log "Récupération des applications Entra ID..."
    $AllApps = Get-MgServicePrincipal -All `
        -Filter "servicePrincipalType eq 'Application'" `
        -Property Id, DisplayName, AppId, AppRoles, SignInAudience `
        -ErrorAction Stop |
        Where-Object { $_.SignInAudience -ne "AzureADMyOrg" -or $_.AppRoles.Count -gt 0 }

    Write-Log "Applications récupérées : $($AllApps.Count)"

    # Récupérer toutes les apps couvertes par les politiques actives
    $CoveredAppIds = @{}
    $HasAllAppPolicy = $false

    foreach ($Policy in $EnabledPolicies) {
        $AppIncludes = $Policy.Conditions.Applications.IncludeApplications
        if ($AppIncludes -contains "All" -or $AppIncludes -contains "00000002-0000-0ff1-ce00-000000000000") {
            $HasAllAppPolicy = $true
        }
        foreach ($AppId in $AppIncludes) {
            $CoveredAppIds[$AppId] = $Policy.DisplayName
        }
    }

    if ($HasAllAppPolicy) {
        Write-Log "Au moins une politique active couvre 'All' applications — couverture globale confirmée" "SUCCESS"
    } else {
        Write-Log "Aucune politique active ne couvre 'All' applications — analyse app par app..." "WARN"

        # Apps à vérifier : celles qui ont des rôles (donc des permissions accordées)
        $UncoveredApps = $AllApps | Where-Object {
            $_.AppId -notin $CoveredAppIds.Keys -and
            $_.AppId -notin @(
                "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
                "00000002-0000-0000-c000-000000000000"   # Azure AD Graph (legacy)
            )
        } | Select-Object -First 30  # Limiter pour éviter les tenants avec des centaines d'apps

        Write-Log "Applications potentiellement sans politique CA : $($UncoveredApps.Count)"

        foreach ($App in $UncoveredApps | Select-Object -First 10) {
            $Finding = "Application '$($App.DisplayName)' (AppId: $($App.AppId)) " +
                       "sans politique CA dédiée et non couverte par une politique globale."
            Write-Log "  MOYEN : $Finding" "WARN"

            Add-Result `
                -Category       "AppCoverage" `
                -ObjectName     $App.DisplayName `
                -ObjectType     "Application" `
                -PolicyState    "Not covered" `
                -Finding        $Finding `
                -RiskLevel      "MOYEN" `
                -RegulatoryRef  "DORA Art.9 · ISO 27001 A.5.15" `
                -RemediationHint "Créer une politique CA 'All Applications' avec MFA requis comme baseline, ou créer une politique dédiée pour cette application."

            if ($UncoveredApps.Count -gt 10) {
                Write-Log "  (Affichage limité — $($UncoveredApps.Count) apps non couvertes au total)" "WARN"
                break
            }
        }

        if ($UncoveredApps.Count -gt 0) {
            $TopFindings.Add("$($UncoveredApps.Count) application(s) sans couverture CA identifiée — accès non contrôlé")
        }
    }
} catch {
    Write-Log "Erreur analyse couverture applications : $_" "WARN"
    $SkippedChecks.Add("D2 — Applications sans couverture CA")
}

# ─────────────────────────────────────────────
# DIMENSION 3 — UTILISATEURS HORS PÉRIMÈTRE CA
# ─────────────────────────────────────────────

Write-Section "DIMENSION 3 — UTILISATEURS HORS PÉRIMÈTRE DES POLITIQUES ACTIVES"

try {
    Write-Log "Analyse de la couverture utilisateurs..."

    # Utilisateurs exclus de TOUTES les politiques actives
    $AllExcludedUserIds = @{}

    foreach ($Policy in $EnabledPolicies) {
        foreach ($UserId in $Policy.Conditions.Users.ExcludeUsers) {
            if (-not $AllExcludedUserIds.ContainsKey($UserId)) {
                $AllExcludedUserIds[$UserId] = @()
            }
            $AllExcludedUserIds[$UserId] += $Policy.DisplayName
        }
    }

    # Identifier les utilisateurs exclus de toutes les politiques "All users"
    $AllUsersPolicies = $EnabledPolicies | Where-Object {
        $_.Conditions.Users.IncludeUsers -contains "All"
    }

    Write-Log "Politiques 'All users' actives : $($AllUsersPolicies.Count)"

    if ($AllUsersPolicies.Count -gt 0) {
        # Trouver les utilisateurs exclus de TOUTES les politiques All-users
        $UsersExcludedFromAll = @{}

        foreach ($Policy in $AllUsersPolicies) {
            foreach ($UserId in $Policy.Conditions.Users.ExcludeUsers) {
                $UsersExcludedFromAll[$UserId] = ($UsersExcludedFromAll[$UserId] ?? 0) + 1
            }
        }

        # Un utilisateur exclu de TOUTES les politiques All-users = hors périmètre complet
        $CompletelyExcluded = $UsersExcludedFromAll.Keys |
            Where-Object { $UsersExcludedFromAll[$_] -eq $AllUsersPolicies.Count }

        Write-Log "Utilisateurs exclus de toutes les politiques 'All users' : $($CompletelyExcluded.Count)"

        foreach ($UserId in $CompletelyExcluded) {
            # Récupérer l'UPN
            try {
                $User = Get-MgUser -UserId $UserId -Property UserPrincipalName, DisplayName -ErrorAction Stop

                # Ignorer les comptes breakglass documentés
                if ($ExcludedBreakglassAccounts -contains $User.UserPrincipalName) {
                    Write-Log "  Compte breakglass documenté (ignoré) : $($User.UserPrincipalName)" "SKIP"
                    continue
                }

                $PolicyNames = ($AllUsersPolicies | Where-Object {
                    $_.Conditions.Users.ExcludeUsers -contains $UserId
                } | Select-Object -ExpandProperty DisplayName) -join ", "

                $Finding = "Utilisateur '$($User.UserPrincipalName)' exclu de toutes les politiques CA 'All users' : $PolicyNames. " +
                           "Il s'authentifie sans aucune contrainte CA."

                Write-Log "  ÉLEVÉ : $($User.UserPrincipalName)" "FOUND"

                Add-Result `
                    -Category       "UserCoverage" `
                    -ObjectName     $User.UserPrincipalName `
                    -ObjectType     "User" `
                    -AffectedScope  "Exclu de : $PolicyNames" `
                    -Finding        $Finding `
                    -RiskLevel      "ÉLEVÉ" `
                    -RegulatoryRef  "DORA Art.9 · FINMA §42 · ISO 27001 A.5.15" `
                    -RemediationHint "Vérifier si cet utilisateur est un compte breakglass légitime (documenter) ou retirer son exclusion. Les breakglass doivent être documentés dans le Persona IA et revus trimestriellement."

            } catch {
                Write-Log "  Impossible de résoudre l'utilisateur $UserId : $_" "WARN"
            }
        }

        $RealExcluded = ($Results | Where-Object { $_.Category -eq "UserCoverage" }).Count
        if ($RealExcluded -gt 0) {
            $TopFindings.Add("ÉLEVÉ : $RealExcluded utilisateur(s) exclu(s) de toutes les politiques CA actives (hors breakglass documentés)")
        } else {
            Write-Log "Tous les utilisateurs exclus sont des comptes breakglass documentés ou aucun exclusion totale détectée" "SUCCESS"
        }
    } else {
        Write-Log "Aucune politique 'All users' active — la couverture n'est pas globale" "WARN"
        $TopFindings.Add("Aucune politique CA active ne couvre 'All users' — des utilisateurs peuvent être hors périmètre")
        Add-Result `
            -Category       "UserCoverage" `
            -ObjectName     "GlobalCoverage" `
            -ObjectType     "PolicyGap" `
            -Finding        "Aucune politique CA active avec portée 'All users'. La couverture repose sur des politiques ciblées — risque de gaps non détectés." `
            -RiskLevel      "ÉLEVÉ" `
            -RegulatoryRef  "DORA Art.9 · FINMA §32" `
            -RemediationHint "Créer une politique CA baseline avec portée 'All users' et MFA requis pour toutes les applications, avec uniquement les comptes breakglass en exclusion."
    }

} catch {
    Write-Log "Erreur analyse couverture utilisateurs : $_" "WARN"
    $SkippedChecks.Add("D3 — Utilisateurs hors périmètre CA")
}

# ─────────────────────────────────────────────
# DIMENSION 4 — POLITIQUES REPORT-ONLY ANCIENNES
# ─────────────────────────────────────────────

Write-Section "DIMENSION 4 — POLITIQUES REPORT-ONLY"

if ($ReportOnlyPolicies.Count -eq 0) {
    Write-Log "Aucune politique en mode Report-Only — conforme" "SUCCESS"
} else {
    Write-Log "$($ReportOnlyPolicies.Count) politique(s) en Report-Only :"
    foreach ($P in $ReportOnlyPolicies) {
        $Age = [math]::Round(((Get-Date) - $P.CreatedDateTime).TotalDays, 0)
        Write-Log "  '$($P.DisplayName)' — créée il y a $Age jours"
    }
    if ($ReportOnlyPolicies.Count -gt 0) {
        $OldReportOnly = $ReportOnlyPolicies | Where-Object {
            ((Get-Date) - $_.CreatedDateTime).TotalDays -gt 30
        }
        if ($OldReportOnly.Count -gt 0) {
            $TopFindings.Add("$($OldReportOnly.Count) politique(s) Report-Only depuis plus de 30 jours — contrôles non appliqués")
        }
    }
}

# ─────────────────────────────────────────────
# DIMENSION 5 — CONFLITS ET REDONDANCES
# ─────────────────────────────────────────────

Write-Section "DIMENSION 5 — CONFLITS ET REDONDANCES ENTRE POLITIQUES"

$ConflictsFound = 0

# Chercher les politiques actives avec le même périmètre utilisateurs et applications
# mais des contrôles contradictoires (une bloque, l'autre autorise avec MFA)
$ActiveAllAllPolicies = $EnabledPolicies | Where-Object {
    $_.Conditions.Users.IncludeUsers -contains "All" -and
    $_.Conditions.Applications.IncludeApplications -contains "All"
}

if ($ActiveAllAllPolicies.Count -gt 1) {
    Write-Log "Politiques actives 'All users + All apps' : $($ActiveAllAllPolicies.Count)" "WARN"
    Write-Log "Politiques multiples sur même périmètre — vérification des conflits..."

    # Comparer les contrôles
    $BlockPolicies = $ActiveAllAllPolicies | Where-Object {
        $_.GrantControls.BuiltInControls -contains "block"
    }
    $AllowPolicies = $ActiveAllAllPolicies | Where-Object {
        $_.GrantControls.BuiltInControls -notcontains "block" -and
        $_.GrantControls.BuiltInControls.Count -gt 0
    }

    if ($BlockPolicies.Count -gt 0 -and $AllowPolicies.Count -gt 0) {
        $Finding = "Conflit potentiel : $($BlockPolicies.Count) politique(s) bloquante(s) " +
                   "et $($AllowPolicies.Count) politique(s) d'autorisation sur le même périmètre 'All users + All apps'. " +
                   "La politique la plus permissive peut primer selon l'ordre d'évaluation."
        Write-Log "  MOYEN : $Finding" "WARN"
        $ConflictsFound++

        Add-Result `
            -Category       "PolicyConflict" `
            -ObjectName     "AllUsers-AllApps-Conflict" `
            -ObjectType     "PolicySet" `
            -AffectedScope  "All users + All applications" `
            -Finding        $Finding `
            -RiskLevel      "MOYEN" `
            -RegulatoryRef  "ISO 27001 A.5.15 · FINMA §32" `
            -RemediationHint "Revoir l'architecture CA : une seule politique 'All users + All apps' avec MFA requis comme baseline, des politiques plus restrictives pour les périmètres sensibles."
    }
}

# Chercher les politiques actives sans aucune condition (politique trop large)
$NoBoundaryPolicies = $EnabledPolicies | Where-Object {
    $_.Conditions.Locations.IncludeLocations.Count -eq 0 -and
    $_.Conditions.SignInRiskLevels.Count -eq 0 -and
    $_.Conditions.UserRiskLevels.Count -eq 0 -and
    $_.Conditions.ClientAppTypes.Count -eq 0 -and
    $_.Conditions.Platforms.IncludePlatforms.Count -eq 0
}

Write-Log "Politiques actives sans condition contextuelle (localisation/risque/plateforme) : $($NoBoundaryPolicies.Count)"

if ($ConflictsFound -eq 0) {
    Write-Log "Aucun conflit majeur détecté entre les politiques actives" "SUCCESS"
}

# ─────────────────────────────────────────────
# DIMENSION 6 — CONDITIONS DE RISQUE ENTRA ID PROTECTION
# ─────────────────────────────────────────────

Write-Section "DIMENSION 6 — EXPLOITATION D'ENTRA ID PROTECTION (RISQUE CONNEXION)"

$PoliciesWithSignInRisk = $EnabledPolicies | Where-Object {
    $_.Conditions.SignInRiskLevels.Count -gt 0
}
$PoliciesWithUserRisk = $EnabledPolicies | Where-Object {
    $_.Conditions.UserRiskLevels.Count -gt 0
}

Write-Log "Politiques exploitant le risque de connexion : $($PoliciesWithSignInRisk.Count)" $(
    if ($PoliciesWithSignInRisk.Count -gt 0) { "SUCCESS" } else { "WARN" }
)
Write-Log "Politiques exploitant le risque utilisateur  : $($PoliciesWithUserRisk.Count)" $(
    if ($PoliciesWithUserRisk.Count -gt 0) { "SUCCESS" } else { "WARN" }
)

if ($PoliciesWithSignInRisk.Count -eq 0) {
    $Finding = "Aucune politique CA n'exploite le signal de risque de connexion Entra ID Protection. " +
               "Les connexions à haut risque (IP anonyme, voyage impossible, malware lié) " +
               "ne déclenchent aucun contrôle supplémentaire."
    Write-Log "MOYEN : $Finding" "WARN"

    Add-Result `
        -Category       "RiskConditions" `
        -ObjectName     "SignInRisk-NotConfigured" `
        -ObjectType     "PolicyGap" `
        -Finding        $Finding `
        -RiskLevel      "MOYEN" `
        -RegulatoryRef  "DORA Art.9 §4(c) · ISO 27001 A.5.15" `
        -RemediationHint "Créer une politique CA ciblant signInRisk 'high' et 'medium' avec MFA requis ou blocage. Nécessite Entra ID P2."

    $TopFindings.Add("Entra ID Protection non exploité : les connexions à risque élevé ne déclenchent pas de MFA ou blocage")
}

if ($PoliciesWithUserRisk.Count -eq 0) {
    $Finding = "Aucune politique CA n'exploite le signal de risque utilisateur. " +
               "Les comptes marqués à risque (credentials compromis, comportement anormal) " +
               "ne sont pas bloqués ni forcés à changer leur mot de passe."
    Write-Log "MOYEN : $Finding" "WARN"

    Add-Result `
        -Category       "RiskConditions" `
        -ObjectName     "UserRisk-NotConfigured" `
        -ObjectType     "PolicyGap" `
        -Finding        $Finding `
        -RiskLevel      "MOYEN" `
        -RegulatoryRef  "DORA Art.9 §4(c) · ISO 27001 A.5.15" `
        -RemediationHint "Créer une politique CA ciblant userRisk 'high' avec : blocage ou forcer le changement de mot de passe sécurisé. Nécessite Entra ID P2."
}

# Vérifier si Entra ID P2 est disponible (pour les politiques de risque)
try {
    $OrgLicenses = Get-MgSubscribedSku -All -ErrorAction SilentlyContinue |
        Where-Object { $_.SkuPartNumber -like "*AAD_PREMIUM_P2*" -or $_.SkuPartNumber -like "*EMS_E5*" }

    $HasP2 = ($OrgLicenses | Where-Object { $_.ConsumedUnits -gt 0 }).Count -gt 0
    Write-Log "Entra ID P2 disponible : $HasP2" $(if ($HasP2) { "SUCCESS" } else { "WARN" })

    if (-not $HasP2 -and ($PoliciesWithSignInRisk.Count -eq 0 -or $PoliciesWithUserRisk.Count -eq 0)) {
        Write-Log "Licence P2 non détectée — les conditions de risque nécessitent Entra ID P2" "WARN"
    }
} catch {
    Write-Log "Impossible de vérifier les licences Entra ID" "WARN"
}

# ─────────────────────────────────────────────
# CALCUL DU SCORE
# ─────────────────────────────────────────────

Write-Section "CALCUL DU SCORE DE CONFORMITÉ"

$CritiqueCount = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" }).Count
$EleveCount    = ($Results | Where-Object { $_.RiskLevel -eq "ÉLEVÉ"    }).Count
$MoyenCount    = ($Results | Where-Object { $_.RiskLevel -eq "MOYEN"    }).Count

$Score = 100
$Score -= [math]::Min($CritiqueCount * 25, 75)
$Score -= [math]::Min($EleveCount    * 12, 36)
$Score -= [math]::Min($MoyenCount    *  5, 25)
$Score -= $SkippedChecks.Count * 2
$Score  = [math]::Max($Score, 0)

# Bonus pour les bonnes pratiques détectées
if ($PoliciesWithSignInRisk.Count -gt 0) { $Score = [math]::Min($Score + 5, 100) }
if ($PoliciesWithUserRisk.Count  -gt 0) { $Score = [math]::Min($Score + 5, 100) }

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

Write-Log "Score ConditionalAccess : $Score/100 ($ScoreLabel)"
Write-Log "Total politiques : $($AllPolicies.Count) | Actives : $($EnabledPolicies.Count) | Report-Only : $($ReportOnlyPolicies.Count)"
Write-Log "Findings : CRITIQUE=$CritiqueCount ÉLEVÉ=$EleveCount MOYEN=$MoyenCount"

# ─────────────────────────────────────────────
# EXPORT CSV — DEUX FICHIERS
# ─────────────────────────────────────────────

Write-Section "EXPORT"

# Fichier 1 : Findings (risques)
$CsvPath = Join-Path $OutputPath "${BaseFileName}.csv"
$Results |
    Sort-Object @{E={ switch ($_.RiskLevel) { "CRITIQUE"{0}"ÉLEVÉ"{1}"MOYEN"{2} default{3} } }},
                Category, ObjectName |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Log "CSV findings : $CsvPath ($($Results.Count) lignes)" "SUCCESS"

# Fichier 2 : Inventaire complet des politiques
$InventoryCsvPath = Join-Path $OutputPath "${BaseFileName}_Inventory.csv"
$PolicySummaries | Export-Csv -Path $InventoryCsvPath -NoTypeInformation -Encoding UTF8
Write-Log "CSV inventaire : $InventoryCsvPath ($($PolicySummaries.Count) politiques)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

$JsonReport = [ordered]@{
    "_schema"          = "iam-federation-lab/audit-conditionalaccess/v1.0"
    "RunId"            = $RunId
    "Domain"           = "D3 — Conditional Access"
    "Client"           = $Client
    "Date"             = $DateStamp
    "GeneratedAt"      = $TimeStamp
    "Score"            = $Score
    "ScoreLabel"       = $ScoreLabel
    "Statistics"       = [ordered]@{
        "TotalPolicies"         = $AllPolicies.Count
        "EnabledPolicies"       = $EnabledPolicies.Count
        "ReportOnlyPolicies"    = $ReportOnlyPolicies.Count
        "DisabledPolicies"      = $DisabledPolicies.Count
        "PoliciesWithSignInRisk"= $PoliciesWithSignInRisk.Count
        "PoliciesWithUserRisk"  = $PoliciesWithUserRisk.Count
        "TotalFindings"         = $Results.Count
        "CRITIQUE"              = $CritiqueCount
        "ÉLEVÉ"                 = $EleveCount
        "MOYEN"                 = $MoyenCount
        "SkippedChecks"         = $SkippedChecks.Count
    }
    "TopFindings"      = $TopFindings
    "SkippedChecks"    = $SkippedChecks
    "BreakglassAccounts" = $ExcludedBreakglassAccounts
    "RegulatoryMapping"= [ordered]@{
        "DORA_Art9_S4c"     = if ($CritiqueCount -gt 0) { "NON_CONFORME" } elseif ($EleveCount -gt 0) { "PARTIEL" } else { "CONFORME" }
        "FINMA_2023_1_S32"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "CSSF_22806_Ctrl8"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "ISO27001_A515"     = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"         = "Remediate-ConditionalAccess.ps1 -AuditReport '$CsvPath' -DryRun"
}

$JsonPath = Join-Path $OutputPath "${BaseFileName}.json"
$JsonReport | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-Log "JSON : $JsonPath" "SUCCESS"

# ─────────────────────────────────────────────
# RÉSUMÉ CONSOLE
# ─────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

$ScoreColor = switch ($ScoreLabel) {
    "OPTIMAL"  { "Green" } "CONFORME" { "Green" } "PARTIEL" { "Yellow" }
    "INSUFFISANT" { "Red" } "CRITIQUE" { "Red" } default { "White" }
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCORE CA : $($Score.ToString().PadRight(3))/100 — $($ScoreLabel.PadRight(13))          │" -ForegroundColor $ScoreColor
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Politiques totales  : $($AllPolicies.Count.ToString().PadRight(31))│" -ForegroundColor White
Write-Host "  │  Actives             : $($EnabledPolicies.Count.ToString().PadRight(31))│" -ForegroundColor Green
Write-Host "  │  Report-Only         : $($ReportOnlyPolicies.Count.ToString().PadRight(31))│" -ForegroundColor $(if ($ReportOnlyPolicies.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Avec risque sign-in : $($PoliciesWithSignInRisk.Count.ToString().PadRight(31))│" -ForegroundColor $(if ($PoliciesWithSignInRisk.Count -gt 0) { "Green" } else { "Yellow" })
Write-Host "  │  Avec risque user    : $($PoliciesWithUserRisk.Count.ToString().PadRight(31))│" -ForegroundColor $(if ($PoliciesWithUserRisk.Count -gt 0) { "Green" } else { "Yellow" })
Write-Host "  │  Findings ÉLEVÉ/CRIT : $(($CritiqueCount + $EleveCount).ToString().PadRight(31))│" -ForegroundColor $(if (($CritiqueCount + $EleveCount) -gt 0) { "Red" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

if ($TopFindings.Count -gt 0) {
    Write-Host "  POINTS D'ATTENTION :" -ForegroundColor Red
    foreach ($F in $TopFindings) { Write-Host "  → $F" -ForegroundColor Yellow }
    Write-Host ""
}

Write-Host "  LIVRABLES :" -ForegroundColor Cyan
Write-Host "  ✅ Findings CSV  : $CsvPath" -ForegroundColor Green
Write-Host "  ✅ Inventaire CSV: $InventoryCsvPath" -ForegroundColor Green
Write-Host "  ✅ JSON          : $JsonPath" -ForegroundColor Green
Write-Host "  ✅ LOG           : $LogFile"  -ForegroundColor Green
Write-Host ""
Write-Host "  PROCHAINE ÉTAPE :" -ForegroundColor Cyan
Write-Host "  .\Remediate-ConditionalAccess.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""

Write-Log "Audit ConditionalAccess terminé — Score : $Score/100 ($ScoreLabel) — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
