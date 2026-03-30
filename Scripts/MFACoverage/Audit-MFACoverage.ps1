<#
.SYNOPSIS
    Audit de couverture MFA — Lecture seule absolue.

.DESCRIPTION
    Audit-MFACoverage.ps1 cartographie l'état de l'authentification multi-facteurs
    sur l'ensemble du tenant Entra ID hybride.

    Ce script ne modifie rien. Il lit, mesure, et produit trois livrables :
      - CSV  : données brutes par utilisateur (toutes méthodes MFA détectées)
      - JSON : score de conformité structuré + top findings
      - LOG  : journal d'exécution horodaté

    Les livrables sont scellables via iam-evidence-sealer (Invoke-SecureAudit.ps1).

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42  — Intégrité des données d'authentification
      CSSF 22/806 Ctrl 7      — Non-répudiation, gestion des identités et accès
      DORA Art. 9 §4(b)       — Protection contre la manipulation des données
      ISO 27001:2022 A.8.5    — Authentification sécurisée

    PRÉREQUIS :
      - Module Microsoft.Graph (Install-Module Microsoft.Graph)
      - Rôle Entra ID : Security Reader ou Reports Reader (lecture seule)
      - PowerShell 5.1+ ou 7+

.PARAMETER OutputPath
    Dossier de sortie pour les rapports.
    Défaut : .\Reports

.PARAMETER Client
    Nom du client — intégré dans le JSON et le log.
    Défaut : [CLIENT]

.PARAMETER InactiveDays
    Seuil en jours pour qualifier un compte comme "inactif".
    Défaut : 90

.PARAMETER ExportAll
    Si activé, exporte tous les comptes y compris les conformes.
    Par défaut, le CSV contient uniquement les comptes à risque.

.PARAMETER Verbose
    Affiche le détail de chaque compte traité pendant l'exécution.

.EXAMPLE
    .\Audit-MFACoverage.ps1 -Client "Banque XYZ"
    .\Audit-MFACoverage.ps1 -Client "Assurance ABC" -ExportAll -OutputPath "C:\Missions\2026-03"

.OUTPUTS
    Reports/Audit-MFACoverage_<date>.csv
    Reports/Audit-MFACoverage_<date>.json
    Reports/Audit-MFACoverage_<date>.log

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D1 — Couverture MFA

    LECTURE SEULE — Ce script ne modifie aucun objet dans Entra ID ou Active Directory.
    Pour la remédiation : utiliser Remediate-MFACoverage.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$ExportAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

$ScriptVersion  = "1.0"
$DateStamp      = Get-Date -Format "yyyy-MM-dd"
$TimeStamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$RunId          = [System.Guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
$BaseFileName   = "Audit-MFACoverage_${DateStamp}"
$InactiveThreshold = (Get-Date).AddDays(-$InactiveDays)

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile = Join-Path $OutputPath "${BaseFileName}.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR" { "Red" } "WARN" { "Yellow" } "SUCCESS" { "Green" } default { "Cyan" }
    }
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Write-Section {
    param([string]$Title)
    $Sep = "─" * 60
    Write-Log $Sep
    Write-Log "  $Title"
    Write-Log $Sep
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkBlue
Write-Host "║         AUDIT-MFACOVERAGE — IAM-FEDERATION-LAB          ║" -ForegroundColor DarkBlue
Write-Host "║         Lecture seule · Aucune modification              ║" -ForegroundColor DarkBlue
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkBlue
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script      : Audit-MFACoverage.ps1 v$ScriptVersion"
Write-Log "Client      : $Client"
Write-Log "Run ID      : $RunId"
Write-Log "Date        : $TimeStamp"
Write-Log "Seuil inactif : $InactiveDays jours"
Write-Log "Mode export : $(if ($ExportAll) { 'Tous les comptes' } else { 'Comptes à risque uniquement' })"

# ─────────────────────────────────────────────
# VÉRIFICATION DES PRÉREQUIS
# ─────────────────────────────────────────────

Write-Section "VÉRIFICATION DES PRÉREQUIS"

# Module Microsoft.Graph
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Log "Module Microsoft.Graph.Users non installé" "ERROR"
    Write-Log "→ Exécuter : Install-Module Microsoft.Graph -Scope CurrentUser" "WARN"
    exit 1
}

# Connexion Entra ID
Write-Log "Connexion à Microsoft Graph..."
try {
    Connect-MgGraph -Scopes `
        "User.Read.All",
        "UserAuthenticationMethod.Read.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All" `
        -NoWelcome -ErrorAction Stop

    $Context = Get-MgContext
    Write-Log "Connecté : $($Context.Account) → Tenant : $($Context.TenantId)" "SUCCESS"
} catch {
    Write-Log "Échec de connexion à Microsoft Graph : $_" "ERROR"
    Write-Log "→ Vérifier les permissions du compte utilisé (Security Reader minimum)" "WARN"
    exit 1
}

# ─────────────────────────────────────────────
# COLLECTE — UTILISATEURS ACTIFS
# ─────────────────────────────────────────────

Write-Section "COLLECTE DES UTILISATEURS"

Write-Log "Récupération des utilisateurs actifs..."

$AllUsers = Get-MgUser -All `
    -Filter "accountEnabled eq true and userType eq 'Member'" `
    -Property Id, UserPrincipalName, DisplayName, Department, JobTitle, `
              CreatedDateTime, SignInActivity, AssignedLicenses `
    -ErrorAction Stop

Write-Log "Utilisateurs actifs récupérés : $($AllUsers.Count)" "SUCCESS"

# ─────────────────────────────────────────────
# COLLECTE — POLITIQUES MFA
# ─────────────────────────────────────────────

Write-Section "COLLECTE DES POLITIQUES MFA"

# Politiques d'accès conditionnel
Write-Log "Récupération des politiques d'accès conditionnel..."
$CAPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
Write-Log "Politiques CA trouvées : $($CAPolicies.Count)"

# Politique MFA par défaut (Security Defaults)
Write-Log "Vérification des Security Defaults..."
try {
    $SecurityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
    $SecurityDefaultsEnabled = $SecurityDefaults.IsEnabled
    Write-Log "Security Defaults : $(if ($SecurityDefaultsEnabled) { 'ACTIVÉS' } else { 'Désactivés' })"
} catch {
    $SecurityDefaultsEnabled = $false
    Write-Log "Impossible de lire les Security Defaults" "WARN"
}

# Politiques CA qui exigent le MFA
$MFARequiringPolicies = $CAPolicies | Where-Object {
    $_.State -eq "enabled" -and
    $_.GrantControls.BuiltInControls -contains "mfa"
}
Write-Log "Politiques CA exigeant le MFA (actives) : $($MFARequiringPolicies.Count)"

# Exclusions des politiques MFA — comptes en exception
$ExcludedUserIds = @{}
foreach ($Policy in $MFARequiringPolicies) {
    foreach ($UserId in $Policy.Conditions.Users.ExcludeUsers) {
        $ExcludedUserIds[$UserId] = $Policy.DisplayName
    }
}
Write-Log "Comptes exclus des politiques MFA : $($ExcludedUserIds.Count)"

# ─────────────────────────────────────────────
# ANALYSE PAR UTILISATEUR
# ─────────────────────────────────────────────

Write-Section "ANALYSE PAR UTILISATEUR"
Write-Log "Analyse des méthodes MFA pour $($AllUsers.Count) comptes..."
Write-Log "Cette opération peut prendre plusieurs minutes selon la taille du tenant."

$Results      = [System.Collections.Generic.List[PSCustomObject]]::new()
$Counter      = 0
$ErrorCount   = 0

foreach ($User in $AllUsers) {
    $Counter++
    if ($Counter % 50 -eq 0) {
        Write-Log "Progression : $Counter/$($AllUsers.Count) comptes analysés..."
    }

    # Méthodes d'authentification enregistrées
    $AuthMethods     = @()
    $MFARegistered   = $false
    $MFAStrength     = "AUCUNE"
    $MFAMethodsList  = ""
    $HasFIDO2        = $false
    $HasAuthApp      = $false
    $HasSMSOnly      = $false
    $HasWindowsHello = $false

    try {
        $Methods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop

        foreach ($Method in $Methods) {
            $MethodType = $Method.AdditionalProperties["@odata.type"]
            switch ($MethodType) {
                "#microsoft.graph.fido2AuthenticationMethod"           { $AuthMethods += "FIDO2"; $HasFIDO2 = $true }
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { $AuthMethods += "AuthenticatorApp"; $HasAuthApp = $true }
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { $AuthMethods += "WindowsHello"; $HasWindowsHello = $true }
                "#microsoft.graph.phoneAuthenticationMethod"           { $AuthMethods += "Phone/SMS" }
                "#microsoft.graph.emailAuthenticationMethod"           { $AuthMethods += "Email" }
                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { $AuthMethods += "TempAccessPass" }
                "#microsoft.graph.softwareOathAuthenticationMethod"    { $AuthMethods += "TOTP" }
                "#microsoft.graph.passwordAuthenticationMethod"        { } # Mot de passe seul — ne compte pas comme MFA
            }
        }

        # Détermination de la force MFA
        $MFARegistered = $AuthMethods.Count -gt 0

        if ($HasFIDO2 -or $HasWindowsHello) {
            $MFAStrength = "FORT"        # Résistant au phishing
        } elseif ($HasAuthApp) {
            $MFAStrength = "MOYEN"       # Vulnerable à MFA fatigue mais acceptable
        } elseif ($AuthMethods.Count -gt 0) {
            $MFAStrength = "FAIBLE"      # SMS/Email — interceptables
            $HasSMSOnly  = $true
        } else {
            $MFAStrength = "AUCUNE"
        }

        $MFAMethodsList = $AuthMethods -join " | "

    } catch {
        $ErrorCount++
        Write-Log "Erreur lecture méthodes MFA pour $($User.UserPrincipalName) : $_" "WARN"
        $MFAStrength    = "ERREUR_LECTURE"
        $MFAMethodsList = "ERREUR_LECTURE"
    }

    # Dernière connexion
    $LastSignIn     = $User.SignInActivity.LastSignInDateTime
    $DaysSinceSignIn = if ($LastSignIn) {
        [math]::Round(((Get-Date) - $LastSignIn).TotalDays, 0)
    } else { 999 }

    $IsInactive = ($DaysSinceSignIn -ge $InactiveDays)

    # Exclusion des politiques MFA
    $ExcludedFromPolicy  = $ExcludedUserIds.ContainsKey($User.Id)
    $ExcludedPolicyName  = if ($ExcludedFromPolicy) { $ExcludedUserIds[$User.Id] } else { "" }

    # Calcul du niveau de risque
    $RiskLevel = switch ($true) {
        { -not $MFARegistered -and $ExcludedFromPolicy }    { "CRITIQUE" ; break }
        { -not $MFARegistered }                             { "ÉLEVÉ"   ; break }
        { $HasSMSOnly }                                     { "MOYEN"   ; break }
        { $MFAStrength -eq "MOYEN" }                        { "FAIBLE"  ; break }
        { $MFAStrength -eq "FORT" }                         { "CONFORME"; break }
        default                                             { "INCONNU" }
    }

    # Licences (résumé)
    $HasLicense = ($User.AssignedLicenses.Count -gt 0)

    $Record = [PSCustomObject]@{
        UPN                  = $User.UserPrincipalName
        DisplayName          = $User.DisplayName
        Department           = $User.Department
        JobTitle             = $User.JobTitle
        AccountEnabled       = $true
        HasLicense           = $HasLicense
        MFARegistered        = $MFARegistered
        MFAMethods           = $MFAMethodsList
        MFAStrength          = $MFAStrength
        HasFIDO2             = $HasFIDO2
        HasAuthenticatorApp  = $HasAuthApp
        HasWindowsHello      = $HasWindowsHello
        HasSMSOnly           = $HasSMSOnly
        ExcludedFromMFAPolicy = $ExcludedFromPolicy
        ExcludedPolicyName   = $ExcludedPolicyName
        LastSignIn           = if ($LastSignIn) { $LastSignIn.ToString("yyyy-MM-dd") } else { "JAMAIS" }
        DaysSinceSignIn      = $DaysSinceSignIn
        IsInactive           = $IsInactive
        RiskLevel            = $RiskLevel
    }

    # Filtre si ExportAll désactivé : n'exporter que les comptes à risque
    if ($ExportAll -or $RiskLevel -in @("CRITIQUE", "ÉLEVÉ", "MOYEN", "INCONNU", "ERREUR_LECTURE")) {
        $Results.Add($Record)
    }

    if ($VerbosePreference -eq "Continue") {
        Write-Log "  $($User.UserPrincipalName) → MFA: $MFARegistered | Force: $MFAStrength | Risque: $RiskLevel"
    }
}

Write-Log "Analyse terminée. Erreurs de lecture : $ErrorCount / $($AllUsers.Count)" $(if ($ErrorCount -gt 0) { "WARN" } else { "SUCCESS" })

# ─────────────────────────────────────────────
# CALCUL DU SCORE ET DES INDICATEURS
# ─────────────────────────────────────────────

Write-Section "CALCUL DU SCORE DE CONFORMITÉ"

$TotalUsers     = $AllUsers.Count
$WithMFA        = ($Results | Where-Object { $_.MFARegistered -eq $true }).Count
$WithoutMFA     = ($Results | Where-Object { $_.MFARegistered -eq $false -and $_.RiskLevel -ne "ERREUR_LECTURE" }).Count
$CritiqueCount  = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" }).Count
$EleveCount     = ($Results | Where-Object { $_.RiskLevel -eq "ÉLEVÉ" }).Count
$MoyenCount     = ($Results | Where-Object { $_.RiskLevel -eq "MOYEN" }).Count
$ConformeCount  = ($Results | Where-Object { $_.RiskLevel -eq "CONFORME" }).Count
$FortCount      = ($Results | Where-Object { $_.MFAStrength -eq "FORT" }).Count
$SMSOnlyCount   = ($Results | Where-Object { $_.HasSMSOnly -eq $true }).Count
$ExclusCount    = ($Results | Where-Object { $_.ExcludedFromMFAPolicy -eq $true }).Count
$InactifCount   = ($Results | Where-Object { $_.IsInactive -eq $true }).Count

# Score : basé sur le taux de couverture MFA pondéré par la force
# Pondération : FORT = 1.0, MOYEN = 0.8, FAIBLE = 0.4, AUCUNE = 0.0
$WeightedCompliant = ($FortCount * 1.0) + (($WithMFA - $FortCount - $SMSOnlyCount) * 0.8) + ($SMSOnlyCount * 0.4)
$Score = if ($TotalUsers -gt 0) {
    [math]::Round(($WeightedCompliant / $TotalUsers) * 100, 0)
} else { 0 }

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

# Top findings
$TopFindings = [System.Collections.Generic.List[string]]::new()

if ($CritiqueCount -gt 0) {
    $CritiqueUsers = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" } | Select-Object -First 3 -ExpandProperty UPN) -join ", "
    $TopFindings.Add("$CritiqueCount compte(s) CRITIQUE : exclus des politiques MFA ET sans méthode enregistrée → $CritiqueUsers")
}
if ($WithoutMFA -gt 0) {
    $TopFindings.Add("$WithoutMFA compte(s) actifs sans aucune méthode MFA enregistrée")
}
if ($SMSOnlyCount -gt 0) {
    $TopFindings.Add("$SMSOnlyCount compte(s) avec SMS comme unique méthode MFA — méthode interceptable (SIM swap)")
}
if ($ExclusCount -gt 0) {
    $TopFindings.Add("$ExclusCount compte(s) exclus des politiques MFA — justification à documenter")
}
if ($InactifCount -gt 0) {
    $TopFindings.Add("$InactifCount compte(s) inactifs depuis plus de $InactiveDays jours avec des méthodes MFA enregistrées")
}
if ($FortCount -lt ($TotalUsers * 0.5)) {
    $TopFindings.Add("Moins de 50% des comptes utilisent une méthode MFA forte (FIDO2 / Windows Hello)")
}

# Répartition par département
$ByDept = $Results | Where-Object { $_.RiskLevel -in @("CRITIQUE", "ÉLEVÉ") } |
    Group-Object Department |
    Sort-Object Count -Descending |
    Select-Object -First 5

$DeptSummary = $ByDept | ForEach-Object { "$($_.Name) : $($_.Count) compte(s) à risque" }

Write-Log "Score de conformité MFA : $Score/100 ($ScoreLabel)"
Write-Log "Total comptes analysés  : $TotalUsers"
Write-Log "Avec MFA                : $WithMFA ($([math]::Round($WithMFA/$TotalUsers*100,1))%)"
Write-Log "Sans MFA                : $WithoutMFA"
Write-Log "MFA fort (FIDO2/WHfB)   : $FortCount"
Write-Log "SMS uniquement          : $SMSOnlyCount"
Write-Log "Exclus des politiques   : $ExclusCount"
Write-Log "CRITIQUE                : $CritiqueCount"

# ─────────────────────────────────────────────
# EXPORT CSV
# ─────────────────────────────────────────────

Write-Section "EXPORT CSV"

$CsvPath = Join-Path $OutputPath "${BaseFileName}.csv"

$Results |
    Sort-Object @{E={
        switch ($_.RiskLevel) {
            "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } "MOYEN" { 2 }
            "FAIBLE"   { 3 } "CONFORME" { 4 } default { 5 }
        }
    }}, UPN |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Log "CSV exporté : $CsvPath ($($Results.Count) lignes)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

Write-Section "EXPORT JSON"

$JsonReport = [ordered]@{
    "_schema"           = "iam-federation-lab/audit-mfacoverage/v1.0"
    "RunId"             = $RunId
    "Domain"            = "D1 — MFA Coverage"
    "Client"            = $Client
    "Date"              = $DateStamp
    "GeneratedAt"       = $TimeStamp
    "Score"             = $Score
    "ScoreLabel"        = $ScoreLabel
    "SecurityDefaults"  = $SecurityDefaultsEnabled
    "Statistics"        = [ordered]@{
        "TotalUsersAnalyzed"  = $TotalUsers
        "WithMFA"             = $WithMFA
        "WithoutMFA"          = $WithoutMFA
        "MFAStrong"           = $FortCount
        "MFASMSOnly"          = $SMSOnlyCount
        "ExcludedFromPolicy"  = $ExclusCount
        "InactiveWithMFA"     = $InactifCount
        "ErrorsReading"       = $ErrorCount
        "CoveragePercent"     = [math]::Round($WithMFA / $TotalUsers * 100, 1)
    }
    "RiskBreakdown"     = [ordered]@{
        "CRITIQUE"    = $CritiqueCount
        "ÉLEVÉ"       = $EleveCount
        "MOYEN"       = $MoyenCount
        "CONFORME"    = $ConformeCount
    }
    "TopFindings"       = $TopFindings
    "TopRiskyDepts"     = $DeptSummary
    "MFAPolicies"       = [ordered]@{
        "TotalCAPolicies"       = $CAPolicies.Count
        "MFARequiringPolicies"  = $MFARequiringPolicies.Count
        "ExcludedUsers"         = $ExclusCount
    }
    "RegulatoryMapping" = [ordered]@{
        "FINMA_2023_1_S42"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "CSSF_22806_Ctrl7"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "DORA_Art9_S4b"     = if ($WithoutMFA -eq 0) { "CONFORME" } elseif ($CritiqueCount -eq 0) { "PARTIEL" } else { "NON_CONFORME" }
        "ISO27001_A85"      = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"          = "Remediate-MFACoverage.ps1 -AuditReport '$CsvPath' -DryRun"
}

$JsonPath = Join-Path $OutputPath "${BaseFileName}.json"
$JsonReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8

Write-Log "JSON exporté : $JsonPath" "SUCCESS"

# ─────────────────────────────────────────────
# RÉSUMÉ CONSOLE
# ─────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

$ScoreColor = switch ($ScoreLabel) {
    "OPTIMAL"     { "Green"  }
    "CONFORME"    { "Green"  }
    "PARTIEL"     { "Yellow" }
    "INSUFFISANT" { "Red"    }
    "CRITIQUE"    { "Red"    }
    default       { "White"  }
}

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCORE MFA : $Score/100 — $ScoreLabel$((' ' * (14 - $ScoreLabel.Length)))│" -ForegroundColor $ScoreColor
Write-Host "  ├─────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Total comptes      : $($TotalUsers.ToString().PadRight(22))│" -ForegroundColor White
Write-Host "  │  Avec MFA           : $($WithMFA.ToString().PadRight(22))│" -ForegroundColor White
Write-Host "  │  Sans MFA           : $($WithoutMFA.ToString().PadRight(22))│" -ForegroundColor $(if ($WithoutMFA -gt 0) { "Red" } else { "Green" })
Write-Host "  │  MFA fort (FIDO2/WHfB): $($FortCount.ToString().PadRight(20))│" -ForegroundColor White
Write-Host "  │  SMS uniquement     : $($SMSOnlyCount.ToString().PadRight(22))│" -ForegroundColor $(if ($SMSOnlyCount -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  CRITIQUE           : $($CritiqueCount.ToString().PadRight(22))│" -ForegroundColor $(if ($CritiqueCount -gt 0) { "Red" } else { "Green" })
Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

if ($TopFindings.Count -gt 0) {
    Write-Host "  POINTS D'ATTENTION :" -ForegroundColor Yellow
    foreach ($Finding in $TopFindings) {
        Write-Host "  → $Finding" -ForegroundColor Yellow
    }
    Write-Host ""
}

Write-Host "  LIVRABLES :" -ForegroundColor Cyan
Write-Host "  ✅ CSV  : $CsvPath" -ForegroundColor Green
Write-Host "  ✅ JSON : $JsonPath" -ForegroundColor Green
Write-Host "  ✅ LOG  : $LogFile" -ForegroundColor Green
Write-Host ""
Write-Host "  PROCHAINE ÉTAPE :" -ForegroundColor Cyan
Write-Host "  .\Remediate-MFACoverage.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""
Write-Host "  SCELLAGE (iam-evidence-sealer) :" -ForegroundColor Cyan
Write-Host "  .\Invoke-SecureAudit.ps1 -ScriptPath '.\audit\Audit-MFACoverage.ps1' -Client '$Client' -Sign -Timestamp" -ForegroundColor White
Write-Host ""

Write-Log "Audit MFA Coverage terminé — Run ID : $RunId" "SUCCESS"

Disconnect-MgGraph -ErrorAction SilentlyContinue
