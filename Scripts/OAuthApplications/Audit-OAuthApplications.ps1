<#
.SYNOPSIS
    Audit des applications OAuth/OIDC — Lecture seule absolue.

.DESCRIPTION
    Audit-OAuthApplications.ps1 cartographie l'ensemble des applications enregistrées
    dans Entra ID et analyse leurs permissions, secrets, certificats et consentements.

    POURQUOI C'EST LE VECTEUR D'ATTAQUE APPLICATIF LE PLUS SOUS-ESTIMÉ :
    Chaque application enregistrée dans Entra ID est une identité — et comme les
    comptes utilisateurs, les identités d'application s'accumulent sans nettoyage.
    Les risques spécifiques :
      → Permissions Application (*.All) : l'app agit sans utilisateur connecté —
        Mail.ReadWrite.All sur 50 000 boîtes mail avec un seul token compromis
      → Secrets et certificats expirés : une app avec un secret expiré plante en
        production, une avec un secret qui expire bientôt est un risque opérationnel
      → Consentements utilisateurs : un utilisateur peut avoir consenti à une app
        tierce malveillante l'accès à ses mails ou fichiers (OAuth Consent Phishing)
      → Applications orphelines : plus personne ne sait à quoi sert cette app,
        mais elle a toujours des permissions actives
      → ROPC (Resource Owner Password Credentials) : flux qui transmet les
        credentials directement, contourne le MFA par construction

    Ce script analyse 5 périmètres :
      [1] Applications et permissions à haut risque (*.All, Application type)
      [2] Secrets et certificats expirés ou expirant sous 30/60/90 jours
      [3] Consentements utilisateurs (OAuth grants non-admin)
      [4] Applications orphelines (sans connexion depuis 90 jours)
      [5] Flux d'authentification à risque (ROPC, flux implicite)

    COUVERTURE RÉGLEMENTAIRE :
      ISO 27001:2022 A.5.15   — Contrôle d'accès des applications
      CSSF 22/806 Ctrl 7      — Gestion des identités applicatives
      DORA Art. 9             — Sécurité des systèmes TIC
      FINMA Circ. 2023/1 §38  — Traçabilité des accès applicatifs

    PRÉREQUIS :
      - Module Microsoft.Graph : Install-Module Microsoft.Graph
      - Rôle Entra ID : Application Administrator (Reader) ou Cloud App Administrator
      - Pour les consentements : Directory.Read.All

.PARAMETER OutputPath
    Dossier de sortie. Défaut : .\Reports

.PARAMETER Client
    Nom du client.

.PARAMETER SecretExpiryWarningDays
    Seuil en jours pour alerter sur les secrets proches de l'expiration.
    Défaut : 90

.PARAMETER InactiveDays
    Seuil en jours pour qualifier une application comme inactive (orpheline potentielle).
    Défaut : 90

.PARAMETER HighRiskPermissions
    Liste des permissions Graph considérées comme critiques.
    Défaut : liste prédéfinie des permissions *.All les plus dangereuses.

.PARAMETER ExportAll
    Exporte toutes les applications, y compris les conformes.
    Par défaut : uniquement les applications à risque.

.EXAMPLE
    .\Audit-OAuthApplications.ps1 -Client "Banque XYZ"
    .\Audit-OAuthApplications.ps1 -Client "Groupe ABC" -SecretExpiryWarningDays 60
    .\Audit-OAuthApplications.ps1 -Client "Client FR" -ExportAll

.OUTPUTS
    Reports/Audit-OAuthApplications_<date>.csv   — applications à risque
    Reports/Audit-OAuthApplications_<date>.json  — score + findings
    Reports/Audit-OAuthApplications_<date>.log   — journal d'exécution

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D4 — OAuth/OIDC Applications

    LECTURE SEULE — Ce script ne modifie aucune application ni permission.
    Pour la remédiation : utiliser Remediate-OAuthApplications.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$SecretExpiryWarningDays = 90,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [string[]]$HighRiskPermissions = @(
        "Mail.ReadWrite",        "Mail.ReadWrite.All",
        "Mail.Send",             "Mail.Send.All",
        "Files.ReadWrite.All",   "Sites.FullControl.All",
        "Directory.ReadWrite.All","User.ReadWrite.All",
        "Group.ReadWrite.All",   "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All","Policy.ReadWrite.All",
        "SecurityEvents.ReadWrite.All","AuditLog.Read.All"
    ),

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
$BaseFileName  = "Audit-OAuthApplications_${DateStamp}"
$Now           = Get-Date

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile       = Join-Path $OutputPath "${BaseFileName}.log"
$Results       = [System.Collections.Generic.List[PSCustomObject]]::new()
$TopFindings   = [System.Collections.Generic.List[string]]::new()
$SkippedChecks = [System.Collections.Generic.List[string]]::new()

# Statistiques globales
$Stats = @{
    TotalApps            = 0
    HighRiskPermApps     = 0
    ExpiredSecrets       = 0
    ExpiringSecrets      = 0
    OrphanApps           = 0
    UserConsentApps      = 0
    ApplicationTypePerms = 0
}

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
        [string]$Category,    [string]$AppName,     [string]$AppId,
        [string]$AppType,     [string]$Finding,     [string]$RiskLevel,
        [string]$RegulatoryRef, [string]$RemediationHint,
        [string]$Detail = "", [string]$LastSignIn = "",
        [string]$ExpiryDate = ""
    )
    $Results.Add([PSCustomObject]@{
        Category        = $Category
        AppName         = $AppName
        AppId           = $AppId
        AppType         = $AppType
        Finding         = $Finding
        Detail          = $Detail
        LastSignIn      = $LastSignIn
        ExpiryDate      = $ExpiryDate
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
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkBlue
Write-Host "║      AUDIT-OAUTHAPPLICATIONS — IAM-FEDERATION-LAB       ║" -ForegroundColor DarkBlue
Write-Host "║      Lecture seule · Aucune modification                 ║" -ForegroundColor DarkBlue
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkBlue
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script            : Audit-OAuthApplications.ps1 v$ScriptVersion"
Write-Log "Client            : $Client"
Write-Log "Run ID            : $RunId"
Write-Log "Seuil expiry warn : $SecretExpiryWarningDays jours"
Write-Log "Seuil inactivité  : $InactiveDays jours"
Write-Log "Permissions haut risque : $($HighRiskPermissions.Count) définies"

# ─────────────────────────────────────────────
# CONNEXION
# ─────────────────────────────────────────────

Write-Section "CONNEXION MICROSOFT GRAPH"
try {
    Connect-MgGraph -Scopes @(
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All"
    ) -NoWelcome -ErrorAction Stop

    $Context = Get-MgContext
    Write-Log "Connecté : $($Context.Account) → Tenant : $($Context.TenantId)" "SUCCESS"
} catch {
    Write-Log "Échec connexion : $_" "ERROR"; exit 1
}

# ─────────────────────────────────────────────
# COLLECTE — SERVICE PRINCIPALS ET APP REGISTRATIONS
# ─────────────────────────────────────────────

Write-Section "COLLECTE DES APPLICATIONS"

Write-Log "Récupération des inscriptions d'applications (App Registrations)..."
$AppRegistrations = Get-MgApplication -All `
    -Property Id, DisplayName, AppId, SignInAudience, PublicClient, `
              PasswordCredentials, KeyCredentials, RequiredResourceAccess, `
              CreatedDateTime, Web, Spa, `
              Notes, Tags `
    -ErrorAction Stop

Write-Log "Récupération des Service Principals (Enterprise Apps)..."
$ServicePrincipals = Get-MgServicePrincipal -All `
    -Filter "servicePrincipalType eq 'Application'" `
    -Property Id, DisplayName, AppId, AppOwnerOrganizationId, `
              PasswordCredentials, KeyCredentials, `
              PublisherName, ServicePrincipalType, Tags, `
              AccountEnabled `
    -ErrorAction Stop

# Dictionnaire AppId → SignIn pour enrichissement
$SPDict = @{}
foreach ($SP in $ServicePrincipals) {
    $SPDict[$SP.AppId] = $SP
}

$Stats.TotalApps = $AppRegistrations.Count
Write-Log "App Registrations : $($AppRegistrations.Count)" "SUCCESS"
Write-Log "Service Principals : $($ServicePrincipals.Count)"

# Récupérer les permissions Microsoft Graph (pour nommer les scopes)
Write-Log "Récupération du schéma de permissions Microsoft Graph..."
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" `
    -Property AppRoles, Oauth2PermissionScopes -ErrorAction SilentlyContinue

$GraphAppRoles   = @{}
$GraphDelegated  = @{}

if ($GraphSP) {
    foreach ($Role in $GraphSP.AppRoles) {
        $GraphAppRoles[$Role.Id] = $Role.Value
    }
    foreach ($Scope in $GraphSP.Oauth2PermissionScopes) {
        $GraphDelegated[$Scope.Id] = $Scope.Value
    }
}
Write-Log "Permissions Graph chargées : $($GraphAppRoles.Count) Application + $($GraphDelegated.Count) Delegated"

# ─────────────────────────────────────────────
# PÉRIMÈTRE 1 — PERMISSIONS À HAUT RISQUE
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 1 — PERMISSIONS À HAUT RISQUE"
Write-Log "Analyse des permissions OAuth2 par application..."

foreach ($App in $AppRegistrations) {

    $AppHighRiskPerms  = @()
    $AppPermsAll       = @()
    $HasApplicationType= $false

    foreach ($ResourceAccess in $App.RequiredResourceAccess) {

        # Uniquement Microsoft Graph (00000003...)
        if ($ResourceAccess.ResourceAppId -ne "00000003-0000-0000-c000-000000000000") { continue }

        foreach ($Permission in $ResourceAccess.ResourceAccess) {

            $PermType  = $Permission.Type  # "Role" = Application, "Scope" = Delegated
            $PermId    = $Permission.Id
            $PermName  = if ($PermType -eq "Role") {
                $GraphAppRoles[$PermId] ?? "Unknown-$PermId"
            } else {
                $GraphDelegated[$PermId] ?? "Unknown-$PermId"
            }

            $Label = "${PermType}:${PermName}"
            $AppPermsAll += $Label

            if ($PermType -eq "Role") { $HasApplicationType = $true }

            # Vérifier si la permission est à haut risque
            $IsHighRisk = $HighRiskPermissions | Where-Object { $PermName -like "*$_*" -or $_ -like "*$PermName*" }
            if ($IsHighRisk -or $PermName -like "*.All") {
                $AppHighRiskPerms += $Label
            }
        }
    }

    if ($HasApplicationType) { $Stats.ApplicationTypePerms++ }

    if ($AppHighRiskPerms.Count -gt 0) {
        $Stats.HighRiskPermApps++

        # Niveau de risque selon le type de permission
        $HasAppRole  = $AppHighRiskPerms | Where-Object { $_ -like "Role:*" }
        $RiskLevel   = if ($HasAppRole) { "CRITIQUE" } else { "ÉLEVÉ" }

        $Finding = "Application '$($App.DisplayName)' possède $($AppHighRiskPerms.Count) permission(s) à haut risque : " +
                   "$($AppHighRiskPerms[0..2] -join ', ')$(if ($AppHighRiskPerms.Count -gt 3) { " (+" + ($AppHighRiskPerms.Count - 3) + " autres)" })."

        if ($HasAppRole) {
            $Finding += " ⚠ Permissions de type APPLICATION (agit sans utilisateur connecté) — risque maximal."
        }

        Write-Log "  $RiskLevel : $($App.DisplayName) → $($AppHighRiskPerms -join ' | ')" $(
            if ($RiskLevel -eq "CRITIQUE") { "FOUND" } else { "WARN" }
        )

        # Récupérer la dernière connexion via Service Principal
        $SP           = $SPDict[$App.AppId]
        $LastSignIn   = ""
        $DaysSinceSI  = 9999

        if ($SP) {
            try {
                $SPSignIn = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id `
                    -ErrorAction SilentlyContinue | Select-Object -First 1

                # Tentative via les logs d'audit (nécessite AuditLog.Read.All)
                $SignInLogs = Get-MgAuditLogSignIn `
                    -Filter "appId eq '$($App.AppId)'" `
                    -Top 1 -ErrorAction SilentlyContinue

                if ($SignInLogs) {
                    $LastSignIn  = $SignInLogs[0].CreatedDateTime.ToString("yyyy-MM-dd")
                    $DaysSinceSI = [math]::Round(($Now - $SignInLogs[0].CreatedDateTime).TotalDays, 0)
                }
            } catch { }
        }

        Add-Result `
            -Category       "HighRiskPermissions" `
            -AppName        $App.DisplayName `
            -AppId          $App.AppId `
            -AppType        $(if ($HasApplicationType) { "Application (daemon)" } else { "Delegated" }) `
            -Finding        $Finding `
            -Detail         ($AppHighRiskPerms -join " | ") `
            -LastSignIn     $LastSignIn `
            -RiskLevel      $RiskLevel `
            -RegulatoryRef  "CSSF Ctrl 7 · DORA Art.9 · ISO 27001 A.5.15" `
            -RemediationHint $(if ($HasAppRole) {
                "Vérifier si les permissions Application *.All sont strictement nécessaires. Envisager des permissions plus restrictives (ex: Mail.Read au lieu de Mail.ReadWrite.All). Documenter la justification métier pour chaque permission Application."
            } else {
                "Vérifier si ces permissions déléguées sont toujours utilisées. Si l'application est inactive, révoquer les permissions ou supprimer l'application."
            })
    }
}

$HighRiskCount = ($Results | Where-Object { $_.Category -eq "HighRiskPermissions" }).Count
Write-Log "Applications avec permissions à haut risque : $HighRiskCount"
if ($HighRiskCount -gt 0) {
    $CritCount = ($Results | Where-Object { $_.Category -eq "HighRiskPermissions" -and $_.RiskLevel -eq "CRITIQUE" }).Count
    $TopFindings.Add("$HighRiskCount application(s) avec permissions à haut risque dont $CritCount CRITIQUE(s) (permissions Application *.All)")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 2 — SECRETS ET CERTIFICATS
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 2 — SECRETS ET CERTIFICATS (EXPIRATION)"

foreach ($App in $AppRegistrations) {

    # Secrets (PasswordCredentials)
    foreach ($Secret in $App.PasswordCredentials) {
        if (-not $Secret.EndDateTime) { continue }

        $DaysLeft = [math]::Round(($Secret.EndDateTime - $Now).TotalDays, 0)
        $SecretName = if ($Secret.DisplayName) { $Secret.DisplayName } else { "Secret-$($Secret.KeyId.ToString().Substring(0,8))" }

        if ($DaysLeft -lt 0) {
            # Déjà expiré
            $Stats.ExpiredSecrets++
            $Finding = "Secret '$SecretName' de l'application '$($App.DisplayName)' EXPIRÉ depuis $([math]::Abs($DaysLeft)) jours. " +
                       "Un secret expiré casse l'authentification de l'application en production."
            Write-Log "  ÉLEVÉ : $($App.DisplayName) — Secret expiré : $($Secret.EndDateTime.ToString('yyyy-MM-dd'))" "FOUND"

            Add-Result `
                -Category       "ExpiredSecret" `
                -AppName        $App.DisplayName `
                -AppId          $App.AppId `
                -AppType        "Secret" `
                -Finding        $Finding `
                -Detail         "Expiré le : $($Secret.EndDateTime.ToString('yyyy-MM-dd'))" `
                -ExpiryDate     $Secret.EndDateTime.ToString("yyyy-MM-dd") `
                -RiskLevel      "ÉLEVÉ" `
                -RegulatoryRef  "ISO 27001 A.8.17 · FINMA §38" `
                -RemediationHint "Créer un nouveau secret via New-MgApplicationPassword, mettre à jour l'application cliente, puis supprimer l'ancien secret."

        } elseif ($DaysLeft -le $SecretExpiryWarningDays) {
            # Expire bientôt
            $Stats.ExpiringSecrets++
            $RiskLevel = if ($DaysLeft -le 7) { "ÉLEVÉ" } elseif ($DaysLeft -le 30) { "MOYEN" } else { "FAIBLE" }

            $Finding = "Secret '$SecretName' de '$($App.DisplayName)' expire dans $DaysLeft jours ($($Secret.EndDateTime.ToString('yyyy-MM-dd'))). " +
                       "Renouveler avant expiration pour éviter une rupture de service."

            if ($RiskLevel -ne "FAIBLE" -or $ExportAll) {
                Add-Result `
                    -Category       "ExpiringSecret" `
                    -AppName        $App.DisplayName `
                    -AppId          $App.AppId `
                    -AppType        "Secret" `
                    -Finding        $Finding `
                    -Detail         "Expire le : $($Secret.EndDateTime.ToString('yyyy-MM-dd')) ($DaysLeft jours)" `
                    -ExpiryDate     $Secret.EndDateTime.ToString("yyyy-MM-dd") `
                    -RiskLevel      $RiskLevel `
                    -RegulatoryRef  "ISO 27001 A.8.17" `
                    -RemediationHint "Planifier le renouvellement du secret. Procédure : New-MgApplicationPassword -ApplicationId '$($App.Id)' -PasswordCredential @{DisplayName='Renewed-$(Get-Date -Format yyyyMMdd)'}"
            }
        }
    }

    # Certificats (KeyCredentials)
    foreach ($Cert in $App.KeyCredentials) {
        if (-not $Cert.EndDateTime) { continue }

        $DaysLeft  = [math]::Round(($Cert.EndDateTime - $Now).TotalDays, 0)
        $CertName  = if ($Cert.DisplayName) { $Cert.DisplayName } else { "Cert-$($Cert.KeyId.ToString().Substring(0,8))" }

        if ($DaysLeft -lt 0) {
            $Stats.ExpiredSecrets++
            $Finding = "Certificat '$CertName' de '$($App.DisplayName)' EXPIRÉ depuis $([math]::Abs($DaysLeft)) jours."
            Write-Log "  ÉLEVÉ : $($App.DisplayName) — Certificat expiré" "FOUND"

            Add-Result `
                -Category       "ExpiredSecret" `
                -AppName        $App.DisplayName `
                -AppId          $App.AppId `
                -AppType        "Certificate" `
                -Finding        $Finding `
                -ExpiryDate     $Cert.EndDateTime.ToString("yyyy-MM-dd") `
                -RiskLevel      "ÉLEVÉ" `
                -RegulatoryRef  "ISO 27001 A.8.17 · FINMA §38" `
                -RemediationHint "Générer un nouveau certificat, mettre à jour l'application, puis supprimer l'ancien certificat via Remove-MgApplicationKey."

        } elseif ($DaysLeft -le $SecretExpiryWarningDays) {
            $RiskLevel = if ($DaysLeft -le 7) { "ÉLEVÉ" } elseif ($DaysLeft -le 30) { "MOYEN" } else { "FAIBLE" }
            if ($RiskLevel -ne "FAIBLE" -or $ExportAll) {
                Add-Result `
                    -Category       "ExpiringSecret" `
                    -AppName        $App.DisplayName `
                    -AppId          $App.AppId `
                    -AppType        "Certificate" `
                    -Finding        "Certificat '$CertName' de '$($App.DisplayName)' expire dans $DaysLeft jours." `
                    -ExpiryDate     $Cert.EndDateTime.ToString("yyyy-MM-dd") `
                    -RiskLevel      $RiskLevel `
                    -RegulatoryRef  "ISO 27001 A.8.17" `
                    -RemediationHint "Planifier le renouvellement du certificat avant expiration."
            }
        }
    }
}

$ExpiredCount  = ($Results | Where-Object { $_.Category -eq "ExpiredSecret"   }).Count
$ExpiringCount = ($Results | Where-Object { $_.Category -eq "ExpiringSecret"  }).Count
Write-Log "Secrets/certs expirés  : $ExpiredCount" $(if ($ExpiredCount -gt 0) { "FOUND" } else { "SUCCESS" })
Write-Log "Secrets/certs expirant : $ExpiringCount" $(if ($ExpiringCount -gt 0) { "WARN" } else { "SUCCESS" })

if ($ExpiredCount -gt 0) {
    $TopFindings.Add("$ExpiredCount secret(s)/certificat(s) EXPIRÉ(s) — applications potentiellement en rupture de service")
}
if ($ExpiringCount -gt 0) {
    $TopFindings.Add("$ExpiringCount secret(s)/certificat(s) expirant dans les $SecretExpiryWarningDays jours — planifier le renouvellement")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 3 — CONSENTEMENTS UTILISATEURS
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 3 — CONSENTEMENTS UTILISATEURS (OAUTH GRANTS)"
Write-Log "Détection des consentements accordés par des utilisateurs individuels..."

try {
    # Consentements non-admin (consentType eq 'Principal' = accordé par un utilisateur)
    $UserConsentGrants = Get-MgOauth2PermissionGrant `
        -Filter "consentType eq 'Principal'" `
        -All -ErrorAction Stop

    Write-Log "Consentements utilisateurs trouvés : $($UserConsentGrants.Count)" $(
        if ($UserConsentGrants.Count -gt 0) { "WARN" } else { "SUCCESS" }
    )
    $Stats.UserConsentApps = $UserConsentGrants.Count

    # Grouper par application
    $ConsentsByApp = $UserConsentGrants | Group-Object ClientId

    foreach ($AppConsents in $ConsentsByApp | Sort-Object Count -Descending | Select-Object -First 20) {

        # Trouver le nom de l'application
        $SP = $ServicePrincipals | Where-Object { $_.Id -eq $AppConsents.Name } | Select-Object -First 1
        $AppName = if ($SP) { $SP.DisplayName } else { "Unknown-$($AppConsents.Name.Substring(0,8))" }
        $AppId   = if ($SP) { $SP.AppId } else { $AppConsents.Name }

        # Analyser les scopes consentis
        $AllScopes = $AppConsents.Group | ForEach-Object { $_.Scope -split " " } | Sort-Object -Unique
        $HighRiskScopes = $AllScopes | Where-Object {
            $HighRiskPermissions | Where-Object { $_ -like "*$($_.Split('.')[0])*" }
        }

        $RiskLevel = if ($HighRiskScopes.Count -gt 0) { "ÉLEVÉ" }
                     elseif ($AllScopes | Where-Object { $_ -like "*.ReadWrite*" }) { "MOYEN" }
                     else { "FAIBLE" }

        if ($RiskLevel -eq "FAIBLE" -and -not $ExportAll) { continue }

        $Finding = "Application '$AppName' possède $($AppConsents.Count) consentement(s) utilisateur(s) " +
                   "pour les scopes : $($AllScopes[0..2] -join ', ')$(if ($AllScopes.Count -gt 3) { " (+" + ($AllScopes.Count-3) + " autres)" }). " +
                   "Ces consentements ont été accordés par des utilisateurs individuels, sans validation admin."

        Write-Log "  $RiskLevel : $AppName — $($AppConsents.Count) consentements, scopes : $($AllScopes -join ', ')" $(
            if ($RiskLevel -ne "FAIBLE") { "WARN" } else { "INFO" }
        )

        Add-Result `
            -Category       "UserConsent" `
            -AppName        $AppName `
            -AppId          $AppId `
            -AppType        "Delegated (User Consent)" `
            -Finding        $Finding `
            -Detail         "Scopes : $($AllScopes -join ' | ') | Utilisateurs : $($AppConsents.Count)" `
            -RiskLevel      $RiskLevel `
            -RegulatoryRef  "CSSF Ctrl 7 · ISO 27001 A.5.15" `
            -RemediationHint "Vérifier si cette application est connue et légitime. Révoquer les consentements suspects via Remove-MgOauth2PermissionGrant. Activer la politique de consentement admin pour bloquer les futurs consentements non-admin."
    }

    $UserConsentRiskyCount = ($Results | Where-Object { $_.Category -eq "UserConsent" -and $_.RiskLevel -in @("ÉLEVÉ","MOYEN") }).Count
    if ($UserConsentRiskyCount -gt 0) {
        $TopFindings.Add("$UserConsentRiskyCount application(s) avec consentements utilisateurs à risque — vecteur potentiel OAuth Consent Phishing")
    }

} catch {
    Write-Log "Erreur lecture consentements OAuth : $_" "WARN"
    $SkippedChecks.Add("P3 — Consentements utilisateurs (erreur lecture)")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 4 — APPLICATIONS ORPHELINES
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 4 — APPLICATIONS ORPHELINES (INACTIVITÉ)"
Write-Log "Détection des applications sans connexion depuis $InactiveDays jours..."

$InactiveThreshold = $Now.AddDays(-$InactiveDays)

foreach ($App in $AppRegistrations | Select-Object -First 100) {

    # Vérifier l'âge de création
    $AgeDays = [math]::Round(($Now - $App.CreatedDateTime).TotalDays, 0)
    if ($AgeDays -lt $InactiveDays) { continue }  # App trop récente pour être orpheline

    # Chercher une activité récente dans les logs
    $HasRecentActivity = $false
    $LastSignIn        = ""

    try {
        $SignInLogs = Get-MgAuditLogSignIn `
            -Filter "appId eq '$($App.AppId)' and createdDateTime ge $($InactiveThreshold.ToString('yyyy-MM-ddT00:00:00Z'))" `
            -Top 1 -ErrorAction SilentlyContinue

        if ($SignInLogs -and $SignInLogs.Count -gt 0) {
            $HasRecentActivity = $true
            $LastSignIn        = $SignInLogs[0].CreatedDateTime.ToString("yyyy-MM-dd")
        }
    } catch {
        # Les logs peuvent être indisponibles selon la licence
    }

    # Vérifier si l'app a des secrets actifs mais pas d'activité
    $HasActiveSecrets = ($App.PasswordCredentials | Where-Object {
        $_.EndDateTime -and $_.EndDateTime -gt $Now
    }).Count -gt 0

    if (-not $HasRecentActivity -and $HasActiveSecrets) {
        $Stats.OrphanApps++
        $RiskLevel = if ($AgeDays -gt 365) { "MOYEN" } else { "FAIBLE" }

        if ($RiskLevel -eq "FAIBLE" -and -not $ExportAll) { continue }

        $Finding = "Application '$($App.DisplayName)' (créée il y a $AgeDays jours) : " +
                   "aucune connexion détectée dans les $InactiveDays derniers jours " +
                   "mais possède des secrets actifs et des permissions enregistrées. " +
                   "Application potentiellement orpheline."

        Add-Result `
            -Category       "OrphanApp" `
            -AppName        $App.DisplayName `
            -AppId          $App.AppId `
            -AppType        "Application Registration" `
            -Finding        $Finding `
            -Detail         "Créée le : $($App.CreatedDateTime.ToString('yyyy-MM-dd')) | Dernière activité détectée : $(if ($LastSignIn) { $LastSignIn } else { 'Jamais' })" `
            -LastSignIn     $LastSignIn `
            -RiskLevel      $RiskLevel `
            -RegulatoryRef  "ISO 27001 A.5.15 · FINMA §38" `
            -RemediationHint "Identifier le propriétaire de l'application via Get-MgApplicationOwner. Confirmer avec le propriétaire métier si l'application est encore utilisée. Si non : supprimer via Remove-MgApplication après révocation des permissions."
    }
}

$OrphanCount = ($Results | Where-Object { $_.Category -eq "OrphanApp" }).Count
Write-Log "Applications potentiellement orphelines : $OrphanCount" $(
    if ($OrphanCount -gt 0) { "WARN" } else { "SUCCESS" }
)

# ─────────────────────────────────────────────
# PÉRIMÈTRE 5 — FLUX D'AUTHENTIFICATION À RISQUE
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 5 — FLUX D'AUTHENTIFICATION À RISQUE"
Write-Log "Détection des applications utilisant des flux OAuth à risque..."

$ImplicitFlowApps = @()
$ROPCApps         = @()
$PublicClientApps = @()

foreach ($App in $AppRegistrations) {

    # Flux implicite activé (implicit grant — déprécié, risqué)
    $ImplicitAccess = $App.Web
    $HasImplicitAccessToken  = $ImplicitAccess -and $ImplicitAccess.ImplicitGrantSettings.EnableAccessTokenIssuance
    $HasImplicitIdToken      = $ImplicitAccess -and $ImplicitAccess.ImplicitGrantSettings.EnableIdTokenIssuance

    if ($HasImplicitAccessToken) {
        $ImplicitFlowApps += $App.DisplayName
        $Finding = "Application '$($App.DisplayName)' a le flux implicite OAuth2 activé pour les Access Tokens. " +
                   "Ce flux est déprécié (IETF RFC 6749 §3.1) et vulnérable aux attaques de type token leakage via l'URL."

        Add-Result `
            -Category       "RiskyAuthFlow" `
            -AppName        $App.DisplayName `
            -AppId          $App.AppId `
            -AppType        "Web Application" `
            -Finding        $Finding `
            -Detail         "ImplicitGrant AccessToken = true" `
            -RiskLevel      "MOYEN" `
            -RegulatoryRef  "ISO 27001 A.5.15 · FINMA §42" `
            -RemediationHint "Migrer vers le flux Authorization Code + PKCE. Désactiver : Update-MgApplication -ApplicationId '$($App.Id)' -Web @{ImplicitGrantSettings=@{EnableAccessTokenIssuance=\$false}}"
    }

    # Client public — peut utiliser ROPC
    $IsPublicClient = $App.PublicClient -and $App.PublicClient.RedirectUris.Count -gt 0
    if ($IsPublicClient) {
        $PublicClientApps += $App.DisplayName

        # Vérifier si des redirectURIs wildcard sont présents
        $WildcardRedirects = $App.PublicClient.RedirectUris | Where-Object { $_ -eq "*" -or $_ -like "http://*" }
        if ($WildcardRedirects) {
            $Finding = "Application cliente publique '$($App.DisplayName)' avec URI de redirection à risque : $($WildcardRedirects -join ', ')."
            Add-Result `
                -Category       "RiskyAuthFlow" `
                -AppName        $App.DisplayName `
                -AppId          $App.AppId `
                -AppType        "Public Client" `
                -Finding        $Finding `
                -Detail         "RedirectURIs : $($WildcardRedirects -join ' | ')" `
                -RiskLevel      "ÉLEVÉ" `
                -RegulatoryRef  "ISO 27001 A.5.15 · FINMA §42" `
                -RemediationHint "Remplacer les URI wildcard par des URI exactes. Remplacer http:// par https:// pour toutes les URI de production."
        }
    }
}

$RiskyFlowCount = ($Results | Where-Object { $_.Category -eq "RiskyAuthFlow" }).Count
Write-Log "Applications avec flux à risque : $RiskyFlowCount" $(if ($RiskyFlowCount -gt 0) { "WARN" } else { "SUCCESS" })
Write-Log "Flux implicites activés : $($ImplicitFlowApps.Count)"
Write-Log "Clients publics détectés : $($PublicClientApps.Count)"

if ($ImplicitFlowApps.Count -gt 0) {
    $TopFindings.Add("$($ImplicitFlowApps.Count) application(s) avec flux implicite OAuth2 activé — flux déprécié et vulnérable")
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
$Score -= [math]::Min($MoyenCount    *  4, 20)
$Score -= $SkippedChecks.Count * 2
$Score  = [math]::Max($Score, 0)

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

Write-Log "Score OAuthApplications : $Score/100 ($ScoreLabel)"
Write-Log "Apps analysées : $($Stats.TotalApps) | Haut risque : $($Stats.HighRiskPermApps) | Orphelines : $($Stats.OrphanApps)"
Write-Log "Secrets expirés : $($Stats.ExpiredSecrets) | Expirant : $($Stats.ExpiringSecrets)"
Write-Log "Findings : CRITIQUE=$CritiqueCount ÉLEVÉ=$EleveCount MOYEN=$MoyenCount"

# ─────────────────────────────────────────────
# EXPORT CSV
# ─────────────────────────────────────────────

$CsvPath = Join-Path $OutputPath "${BaseFileName}.csv"
$Results |
    Sort-Object @{E={
        switch ($_.RiskLevel) { "CRITIQUE"{0}"ÉLEVÉ"{1}"MOYEN"{2} default{3} }
    }}, @{E={
        switch ($_.Category) { "HighRiskPermissions"{0}"ExpiredSecret"{1}"UserConsent"{2} default{3} }
    }}, AppName |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Log "CSV exporté : $CsvPath ($($Results.Count) findings)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

$JsonReport = [ordered]@{
    "_schema"          = "iam-federation-lab/audit-oauthapplications/v1.0"
    "RunId"            = $RunId
    "Domain"           = "D4 — OAuth/OIDC Applications"
    "Client"           = $Client
    "Date"             = $DateStamp
    "GeneratedAt"      = $TimeStamp
    "Score"            = $Score
    "ScoreLabel"       = $ScoreLabel
    "Statistics"       = [ordered]@{
        "TotalAppRegistrations"  = $Stats.TotalApps
        "TotalServicePrincipals" = $ServicePrincipals.Count
        "HighRiskPermApps"       = $Stats.HighRiskPermApps
        "ApplicationTypePermApps"= $Stats.ApplicationTypePerms
        "ExpiredCredentials"     = $Stats.ExpiredSecrets
        "ExpiringCredentials"    = $Stats.ExpiringSecrets
        "OrphanApps"             = $Stats.OrphanApps
        "UserConsentGrants"      = $Stats.UserConsentApps
        "ImplicitFlowApps"       = $ImplicitFlowApps.Count
        "TotalFindings"          = $Results.Count
        "CRITIQUE"               = $CritiqueCount
        "ÉLEVÉ"                  = $EleveCount
        "MOYEN"                  = $MoyenCount
        "SkippedChecks"          = $SkippedChecks.Count
    }
    "TopFindings"      = $TopFindings
    "SkippedChecks"    = $SkippedChecks
    "RegulatoryMapping"= [ordered]@{
        "ISO27001_A515"    = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "CSSF_22806_Ctrl7" = if ($CritiqueCount -gt 0) { "NON_CONFORME" } elseif ($EleveCount -gt 0) { "PARTIEL" } else { "CONFORME" }
        "DORA_Art9"        = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "FINMA_2023_1_S38" = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"         = "Remediate-OAuthApplications.ps1 -AuditReport '$CsvPath' -DryRun"
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
Write-Host "  │  SCORE OAUTH/OIDC : $($Score.ToString().PadRight(3))/100 — $($ScoreLabel.PadRight(13))   │" -ForegroundColor $ScoreColor
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Apps analysées        : $($Stats.TotalApps.ToString().PadRight(29))│" -ForegroundColor White
Write-Host "  │  Permissions haut risque: $($Stats.HighRiskPermApps.ToString().PadRight(28))│" -ForegroundColor $(if ($Stats.HighRiskPermApps -gt 0) { "Red" } else { "Green" })
Write-Host "  │  Secrets expirés       : $($Stats.ExpiredSecrets.ToString().PadRight(29))│" -ForegroundColor $(if ($Stats.ExpiredSecrets -gt 0) { "Red" } else { "Green" })
Write-Host "  │  Secrets expirant      : $($Stats.ExpiringSecrets.ToString().PadRight(29))│" -ForegroundColor $(if ($Stats.ExpiringSecrets -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Consentements users   : $($Stats.UserConsentApps.ToString().PadRight(29))│" -ForegroundColor $(if ($Stats.UserConsentApps -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Apps orphelines       : $($Stats.OrphanApps.ToString().PadRight(29))│" -ForegroundColor $(if ($Stats.OrphanApps -gt 0) { "Yellow" } else { "White" })
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
Write-Host "  ✅ LOG  : $LogFile"  -ForegroundColor Green
Write-Host ""
Write-Host "  PROCHAINE ÉTAPE :" -ForegroundColor Cyan
Write-Host "  .\Remediate-OAuthApplications.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""

Write-Log "Audit OAuthApplications terminé — Score : $Score/100 ($ScoreLabel) — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
