<#
.SYNOPSIS
    Audit des relations de confiance et accès guests — Lecture seule absolue.

.DESCRIPTION
    Audit-FederationTrusts.ps1 cartographie l'ensemble des portes d'entrée externes
    dans le tenant Entra ID : comptes guests B2B, domaines fédérés, politiques de
    collaboration externe, et configuration Keycloak si présent.

    POURQUOI C'EST UN ANGLE MORT FRÉQUENT :
    Les accès externes (guests, fédération B2B) se créent facilement — une invitation
    envoyée, un partenariat établi — et ne sont presque jamais audités. Le résultat :
      → Des guests actifs dont l'organisation externe n'est plus partenaire
      → Des certificats SAML de fédération qui expirent sans alerte (= tous les
        utilisateurs fédérés bloqués du jour au lendemain)
      → Des politiques de collaboration externe ouvertes à tous les domaines
      → Des guests sans aucune politique d'accès conditionnel (ils contournent
        les règles MFA qui s'appliquent aux membres internes)

    Ce script analyse 5 périmètres :
      [1] Comptes guests Entra B2B — état, ancienneté, activité
      [2] Domaines fédérés — configuration SAML, expiration des certificats
      [3] Politiques de collaboration externe — qui peut inviter qui
      [4] Politiques d'accès conditionnel pour les guests
      [5] Configuration Keycloak (si -KeycloakUrl fourni)

    COUVERTURE RÉGLEMENTAIRE :
      CSSF 22/806 Ctrl 7      — Gestion des identités externes et accès tiers
      FINMA Circ. 2023/1 §38  — Traçabilité des accès externes
      DORA Art. 12            — Gestion des prestataires tiers
      ISO 27001:2022 A.5.16   — Gestion des identités, accès tiers

    PRÉREQUIS :
      - Module Microsoft.Graph : Install-Module Microsoft.Graph
      - Rôle Entra ID : Security Reader + External Identity Provider Reader
      - Pour Keycloak : accès API admin Keycloak (URL + token d'accès)

.PARAMETER OutputPath
    Dossier de sortie. Défaut : .\Reports

.PARAMETER Client
    Nom du client pour les rapports.

.PARAMETER GuestInactiveDays
    Seuil de jours sans connexion pour qualifier un guest comme inactif.
    Défaut : 90

.PARAMETER KeycloakUrl
    URL de base de l'API admin Keycloak (ex: https://keycloak.corp.com).
    Si fourni, active l'analyse Keycloak (périmètre 5).

.PARAMETER KeycloakToken
    Token d'accès Keycloak (Bearer). Requis si KeycloakUrl est fourni.
    Générer via : POST /auth/realms/master/protocol/openid-connect/token

.PARAMETER ExportAll
    Exporte tous les guests, y compris les actifs conformes.
    Par défaut : uniquement les guests à risque.

.EXAMPLE
    .\Audit-FederationTrusts.ps1 -Client "Banque XYZ"
    .\Audit-FederationTrusts.ps1 -Client "Groupe ABC" -GuestInactiveDays 60
    .\Audit-FederationTrusts.ps1 -Client "Client FR" `
        -KeycloakUrl "https://keycloak.corp.com" `
        -KeycloakToken "eyJhbGci..."

.OUTPUTS
    Reports/Audit-FederationTrusts_<date>.csv   — détail par entité
    Reports/Audit-FederationTrusts_<date>.json  — score + findings
    Reports/Audit-FederationTrusts_<date>.log   — journal d'exécution

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D5 — Federation Trusts

    LECTURE SEULE — Ce script ne modifie aucun objet.
    Pour la remédiation : utiliser Remediate-FederationTrusts.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$GuestInactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$KeycloakUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$KeycloakToken = "",

    [Parameter(Mandatory = $false)]
    [switch]$ExportAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

$ScriptVersion    = "1.0"
$DateStamp        = Get-Date -Format "yyyy-MM-dd"
$TimeStamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$RunId            = [System.Guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
$BaseFileName     = "Audit-FederationTrusts_${DateStamp}"
$InactiveThreshold = (Get-Date).AddDays(-$GuestInactiveDays)

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
        [string]$Category, [string]$EntityName, [string]$EntityType,
        [string]$ExternalOrg, [string]$Finding, [string]$RiskLevel,
        [string]$RegulatoryRef, [string]$RemediationHint,
        [string]$LastSignIn = "", [string]$CreatedDate = ""
    )
    $Results.Add([PSCustomObject]@{
        Category        = $Category
        EntityName      = $EntityName
        EntityType      = $EntityType
        ExternalOrg     = $ExternalOrg
        Finding         = $Finding
        RiskLevel       = $RiskLevel
        RegulatoryRef   = $RegulatoryRef
        RemediationHint = $RemediationHint
        LastSignIn      = $LastSignIn
        CreatedDate     = $CreatedDate
        DetectedAt      = $TimeStamp
    })
}

# ─────────────────────────────────────────────
# BANNIÈRE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
Write-Host "║      AUDIT-FEDERATIONTRUSTS — IAM-FEDERATION-LAB        ║" -ForegroundColor DarkYellow
Write-Host "║      Lecture seule · Aucune modification                 ║" -ForegroundColor DarkYellow
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script          : Audit-FederationTrusts.ps1 v$ScriptVersion"
Write-Log "Client          : $Client"
Write-Log "Run ID          : $RunId"
Write-Log "Seuil inactivité : $GuestInactiveDays jours"
Write-Log "Keycloak        : $(if ($KeycloakUrl) { $KeycloakUrl } else { 'Non configuré' })"

# ─────────────────────────────────────────────
# CONNEXION MICROSOFT GRAPH
# ─────────────────────────────────────────────

Write-Section "CONNEXION MICROSOFT GRAPH"

try {
    Connect-MgGraph -Scopes @(
        "User.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
        "CrossTenantInformation.ReadBasic.All",
        "Organization.Read.All"
    ) -NoWelcome -ErrorAction Stop

    $Context = Get-MgContext
    Write-Log "Connecté : $($Context.Account) → Tenant : $($Context.TenantId)" "SUCCESS"
} catch {
    Write-Log "Échec connexion Microsoft Graph : $_" "ERROR"
    exit 1
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 1 — COMPTES GUESTS ENTRA B2B
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 1 — COMPTES GUESTS ENTRA B2B"
Write-Log "Récupération de tous les comptes guests (userType eq 'Guest')..."

$AllGuests = Get-MgUser -All `
    -Filter "userType eq 'Guest'" `
    -Property Id, UserPrincipalName, DisplayName, Mail, CreatedDateTime, `
              SignInActivity, AccountEnabled, ExternalUserState, `
              ExternalUserStateChangeDateTime `
    -ErrorAction Stop

Write-Log "Guests trouvés : $($AllGuests.Count)"

$GuestStats = @{
    Total        = $AllGuests.Count
    Inactive     = 0
    NeverSignedIn= 0
    PendingInvite= 0
    NoCAPolicy   = 0
    Disabled     = 0
}

foreach ($Guest in $AllGuests) {
    $LastSignIn      = $Guest.SignInActivity.LastSignInDateTime
    $DaysSinceSignIn = if ($LastSignIn) {
        [math]::Round(((Get-Date) - $LastSignIn).TotalDays, 0)
    } else { 9999 }

    $NeverSignedIn   = ($null -eq $LastSignIn)
    $IsInactive      = ($DaysSinceSignIn -ge $GuestInactiveDays)
    $IsPending       = ($Guest.ExternalUserState -eq "PendingAcceptance")
    $IsDisabled      = (-not $Guest.AccountEnabled)

    # Extraction de l'organisation externe depuis l'UPN guest (format: user_domain.com#EXT#@tenant.onmicrosoft.com)
    $ExternalOrg = ""
    if ($Guest.UserPrincipalName -match "_([^_#]+)#EXT#") {
        $ExternalOrg = $Matches[1]
    } elseif ($Guest.Mail) {
        $ExternalOrg = ($Guest.Mail -split "@")[1]
    }

    # Calcul du niveau de risque
    $RiskLevel  = "FAIBLE"
    $FindingMsg = ""

    if ($IsDisabled) {
        $GuestStats.Disabled++
        # Un guest désactivé mais toujours présent = bruit + risque de réactivation accidentelle
        $RiskLevel  = "FAIBLE"
        $FindingMsg = "Guest désactivé — présence résiduelle dans le tenant"
    } elseif ($NeverSignedIn -and $IsPending) {
        $GuestStats.PendingInvite++
        $DaysPending = if ($Guest.ExternalUserStateChangeDateTime) {
            [math]::Round(((Get-Date) - $Guest.ExternalUserStateChangeDateTime).TotalDays, 0)
        } else { 0 }
        $RiskLevel  = if ($DaysPending -gt 30) { "MOYEN" } else { "FAIBLE" }
        $FindingMsg = "Invitation en attente depuis $DaysPending jours — jamais acceptée"
    } elseif ($NeverSignedIn) {
        $GuestStats.NeverSignedIn++
        $RiskLevel  = "MOYEN"
        $FindingMsg = "Guest actif mais n'a jamais utilisé son accès — invitation à vérifier"
    } elseif ($IsInactive) {
        $GuestStats.Inactive++
        $RiskLevel  = if ($DaysSinceSignIn -gt 180) { "ÉLEVÉ" } else { "MOYEN" }
        $FindingMsg = "Guest inactif depuis $DaysSinceSignIn jours (dernière connexion : $($LastSignIn.ToString('yyyy-MM-dd')))"
    }

    if (-not $ExportAll -and $RiskLevel -eq "FAIBLE") { continue }

    if ($FindingMsg) {
        Add-Result `
            -Category    "GuestB2B" `
            -EntityName  $Guest.UserPrincipalName `
            -EntityType  "GuestUser" `
            -ExternalOrg $ExternalOrg `
            -Finding     $FindingMsg `
            -RiskLevel   $RiskLevel `
            -RegulatoryRef "CSSF Ctrl 7 · FINMA §38 · ISO 27001 A.5.16" `
            -RemediationHint "Vérifier avec le propriétaire métier si cet accès est toujours justifié. Si non : supprimer le guest via Remove-MgUser (ne pas désactiver seulement)." `
            -LastSignIn  $(if ($LastSignIn) { $LastSignIn.ToString("yyyy-MM-dd") } else { "JAMAIS" }) `
            -CreatedDate $(if ($Guest.CreatedDateTime) { $Guest.CreatedDateTime.ToString("yyyy-MM-dd") } else { "" })
    }
}

# Résumé guests
$GuestInactiveCount  = ($Results | Where-Object { $_.Category -eq "GuestB2B" -and $_.RiskLevel -eq "ÉLEVÉ" }).Count
$GuestMoyenCount     = ($Results | Where-Object { $_.Category -eq "GuestB2B" -and $_.RiskLevel -eq "MOYEN" }).Count

Write-Log "  Total guests         : $($GuestStats.Total)"
Write-Log "  Inactifs >$($GuestInactiveDays)j      : $($GuestStats.Inactive)" $(if ($GuestStats.Inactive -gt 0) { "WARN" } else { "SUCCESS" })
Write-Log "  Jamais connectés     : $($GuestStats.NeverSignedIn)" $(if ($GuestStats.NeverSignedIn -gt 0) { "WARN" } else { "SUCCESS" })
Write-Log "  Invitations pending  : $($GuestStats.PendingInvite)"
Write-Log "  Désactivés           : $($GuestStats.Disabled)"

if ($GuestStats.Inactive -gt 0) {
    $TopFindings.Add("$($GuestStats.Inactive) guest(s) inactif(s) depuis plus de $GuestInactiveDays jours — accès potentiellement orphelins")
}
if ($GuestStats.NeverSignedIn -gt 0) {
    $TopFindings.Add("$($GuestStats.NeverSignedIn) guest(s) actifs n'ont jamais utilisé leur accès")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 2 — DOMAINES FÉDÉRÉS ET CERTIFICATS SAML
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 2 — DOMAINES FÉDÉRÉS ET CERTIFICATS SAML"

try {
    $AllDomains      = Get-MgDomain -All -ErrorAction Stop
    $FederatedDomains = $AllDomains | Where-Object { $_.AuthenticationType -eq "Federated" }
    $ManagedDomains   = $AllDomains | Where-Object { $_.AuthenticationType -eq "Managed" }

    Write-Log "Domaines total    : $($AllDomains.Count)"
    Write-Log "Domaines fédérés  : $($FederatedDomains.Count)" $(if ($FederatedDomains.Count -gt 0) { "WARN" } else { "SUCCESS" })
    Write-Log "Domaines managés  : $($ManagedDomains.Count)"

    foreach ($Domain in $FederatedDomains) {
        Write-Log "  Analyse domaine fédéré : $($Domain.Id)"

        try {
            $FedConfigs = Get-MgDomainFederationConfiguration -DomainId $Domain.Id -ErrorAction Stop

            if (-not $FedConfigs -or $FedConfigs.Count -eq 0) {
                Write-Log "    Aucune configuration de fédération trouvée pour $($Domain.Id)" "WARN"
                Add-Result `
                    -Category    "FederatedDomain" `
                    -EntityName  $Domain.Id `
                    -EntityType  "Domain" `
                    -ExternalOrg $Domain.Id `
                    -Finding     "Domaine marqué comme fédéré mais aucune configuration SAML trouvée — configuration orpheline" `
                    -RiskLevel   "MOYEN" `
                    -RegulatoryRef "FINMA §38 · ISO 27001 A.5.16" `
                    -RemediationHint "Vérifier si ce domaine est encore utilisé. Si non : Convert-MgDomainToManaged pour le convertir en managed."
                continue
            }

            foreach ($Config in $FedConfigs) {
                $IdPUrl       = $Config.PassiveSignInUri
                $MetadataUrl  = $Config.MetadataExchangeUri
                $CertExpiry   = $null
                $DaysLeft     = 9999

                # Analyse du certificat de signature SAML
                if ($Config.SigningCertificate) {
                    try {
                        $CertBytes = [System.Convert]::FromBase64String($Config.SigningCertificate)
                        $Cert      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
                        $CertExpiry = $Cert.NotAfter
                        $DaysLeft   = [math]::Round(($Cert.NotAfter - (Get-Date)).TotalDays, 0)

                        Write-Log "    Certificat SAML : expire $($Cert.NotAfter.ToString('yyyy-MM-dd')) ($DaysLeft jours)"

                        $CertRisk = if ($DaysLeft -lt 0) {
                            "CRITIQUE"  # Déjà expiré
                        } elseif ($DaysLeft -lt 14) {
                            "CRITIQUE"  # Expire dans moins de 2 semaines
                        } elseif ($DaysLeft -lt 30) {
                            "ÉLEVÉ"
                        } elseif ($DaysLeft -lt 60) {
                            "MOYEN"
                        } else { $null }

                        if ($CertRisk) {
                            $ExpiredOrExpiring = if ($DaysLeft -lt 0) {
                                "EXPIRÉ depuis $([math]::Abs($DaysLeft)) jours"
                            } else {
                                "expire dans $DaysLeft jours"
                            }

                            $Finding = "Certificat SAML du domaine fédéré '$($Domain.Id)' : $ExpiredOrExpiring " +
                                       "(date : $($Cert.NotAfter.ToString('yyyy-MM-dd'))). " +
                                       "Impact : TOUS les utilisateurs de ce domaine ne peuvent plus s'authentifier."

                            Write-Log "    $CertRisk : $Finding" "FOUND"

                            Add-Result `
                                -Category    "FederatedDomain" `
                                -EntityName  $Domain.Id `
                                -EntityType  "SAMLCertificate" `
                                -ExternalOrg $($Config.DisplayName) `
                                -Finding     $Finding `
                                -RiskLevel   $CertRisk `
                                -RegulatoryRef "FINMA §38 · DORA Art.12 · ISO 27001 A.8.17" `
                                -RemediationHint "Renouveler le certificat SAML en urgence via Update-MgDomainFederationConfiguration ou le portail ADFS. Prévoir une communication aux utilisateurs si expiration imminente."

                            if ($CertRisk -in @("CRITIQUE", "ÉLEVÉ")) {
                                $TopFindings.Add("$CertRisk : Certificat SAML '$($Domain.Id)' $ExpiredOrExpiring")
                            }
                        } else {
                            Write-Log "    Certificat valide ($DaysLeft jours restants)" "SUCCESS"
                        }

                    } catch {
                        Write-Log "    Impossible de lire le certificat SAML : $_" "WARN"
                    }
                } else {
                    Write-Log "    Aucun certificat de signature dans la configuration" "WARN"
                    Add-Result `
                        -Category    "FederatedDomain" `
                        -EntityName  $Domain.Id `
                        -EntityType  "SAMLConfiguration" `
                        -ExternalOrg "" `
                        -Finding     "Configuration SAML sans certificat de signature détecté via Graph — vérifier manuellement dans le portail" `
                        -RiskLevel   "MOYEN" `
                        -RegulatoryRef "ISO 27001 A.8.17" `
                        -RemediationHint "Vérifier la configuration SAML via Get-MgDomainFederationConfiguration ou le portail Entra ID."
                }

                Write-Log "    IdP URI     : $IdPUrl"
            }

        } catch {
            Write-Log "    Erreur lecture config fédération pour $($Domain.Id) : $_" "WARN"
        }
    }

} catch {
    Write-Log "Erreur récupération des domaines : $_" "WARN"
    $SkippedChecks.Add("P2 — Domaines fédérés")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 3 — POLITIQUES DE COLLABORATION EXTERNE
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 3 — POLITIQUES DE COLLABORATION EXTERNE"
Write-Log "Analyse des paramètres d'invitation et de collaboration B2B..."

try {
    # Politique d'autorisation B2B
    $AuthorizationPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop

    Write-Log "Paramètres de collaboration externe :"

    # Qui peut inviter des guests
    $GuestInviteSettings = $AuthorizationPolicy.AllowInvitesFrom
    Write-Log "  AllowInvitesFrom : $GuestInviteSettings"

    $InviteRisk = switch ($GuestInviteSettings) {
        "everyone"            { "CRITIQUE" }  # N'importe qui peut inviter
        "adminsAndGuestInviters" { "MOYEN" }  # Admins + rôle Guest Inviter
        "adminsGuestInvitersAndAllMembers" { "ÉLEVÉ" }  # Tous les membres peuvent inviter
        "none"                { $null }       # Personne ne peut inviter
        default               { "MOYEN" }
    }

    if ($InviteRisk) {
        $Finding = "Politique d'invitation guests : '$GuestInviteSettings'. " + $(switch ($GuestInviteSettings) {
            "everyone"  { "TOUT utilisateur (y compris guests) peut inviter d'autres externes — surface d'attaque maximale." }
            "adminsGuestInvitersAndAllMembers" { "Tous les membres internes peuvent inviter des externes sans validation centralisée." }
            default     { "Niveau de contrôle à vérifier selon la politique de l'organisation." }
        })

        Write-Log "  $InviteRisk : $Finding" $(if ($InviteRisk -eq "CRITIQUE") { "FOUND" } else { "WARN" })

        Add-Result `
            -Category    "ExternalCollab" `
            -EntityName  "AllowInvitesFrom" `
            -EntityType  "CollaborationPolicy" `
            -ExternalOrg "Tenant" `
            -Finding     $Finding `
            -RiskLevel   $InviteRisk `
            -RegulatoryRef "CSSF Ctrl 7 · FINMA §38 · DORA Art.12" `
            -RemediationHint "Restreindre à 'adminsAndGuestInviters' minimum. Idéalement configurer un processus d'approbation via Entra ID Entitlement Management."

        if ($InviteRisk -eq "CRITIQUE") {
            $TopFindings.Add("CRITIQUE : Tous les utilisateurs peuvent inviter des guests externes — aucun contrôle centralisé")
        }
    } else {
        Write-Log "  Invitations désactivées — conforme" "SUCCESS"
    }

    # Restrictions de domaine pour la collaboration B2B
    try {
        $B2BPolicy = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction SilentlyContinue

        if ($B2BPolicy) {
            $InboundAllowed  = $B2BPolicy.InboundTrust
            $OutboundAllowed = $B2BPolicy.B2BCollaborationOutbound

            Write-Log "  Cross-tenant inbound  : $($B2BPolicy.InboundTrust | ConvertTo-Json -Compress)"
            Write-Log "  Cross-tenant outbound : $($B2BPolicy.B2BCollaborationOutbound | ConvertTo-Json -Compress)"

            # Vérifier si les accès entrants sont ouverts à tous les tenants
            $InboundOpen = $B2BPolicy.B2BCollaborationInbound.UsersAndGroups.AccessType -eq "allowed" -and
                           $B2BPolicy.B2BCollaborationInbound.Applications.AccessType   -eq "allowed"

            if ($InboundOpen) {
                $Finding = "Politique cross-tenant par défaut : collaboration B2B entrante ouverte à tous les tenants externes. " +
                           "Aucune liste blanche de tenants autorisés configurée."
                Write-Log "  MOYEN : $Finding" "WARN"

                Add-Result `
                    -Category    "ExternalCollab" `
                    -EntityName  "CrossTenantPolicy-Default" `
                    -EntityType  "CrossTenantPolicy" `
                    -ExternalOrg "All tenants" `
                    -Finding     $Finding `
                    -RiskLevel   "MOYEN" `
                    -RegulatoryRef "FINMA §38 · DORA Art.12" `
                    -RemediationHint "Configurer des politiques cross-tenant spécifiques par organisation partenaire via New-MgPolicyCrossTenantAccessPolicyPartner. Restreindre la politique par défaut."
            }
        }
    } catch {
        Write-Log "  Impossible de lire la politique cross-tenant par défaut : $_" "WARN"
        $SkippedChecks.Add("P3 — Politique cross-tenant (erreur lecture)")
    }

    # Listes d'autorisation / blocage de domaines B2B
    try {
        $AllowedDomains = Get-MgPolicyAuthorizationPolicyDefaultUserRolePermission -ErrorAction SilentlyContinue
        Write-Log "  Paramètres utilisateurs par défaut lus" "SUCCESS"
    } catch {
        Write-Log "  Impossible de lire les paramètres utilisateurs par défaut : $_" "WARN"
    }

} catch {
    Write-Log "Erreur lecture politiques de collaboration : $_" "WARN"
    $SkippedChecks.Add("P3 — Politiques de collaboration externe")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 4 — POLITIQUES CA POUR LES GUESTS
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 4 — POLITIQUES D'ACCÈS CONDITIONNEL POUR LES GUESTS"
Write-Log "Vérification de la couverture CA spécifique aux utilisateurs guests..."

try {
    $AllCAPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

    # Politiques qui incluent explicitement les guests / utilisateurs externes
    $GuestCAPolicies = $AllCAPolicies | Where-Object {
        $State = $_.State -eq "enabled"
        $IncludesGuests = (
            $_.Conditions.Users.IncludeGuestsOrExternalUsers -ne $null -or
            $_.Conditions.Users.IncludeUsers -contains "GuestsOrExternalUsers"
        )
        $State -and $IncludesGuests
    }

    # Politiques qui couvrent "All" utilisateurs (incluent potentiellement les guests)
    $AllUsersPolicies = $AllCAPolicies | Where-Object {
        $_.State -eq "enabled" -and
        $_.Conditions.Users.IncludeUsers -contains "All"
    }

    # Politiques qui excluent explicitement les guests
    $ExcludingGuestPolicies = $AllCAPolicies | Where-Object {
        $_.State -eq "enabled" -and (
            $_.Conditions.Users.ExcludeGuestsOrExternalUsers -ne $null -or
            $_.Conditions.Users.ExcludeUsers -contains "GuestsOrExternalUsers"
        )
    }

    Write-Log "Politiques CA pour guests spécifiquement : $($GuestCAPolicies.Count)" $(
        if ($GuestCAPolicies.Count -gt 0) { "SUCCESS" } else { "WARN" }
    )
    Write-Log "Politiques CA 'All' (couvrent potentiellement les guests) : $($AllUsersPolicies.Count)"
    Write-Log "Politiques CA excluant explicitement les guests : $($ExcludingGuestPolicies.Count)" $(
        if ($ExcludingGuestPolicies.Count -gt 0) { "FOUND" } else { "SUCCESS" }
    )

    foreach ($P in $GuestCAPolicies) {
        Write-Log "  Politique guest : '$($P.DisplayName)' — Contrôles : $($P.GrantControls.BuiltInControls -join ', ')" "SUCCESS"
    }

    foreach ($P in $ExcludingGuestPolicies) {
        Write-Log "  ⚠ Politique excluant les guests : '$($P.DisplayName)'" "WARN"
        Add-Result `
            -Category    "GuestCAPolicy" `
            -EntityName  $P.DisplayName `
            -EntityType  "ConditionalAccessPolicy" `
            -ExternalOrg "" `
            -Finding     "Politique CA '$($P.DisplayName)' exclut explicitement les guests — ils ne sont pas soumis à cette règle" `
            -RiskLevel   "MOYEN" `
            -RegulatoryRef "CSSF Ctrl 7 · FINMA §42" `
            -RemediationHint "Évaluer si cette exclusion est justifiée. Si non : retirer les guests des exclusions et créer une politique CA dédiée avec les contrôles appropriés."
    }

    # Alerte si aucune politique ne couvre les guests
    if ($GuestCAPolicies.Count -eq 0 -and $AllUsersPolicies.Count -eq 0) {
        $Finding = "Aucune politique d'accès conditionnel ne couvre les utilisateurs guests. " +
                   "Les guests s'authentifient sans contrainte MFA ni condition de localisation."
        Write-Log "ÉLEVÉ : $Finding" "FOUND"

        Add-Result `
            -Category    "GuestCAPolicy" `
            -EntityName  "NoGuestCAPolicyFound" `
            -EntityType  "PolicyGap" `
            -ExternalOrg "" `
            -Finding     $Finding `
            -RiskLevel   "ÉLEVÉ" `
            -RegulatoryRef "CSSF Ctrl 7 · FINMA §42 · DORA Art.9" `
            -RemediationHint "Créer une politique CA ciblant GuestsOrExternalUsers avec au minimum : MFA requis + blocage des pays à risque."

        $TopFindings.Add("ÉLEVÉ : Aucune politique CA ne couvre les guests — MFA et localisation non vérifiés pour les externes")
    } elseif ($GuestCAPolicies.Count -eq 0 -and $AllUsersPolicies.Count -gt 0) {
        Write-Log "Les guests sont potentiellement couverts par les politiques 'All' — vérifier les exclusions" "WARN"
    }

    # Vérifier si les politiques All excluent les guests
    $AllWithGuestExclusion = $AllUsersPolicies | Where-Object {
        $_.Conditions.Users.ExcludeGuestsOrExternalUsers -ne $null
    }
    if ($AllWithGuestExclusion.Count -gt 0) {
        $PolicyNames = $AllWithGuestExclusion | Select-Object -ExpandProperty DisplayName
        $TopFindings.Add("$($AllWithGuestExclusion.Count) politique(s) CA 'All users' excluent les guests : $($PolicyNames -join ', ')")
    }

} catch {
    Write-Log "Erreur analyse politiques CA guests : $_" "WARN"
    $SkippedChecks.Add("P4 — Politiques CA guests")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 5 — KEYCLOAK (SI CONFIGURÉ)
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 5 — KEYCLOAK"

if (-not $KeycloakUrl) {
    Write-Log "Keycloak non configuré — périmètre ignoré (-KeycloakUrl requis)" "SKIP"
    $SkippedChecks.Add("P5 — Keycloak (paramètre -KeycloakUrl non fourni)")
} elseif (-not $KeycloakToken) {
    Write-Log "Token Keycloak manquant — périmètre ignoré (-KeycloakToken requis)" "WARN"
    $SkippedChecks.Add("P5 — Keycloak (paramètre -KeycloakToken manquant)")
} else {
    Write-Log "Analyse Keycloak : $KeycloakUrl"

    $KcHeaders = @{
        "Authorization" = "Bearer $KeycloakToken"
        "Content-Type"  = "application/json"
    }

    try {
        # Récupérer la liste des realms
        $RealmsResponse = Invoke-RestMethod `
            -Uri     "$KeycloakUrl/auth/admin/realms" `
            -Headers $KcHeaders `
            -Method  GET `
            -ErrorAction Stop

        Write-Log "Realms Keycloak trouvés : $($RealmsResponse.Count)"

        foreach ($Realm in $RealmsResponse) {
            $RealmName = $Realm.realm
            Write-Log "  Analyse realm : $RealmName"

            # Clients du realm
            $Clients = Invoke-RestMethod `
                -Uri     "$KeycloakUrl/auth/admin/realms/$RealmName/clients" `
                -Headers $KcHeaders `
                -Method  GET `
                -ErrorAction SilentlyContinue

            $PublicClients = $Clients | Where-Object { $_.publicClient -eq $true }
            Write-Log "    Clients total    : $($Clients.Count)"
            Write-Log "    Clients publics  : $($PublicClients.Count)" $(
                if ($PublicClients.Count -gt 0) { "WARN" } else { "SUCCESS" }
            )

            # Clients publics sans secret = acceptent n'importe quel redirect URI
            $RiskyClients = $PublicClients | Where-Object {
                $_.redirectUris -contains "*" -or $_.redirectUris -contains "/*"
            }

            foreach ($Client in $RiskyClients) {
                $Finding = "Client Keycloak '$($Client.clientId)' (realm: $RealmName) : " +
                           "client public avec redirectUri wildcard '$($Client.redirectUris -join ', ')' — " +
                           "vulnérable aux attaques de redirection OAuth"

                Write-Log "    ÉLEVÉ : $Finding" "FOUND"

                Add-Result `
                    -Category    "Keycloak" `
                    -EntityName  "$RealmName/$($Client.clientId)" `
                    -EntityType  "KeycloakClient" `
                    -ExternalOrg "Keycloak" `
                    -Finding     $Finding `
                    -RiskLevel   "ÉLEVÉ" `
                    -RegulatoryRef "FINMA §42 · ISO 27001 A.5.15" `
                    -RemediationHint "Remplacer les redirectUri wildcard par des URLs exactes. Envisager de convertir en client confidentiel si l'application le supporte."
            }

            # Flux d'authentification activés
            try {
                $RealmDetails = Invoke-RestMethod `
                    -Uri     "$KeycloakUrl/auth/admin/realms/$RealmName" `
                    -Headers $KcHeaders `
                    -Method  GET `
                    -ErrorAction SilentlyContinue

                if ($RealmDetails) {
                    # Vérifier si le flux Direct Grant (ROPC) est activé
                    if ($RealmDetails.directGrantFlow -ne $null) {
                        Write-Log "    Flux Direct Grant (ROPC) configuré : $($RealmDetails.directGrantFlow)"
                    }

                    # Brute force protection
                    if (-not $RealmDetails.bruteForceProtected) {
                        $Finding = "Realm Keycloak '$RealmName' : protection brute force désactivée — attaques par force brute possibles"
                        Write-Log "    MOYEN : $Finding" "WARN"

                        Add-Result `
                            -Category    "Keycloak" `
                            -EntityName  $RealmName `
                            -EntityType  "KeycloakRealm" `
                            -ExternalOrg "Keycloak" `
                            -Finding     $Finding `
                            -RiskLevel   "MOYEN" `
                            -RegulatoryRef "ISO 27001 A.8.5 · FINMA §42" `
                            -RemediationHint "Activer la protection brute force dans les paramètres de sécurité du realm : bruteForceProtected=true, maxFailureWaitSeconds, maxDeltaTimeSeconds."
                    }

                    # SSL requis
                    if ($RealmDetails.sslRequired -ne "all") {
                        $Finding = "Realm Keycloak '$RealmName' : SSL non requis pour toutes les connexions (sslRequired='$($RealmDetails.sslRequired)')"
                        Write-Log "    ÉLEVÉ : $Finding" "FOUND"

                        Add-Result `
                            -Category    "Keycloak" `
                            -EntityName  $RealmName `
                            -EntityType  "KeycloakRealm" `
                            -ExternalOrg "Keycloak" `
                            -Finding     $Finding `
                            -RiskLevel   "ÉLEVÉ" `
                            -RegulatoryRef "FINMA §42 · DORA Art.9 · ISO 27001 A.8.5" `
                            -RemediationHint "Configurer sslRequired='all' dans les paramètres du realm pour forcer HTTPS sur toutes les connexions."
                    }
                }
            } catch {
                Write-Log "    Impossible de lire les détails du realm $RealmName : $_" "WARN"
            }
        }

        $KcFindings = ($Results | Where-Object { $_.Category -eq "Keycloak" }).Count
        if ($KcFindings -gt 0) {
            $TopFindings.Add("Keycloak : $KcFindings finding(s) détecté(s) — clients publics, configuration de sécurité")
        } else {
            Write-Log "Keycloak : aucun risque majeur détecté" "SUCCESS"
        }

    } catch {
        Write-Log "Erreur connexion API Keycloak : $_" "WARN"
        Write-Log "→ Vérifier l'URL ($KeycloakUrl) et la validité du token" "WARN"
        $SkippedChecks.Add("P5 — Keycloak (erreur API : $($_.Exception.Message))")
    }
}

# ─────────────────────────────────────────────
# CALCUL DU SCORE
# ─────────────────────────────────────────────

Write-Section "CALCUL DU SCORE DE CONFORMITÉ"

$CritiqueCount  = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" }).Count
$EleveCount     = ($Results | Where-Object { $_.RiskLevel -eq "ÉLEVÉ"    }).Count
$MoyenCount     = ($Results | Where-Object { $_.RiskLevel -eq "MOYEN"    }).Count
$TotalFindings  = $Results.Count

$Score = 100
$Score -= [math]::Min($CritiqueCount * 25, 75)
$Score -= [math]::Min($EleveCount    * 10, 30)
$Score -= [math]::Min($MoyenCount    *  5, 20)
$Score -= $SkippedChecks.Count * 2
$Score  = [math]::Max($Score, 0)

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

Write-Log "Score FederationTrusts : $Score/100 ($ScoreLabel)"
Write-Log "Findings : CRITIQUE=$CritiqueCount ÉLEVÉ=$EleveCount MOYEN=$MoyenCount"
Write-Log "Guests analysés : $($AllGuests.Count)"

# ─────────────────────────────────────────────
# EXPORT CSV
# ─────────────────────────────────────────────

$CsvPath = Join-Path $OutputPath "${BaseFileName}.csv"
$Results |
    Sort-Object @{E={
        switch ($_.RiskLevel) {
            "CRITIQUE" { 0 } "ÉLEVÉ" { 1 } "MOYEN" { 2 } default { 3 }
        }
    }}, Category, EntityName |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Log "CSV exporté : $CsvPath ($($Results.Count) findings)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

$JsonReport = [ordered]@{
    "_schema"          = "iam-federation-lab/audit-federationtrusts/v1.0"
    "RunId"            = $RunId
    "Domain"           = "D5 — Federation Trusts & Guest Access"
    "Client"           = $Client
    "Date"             = $DateStamp
    "GeneratedAt"      = $TimeStamp
    "Score"            = $Score
    "ScoreLabel"       = $ScoreLabel
    "GuestThresholdDays" = $GuestInactiveDays
    "Statistics"       = [ordered]@{
        "TotalGuests"          = $GuestStats.Total
        "InactiveGuests"       = $GuestStats.Inactive
        "NeverSignedInGuests"  = $GuestStats.NeverSignedIn
        "PendingInvitations"   = $GuestStats.PendingInvite
        "FederatedDomains"     = ($AllDomains | Where-Object { $_.AuthenticationType -eq "Federated" }).Count
        "TotalFindings"        = $TotalFindings
        "CRITIQUE"             = $CritiqueCount
        "ÉLEVÉ"                = $EleveCount
        "MOYEN"                = $MoyenCount
        "SkippedChecks"        = $SkippedChecks.Count
    }
    "TopFindings"      = $TopFindings
    "SkippedChecks"    = $SkippedChecks
    "RegulatoryMapping"= [ordered]@{
        "CSSF_22806_Ctrl7" = if ($CritiqueCount -gt 0) { "NON_CONFORME" } elseif ($EleveCount -gt 0) { "PARTIEL" } else { "CONFORME" }
        "FINMA_2023_1_S38" = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "DORA_Art12"       = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "ISO27001_A516"    = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"         = "Remediate-FederationTrusts.ps1 -AuditReport '$CsvPath' -DryRun"
}

$JsonPath = Join-Path $OutputPath "${BaseFileName}.json"
$JsonReport | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonPath -Encoding UTF8
Write-Log "JSON exporté : $JsonPath" "SUCCESS"

# ─────────────────────────────────────────────
# RÉSUMÉ CONSOLE
# ─────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

$ScoreColor = switch ($ScoreLabel) {
    "OPTIMAL"     { "Green"  } "CONFORME"    { "Green"  }
    "PARTIEL"     { "Yellow" } "INSUFFISANT" { "Red"    }
    "CRITIQUE"    { "Red"    } default       { "White"  }
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  SCORE FEDERATION : $($Score.ToString().PadRight(3))/100 — $($ScoreLabel.PadRight(13))│" -ForegroundColor $ScoreColor
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Guests total       : $($GuestStats.Total.ToString().PadRight(31))│" -ForegroundColor White
Write-Host "  │  Guests inactifs    : $($GuestStats.Inactive.ToString().PadRight(31))│" -ForegroundColor $(if ($GuestStats.Inactive -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Jamais connectés   : $($GuestStats.NeverSignedIn.ToString().PadRight(31))│" -ForegroundColor $(if ($GuestStats.NeverSignedIn -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  CRITIQUE           : $($CritiqueCount.ToString().PadRight(31))│" -ForegroundColor $(if ($CritiqueCount -gt 0) { "Red" } else { "White" })
Write-Host "  │  ÉLEVÉ              : $($EleveCount.ToString().PadRight(31))│" -ForegroundColor $(if ($EleveCount -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  MOYEN              : $($MoyenCount.ToString().PadRight(31))│" -ForegroundColor White
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
Write-Host "  .\Remediate-FederationTrusts.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""

Write-Log "Audit FederationTrusts terminé — Score : $Score/100 ($ScoreLabel) — Run ID : $RunId" "SUCCESS"
Disconnect-MgGraph -ErrorAction SilentlyContinue
