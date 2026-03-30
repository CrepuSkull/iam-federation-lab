<#
.SYNOPSIS
    Audit de la synchronisation hybride AD ↔ Entra ID — Lecture seule absolue.

.DESCRIPTION
    Audit-HybridSync.ps1 analyse la configuration et l'état de la synchronisation
    entre Active Directory on-premise et Entra ID (via Entra Connect / Azure AD Connect).

    POURQUOI C'EST CRITIQUE DANS UN ENVIRONNEMENT HYBRIDE :
    La synchronisation AD ↔ Entra ID crée une dépendance directe entre le périmètre
    on-premise et le cloud. Une mauvaise configuration propage les faiblesses dans
    les deux sens :
      → Compromission on-premise → propagation vers le cloud si les admins Tier 0
        sont synchronisés (ils ne devraient JAMAIS l'être)
      → Compte de service Entra Connect trop privilégié → vecteur d'escalade de privilèges
      → Attributs RH sensibles synchronisés inutilement → exposition de données
      → Seamless SSO mal configuré → ticket Kerberos falsifiable

    Ce script analyse 6 périmètres :
      [1] Comptes Tier 0 / Domain Admins synchronisés vers Entra ID
      [2] Permissions du compte de service Entra Connect
      [3] Configuration du mode de synchronisation (PHS / PTA / Fédération)
      [4] Attributs sensibles synchronisés inutilement
      [5] Seamless SSO — état et configuration Kerberos
      [6] Erreurs de synchronisation actives et santé du connecteur

    COUVERTURE RÉGLEMENTAIRE :
      FINMA Circ. 2023/1 §42  — Authentification forte, isolation des comptes admins
      CSSF 22/806 Ctrl 8      — Journalisation et surveillance de la synchronisation
      DORA Art. 9 §4(b,c)     — Intégrité et surveillance des données
      ISO 27001:2022 A.8.16   — Surveillance des activités

    PRÉREQUIS :
      - Module ActiveDirectory    : RSAT ou Windows Server AD DS Tools
      - Module Microsoft.Graph    : Install-Module Microsoft.Graph
      - Module ADSync             : disponible sur le serveur Entra Connect (local uniquement)
      - Rôle AD    : Domain Users avec accès lecture (lecture seule)
      - Rôle Entra : Hybrid Identity Administrator (lecture) ou Global Reader

    NOTE SUR L'EXÉCUTION :
      Certaines vérifications (périmètres 2 et 5) nécessitent d'être exécutées
      directement sur le serveur hébergeant Entra Connect, ou via PSRemoting
      si configuré. Le script détecte automatiquement si le module ADSync est
      disponible et adapte son périmètre en conséquence.

.PARAMETER OutputPath
    Dossier de sortie. Défaut : .\Reports

.PARAMETER Client
    Nom du client pour les rapports.

.PARAMETER DomainController
    Nom ou IP du contrôleur de domaine cible.
    Défaut : détection automatique via Get-ADDomainController.

.PARAMETER EntraConnectServer
    Nom du serveur hébergeant Entra Connect pour les vérifications ADSync.
    Si non renseigné : le script vérifie si ADSync est disponible localement.

.PARAMETER SensitiveAttributes
    Liste d'attributs AD considérés comme sensibles à vérifier dans le schéma de sync.
    Défaut : liste prédéfinie (salaire, données RH, numéros personnels).

.PARAMETER Tier0Groups
    Groupes AD considérés comme Tier 0 (admins critiques à ne JAMAIS synchroniser).
    Défaut : Domain Admins, Enterprise Admins, Schema Admins, Administrators.

.EXAMPLE
    .\Audit-HybridSync.ps1 -Client "Banque XYZ"
    .\Audit-HybridSync.ps1 -Client "Banque XYZ" -EntraConnectServer "SRV-SYNC01"
    .\Audit-HybridSync.ps1 -Client "Client FR" -DomainController "DC01.corp.local"

.OUTPUTS
    Reports/Audit-HybridSync_<date>.csv   — objets à risque par catégorie
    Reports/Audit-HybridSync_<date>.json  — score + findings + mapping réglementaire
    Reports/Audit-HybridSync_<date>.log   — journal d'exécution

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    Version : 1.0
    GitHub  : https://github.com/CrepuSkull/iam-federation-lab
    Repo    : iam-federation-lab / audit / D6 — Hybrid Sync

    LECTURE SEULE — Ce script ne modifie aucun objet AD ni Entra ID.
    Pour la remédiation : utiliser Remediate-HybridSync.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [string]$DomainController = "",

    [Parameter(Mandatory = $false)]
    [string]$EntraConnectServer = "",

    [Parameter(Mandatory = $false)]
    [string[]]$SensitiveAttributes = @(
        "employeeNumber", "employeeID", "extensionAttribute1", "extensionAttribute2",
        "extensionAttribute3", "extensionAttribute4", "extensionAttribute5",
        "mobile", "homePhone", "streetAddress", "postalCode", "l",
        "personalTitle", "msDS-cloudExtensionAttribute1"
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$Tier0Groups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Group Policy Creator Owners",
        "DNSAdmins", "Account Operators", "Backup Operators"
    )
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
$BaseFileName  = "Audit-HybridSync_${DateStamp}"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$LogFile = Join-Path $OutputPath "${BaseFileName}.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$RunId] $Message"
    $Color = switch ($Level) {
        "ERROR"   { "Red"     } "WARN"    { "Yellow"  }
        "SUCCESS" { "Green"   } "FOUND"   { "Magenta" }
        "SKIP"    { "Gray"    } default   { "Cyan"    }
    }
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Write-Section { param([string]$T)
    Write-Log ("─" * 60); Write-Log "  $T"; Write-Log ("─" * 60)
}

# Collections de résultats
$Results        = [System.Collections.Generic.List[PSCustomObject]]::new()
$TopFindings    = [System.Collections.Generic.List[string]]::new()
$SkippedChecks  = [System.Collections.Generic.List[string]]::new()

function Add-Result {
    param(
        [string]$Category,
        [string]$ObjectName,
        [string]$ObjectType,
        [string]$Finding,
        [string]$RiskLevel,
        [string]$RegulatoryRef,
        [string]$RemediationHint
    )
    $Results.Add([PSCustomObject]@{
        Category        = $Category
        ObjectName      = $ObjectName
        ObjectType      = $ObjectType
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
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║         AUDIT-HYBRIDSYNC — IAM-FEDERATION-LAB           ║" -ForegroundColor DarkCyan
Write-Host "║         Lecture seule · Aucune modification              ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

Write-Section "INITIALISATION"
Write-Log "Script  : Audit-HybridSync.ps1 v$ScriptVersion"
Write-Log "Client  : $Client"
Write-Log "Run ID  : $RunId"
Write-Log "DC      : $(if ($DomainController) { $DomainController } else { 'Auto-détection' })"
Write-Log "Sync SRV: $(if ($EntraConnectServer) { $EntraConnectServer } else { 'Local uniquement' })"

# ─────────────────────────────────────────────
# VÉRIFICATION DES MODULES
# ─────────────────────────────────────────────

Write-Section "VÉRIFICATION DES MODULES ET CONNEXIONS"

# Active Directory
$ADAvailable = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $ADAvailable = $true
    Write-Log "Module ActiveDirectory : disponible" "SUCCESS"
} else {
    Write-Log "Module ActiveDirectory non disponible — certaines vérifications AD ignorées" "WARN"
    Write-Log "→ Installer RSAT : Add-WindowsFeature RSAT-AD-PowerShell" "WARN"
    $SkippedChecks.Add("Périmètres AD (module ActiveDirectory manquant)")
}

# ADSync (Entra Connect)
$ADSyncAvailable = $false
if ($EntraConnectServer) {
    try {
        $ADSyncSession = New-PSSession -ComputerName $EntraConnectServer -ErrorAction Stop
        $ADSyncAvailable = Invoke-Command -Session $ADSyncSession -ScriptBlock {
            (Get-Module -ListAvailable -Name ADSync) -ne $null
        }
        Write-Log "ADSync sur $EntraConnectServer : $(if ($ADSyncAvailable) { 'disponible' } else { 'non trouvé' })"
    } catch {
        Write-Log "Impossible de se connecter à $EntraConnectServer via PSRemoting : $_" "WARN"
        Write-Log "→ Vérifier WinRM et les droits d'accès distant" "WARN"
        $SkippedChecks.Add("Vérifications ADSync (PSRemoting indisponible vers $EntraConnectServer)")
    }
} elseif (Get-Module -ListAvailable -Name ADSync) {
    Import-Module ADSync -ErrorAction SilentlyContinue
    $ADSyncAvailable = $true
    Write-Log "Module ADSync : disponible localement" "SUCCESS"
} else {
    Write-Log "Module ADSync non disponible — vérifications Entra Connect limitées" "WARN"
    Write-Log "→ Exécuter sur le serveur Entra Connect ou fournir -EntraConnectServer" "WARN"
    $SkippedChecks.Add("Vérifications ADSync directes (module ADSync manquant)")
}

# Microsoft Graph
$GraphAvailable = $false
if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
    try {
        Connect-MgGraph -Scopes `
            "User.Read.All",
            "Directory.Read.All",
            "Policy.Read.All",
            "Organization.Read.All" `
            -NoWelcome -ErrorAction Stop
        $GraphAvailable = $true
        $Context = Get-MgContext
        Write-Log "Microsoft Graph : connecté — $($Context.Account)" "SUCCESS"
    } catch {
        Write-Log "Échec connexion Microsoft Graph : $_" "WARN"
        $SkippedChecks.Add("Vérifications Entra ID (connexion Graph échouée)")
    }
} else {
    Write-Log "Module Microsoft.Graph non disponible" "WARN"
    $SkippedChecks.Add("Vérifications Entra ID (module Microsoft.Graph manquant)")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 1 — COMPTES TIER 0 SYNCHRONISÉS
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 1 — COMPTES TIER 0 SYNCHRONISÉS VERS ENTRA ID"
Write-Log "Règle : aucun compte Tier 0 ne doit être synchronisé vers Entra ID"
Write-Log "Groupes Tier 0 analysés : $($Tier0Groups -join ', ')"

$Tier0SyncedUsers  = @()
$Tier0GroupsFound  = @()

if ($ADAvailable -and $GraphAvailable) {

    # Récupérer tous les membres des groupes Tier 0
    $Tier0Members = @{}

    foreach ($GroupName in $Tier0Groups) {
        try {
            $ADParams = @{ Identity = $GroupName; Recursive = $true; ErrorAction = "Stop" }
            if ($DomainController) { $ADParams.Server = $DomainController }

            $Members = Get-ADGroupMember @ADParams |
                Where-Object { $_.objectClass -eq "user" }

            foreach ($Member in $Members) {
                if (-not $Tier0Members.ContainsKey($Member.SamAccountName)) {
                    $Tier0Members[$Member.SamAccountName] = @{
                        Groups = @()
                        UPN    = ""
                    }
                }
                $Tier0Members[$Member.SamAccountName].Groups += $GroupName
            }

            $Tier0GroupsFound += "$GroupName ($($Members.Count) membres)"
            Write-Log "  Groupe '$GroupName' : $($Members.Count) membre(s)" $(
                if ($Members.Count -gt 5) { "WARN" } else { "INFO" }
            )

        } catch {
            Write-Log "  Groupe '$GroupName' introuvable ou inaccessible : $_" "WARN"
        }
    }

    Write-Log "Total membres Tier 0 uniques : $($Tier0Members.Count)"

    # Vérifier lesquels sont synchronisés dans Entra ID
    foreach ($SAM in $Tier0Members.Keys) {
        try {
            $EntraUser = Get-MgUser -Filter "onPremisesSamAccountName eq '$SAM'" `
                -Property UserPrincipalName, DisplayName, OnPremisesSyncEnabled, `
                          OnPremisesLastSyncDateTime, AccountEnabled `
                -ErrorAction Stop

            if ($EntraUser -and $EntraUser.OnPremisesSyncEnabled) {
                $Tier0Members[$SAM].UPN = $EntraUser.UserPrincipalName

                $Finding = "Compte Tier 0 synchronisé dans Entra ID : $SAM " +
                           "(Groupes : $($Tier0Members[$SAM].Groups -join ', ')). " +
                           "Dernière sync : $($EntraUser.OnPremisesLastSyncDateTime)"

                Write-Log "  CRITIQUE : $Finding" "FOUND"

                Add-Result `
                    -Category "Tier0-Sync" `
                    -ObjectName $SAM `
                    -ObjectType "User-Admin" `
                    -Finding $Finding `
                    -RiskLevel "CRITIQUE" `
                    -RegulatoryRef "FINMA §42 · DORA Art.9 · ISO 27001 A.8.2" `
                    -RemediationHint "Exclure ce compte de la synchronisation via les règles de filtrage Entra Connect (OU ou attribut). Ne jamais supprimer directement dans Entra ID."

                $Tier0SyncedUsers += $SAM
            }
        } catch {
            Write-Log "  Erreur vérification Entra ID pour $SAM : $_" "WARN"
        }
    }

    if ($Tier0SyncedUsers.Count -eq 0) {
        Write-Log "Aucun compte Tier 0 synchronisé — conforme" "SUCCESS"
    } else {
        $TopFindings.Add("CRITIQUE : $($Tier0SyncedUsers.Count) compte(s) Tier 0 synchronisé(s) dans Entra ID → $($Tier0SyncedUsers -join ', ')")
    }

} else {
    Write-Log "Périmètre 1 ignoré — modules AD et/ou Graph non disponibles" "WARN"
    $SkippedChecks.Add("P1 — Comptes Tier 0 synchronisés")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 2 — COMPTE DE SERVICE ENTRA CONNECT
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 2 — COMPTE DE SERVICE ENTRA CONNECT"
Write-Log "Analyse des droits du compte de service utilisé par Entra Connect"

$SyncServiceAccount = $null
$SyncServiceAccountRisks = @()

if ($ADSyncAvailable) {

    $GetSyncConfig = {
        Import-Module ADSync -ErrorAction SilentlyContinue
        $Connectors = Get-ADSyncConnector -ErrorAction SilentlyContinue
        $Scheduler  = Get-ADSyncScheduler -ErrorAction SilentlyContinue
        @{
            Connectors = $Connectors | Select-Object Name, Type, ConnectorTypeName
            Scheduler  = $Scheduler  | Select-Object SyncCycleEnabled, CurrentlyRunning, NextSyncCyclePolicyType, SyncCycleInterval
        }
    }

    try {
        $SyncConfig = if ($EntraConnectServer -and $ADSyncSession) {
            Invoke-Command -Session $ADSyncSession -ScriptBlock $GetSyncConfig
        } else {
            & $GetSyncConfig
        }

        Write-Log "Connecteurs Entra Connect trouvés : $($SyncConfig.Connectors.Count)"
        foreach ($Conn in $SyncConfig.Connectors) {
            Write-Log "  Connecteur : '$($Conn.Name)' — Type : $($Conn.ConnectorTypeName)"
        }

        Write-Log "Planificateur sync : activé=$($SyncConfig.Scheduler.SyncCycleEnabled), intervalle=$($SyncConfig.Scheduler.SyncCycleInterval)"

    } catch {
        Write-Log "Erreur lecture configuration ADSync : $_" "WARN"
    }

    # Rechercher le compte de service MSOL_ ou ADConnect
    if ($ADAvailable) {
        try {
            $ADParams = @{ ErrorAction = "Stop" }
            if ($DomainController) { $ADParams.Server = $DomainController }

            $SyncAccounts = Get-ADUser @ADParams -Filter {
                SamAccountName -like "MSOL_*" -or
                SamAccountName -like "AAD_*"  -or
                SamAccountName -like "Sync_*"
            } -Properties MemberOf, PasswordNeverExpires, PasswordLastSet, LastLogonDate

            foreach ($SvcAcct in $SyncAccounts) {
                Write-Log "  Compte de service détecté : $($SvcAcct.SamAccountName)"

                # Vérifications de sécurité
                if ($SvcAcct.PasswordNeverExpires) {
                    $Risk = "Mot de passe configuré sans expiration — risque si compromis"
                    Write-Log "    WARN : $Risk" "WARN"
                    $SyncServiceAccountRisks += $Risk

                    Add-Result `
                        -Category "SyncServiceAccount" `
                        -ObjectName $SvcAcct.SamAccountName `
                        -ObjectType "ServiceAccount" `
                        -Finding $Risk `
                        -RiskLevel "MOYEN" `
                        -RegulatoryRef "ISO 27001 A.8.2 · FINMA §42" `
                        -RemediationHint "Activer la rotation automatique du mot de passe via une GMSA ou documenter la procédure de rotation manuelle périodique."
                }

                # Vérifier si le compte est dans des groupes à privilèges excessifs
                foreach ($Group in $SvcAcct.MemberOf) {
                    $GroupName = ($Group -split ",")[0] -replace "CN=", ""
                    $IsTier0   = $Tier0Groups | Where-Object { $GroupName -like "*$_*" }

                    if ($IsTier0) {
                        $Risk = "Compte de service Entra Connect membre d'un groupe Tier 0 : $GroupName"
                        Write-Log "    CRITIQUE : $Risk" "FOUND"
                        $SyncServiceAccountRisks += $Risk

                        Add-Result `
                            -Category "SyncServiceAccount" `
                            -ObjectName $SvcAcct.SamAccountName `
                            -ObjectType "ServiceAccount" `
                            -Finding $Risk `
                            -RiskLevel "CRITIQUE" `
                            -RegulatoryRef "FINMA §42 · DORA Art.9 · ISO 27001 A.8.2" `
                            -RemediationHint "Retirer immédiatement le compte de service des groupes Tier 0. Le compte Entra Connect nécessite uniquement : Replicate Directory Changes, Replicate Directory Changes All."
                    }
                }
            }

            if ($SyncAccounts.Count -eq 0) {
                Write-Log "Aucun compte de service MSOL_/AAD_/Sync_ trouvé en AD — vérification manuelle requise" "WARN"
            }

        } catch {
            Write-Log "Erreur recherche compte de service AD : $_" "WARN"
        }
    }

    if ($SyncServiceAccountRisks.Count -eq 0) {
        Write-Log "Compte de service Entra Connect : aucun risque majeur détecté" "SUCCESS"
    } else {
        $TopFindings.Add("Compte service Entra Connect : $($SyncServiceAccountRisks.Count) risque(s) → $($SyncServiceAccountRisks[0])")
    }

} else {
    Write-Log "Périmètre 2 partiellement ignoré — ADSync non disponible" "WARN"
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 3 — MODE DE SYNCHRONISATION
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 3 — MODE DE SYNCHRONISATION ET RISQUES ASSOCIÉS"

if ($GraphAvailable) {
    try {
        # Récupérer la configuration de l'organisation pour détecter le mode
        $OrgDetails = Get-MgOrganization -Property OnPremisesSyncEnabled, `
            OnPremisesLastSyncDateTime, OnPremisesProvisioningErrors `
            -ErrorAction Stop

        $Org = $OrgDetails | Select-Object -First 1

        Write-Log "Synchronisation on-premise activée : $($Org.OnPremisesSyncEnabled)"
        Write-Log "Dernière synchronisation           : $($Org.OnPremisesLastSyncDateTime)"

        if ($Org.OnPremisesLastSyncDateTime) {
            $SyncAge = [math]::Round(((Get-Date) - $Org.OnPremisesLastSyncDateTime).TotalHours, 1)
            Write-Log "Ancienneté de la dernière sync     : $SyncAge heures"

            if ($SyncAge -gt 3) {
                $Finding = "Dernière synchronisation il y a $SyncAge heures (seuil : 3h). " +
                           "Risque de désynchronisation des comptes désactivés on-premise."
                Write-Log "  WARN : $Finding" "WARN"

                Add-Result `
                    -Category "SyncHealth" `
                    -ObjectName "Tenant" `
                    -ObjectType "SyncConfiguration" `
                    -Finding $Finding `
                    -RiskLevel $(if ($SyncAge -gt 24) { "ÉLEVÉ" } else { "MOYEN" }) `
                    -RegulatoryRef "FINMA §38 · ISO 27001 A.8.16" `
                    -RemediationHint "Vérifier l'état du service ADSync sur le serveur Entra Connect. Investiguer les erreurs dans le journal des événements."

                if ($SyncAge -gt 24) {
                    $TopFindings.Add("ÉLEVÉ : Dernière sync il y a $SyncAge heures — comptes désactivés AD potentiellement encore actifs dans Entra ID")
                }
            } else {
                Write-Log "Synchronisation récente — OK" "SUCCESS"
            }
        }

        # Erreurs de provisioning
        if ($Org.OnPremisesProvisioningErrors -and $Org.OnPremisesProvisioningErrors.Count -gt 0) {
            Write-Log "Erreurs de provisioning on-premise : $($Org.OnPremisesProvisioningErrors.Count)" "FOUND"
            $TopFindings.Add("$($Org.OnPremisesProvisioningErrors.Count) erreur(s) de synchronisation active(s) dans Entra ID")

            foreach ($Error in $Org.OnPremisesProvisioningErrors | Select-Object -First 5) {
                Write-Log "  Erreur : $($Error.Category) — $($Error.OccurredDateTime)" "WARN"
            }
        } else {
            Write-Log "Aucune erreur de provisioning on-premise détectée" "SUCCESS"
        }

        # Détecter le mode (PHS vs PTA vs Fédération)
        # Le mode se déduit de la configuration des domaines fédérés
        $Domains = Get-MgDomain -All -ErrorAction SilentlyContinue
        $FederatedDomains = $Domains | Where-Object { $_.AuthenticationType -eq "Federated" }
        $ManagedDomains   = $Domains | Where-Object { $_.AuthenticationType -eq "Managed" }

        Write-Log "Domaines fédérés  : $($FederatedDomains.Count)"
        Write-Log "Domaines managés  : $($ManagedDomains.Count)"

        if ($FederatedDomains.Count -gt 0) {
            $FedDetails = $FederatedDomains | Select-Object -ExpandProperty Id
            Write-Log "  Domaines fédérés : $($FedDetails -join ', ')" "WARN"
            Write-Log "  Mode Fédération (ADFS) détecté — vérifier la configuration des certificats SAML" "WARN"

            # Vérifier les certificats de fédération SAML
            foreach ($FedDomain in $FederatedDomains) {
                $FedConfig = Get-MgDomainFederationConfiguration -DomainId $FedDomain.Id -ErrorAction SilentlyContinue
                if ($FedConfig) {
                    foreach ($Config in $FedConfig) {
                        if ($Config.PassiveSignInUri) {
                            Write-Log "    IdP URI : $($Config.PassiveSignInUri)"
                        }
                        # Vérifier expiration certificat si accessible
                        if ($Config.SigningCertificate) {
                            try {
                                $CertBytes = [System.Convert]::FromBase64String($Config.SigningCertificate)
                                $Cert      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
                                $DaysLeft  = ($Cert.NotAfter - (Get-Date)).Days

                                Write-Log "    Certificat SAML expire dans : $DaysLeft jours ($($Cert.NotAfter.ToString('yyyy-MM-dd')))"

                                if ($DaysLeft -lt 30) {
                                    $Finding = "Certificat SAML du domaine fédéré '$($FedDomain.Id)' expire dans $DaysLeft jours. Expiration = tous les utilisateurs fédérés ne peuvent plus s'authentifier."
                                    Write-Log "    CRITIQUE : $Finding" "FOUND"

                                    Add-Result `
                                        -Category "FederationCert" `
                                        -ObjectName $FedDomain.Id `
                                        -ObjectType "FederatedDomain" `
                                        -Finding $Finding `
                                        -RiskLevel $(if ($DaysLeft -lt 7) { "CRITIQUE" } else { "ÉLEVÉ" }) `
                                        -RegulatoryRef "FINMA §38 · ISO 27001 A.8.17" `
                                        -RemediationHint "Renouveler le certificat SAML en urgence. Procédure : Update-MgDomainFederationConfiguration ou via le portail ADFS."

                                    $TopFindings.Add("$(if ($DaysLeft -lt 7) { 'CRITIQUE' } else { 'ÉLEVÉ' }) : Certificat SAML '$($FedDomain.Id)' expire dans $DaysLeft jours")
                                } elseif ($DaysLeft -lt 60) {
                                    Write-Log "    WARN : Certificat expire dans $DaysLeft jours — planifier le renouvellement" "WARN"
                                    Add-Result `
                                        -Category "FederationCert" `
                                        -ObjectName $FedDomain.Id `
                                        -ObjectType "FederatedDomain" `
                                        -Finding "Certificat SAML expire dans $DaysLeft jours — renouvellement à planifier" `
                                        -RiskLevel "MOYEN" `
                                        -RegulatoryRef "ISO 27001 A.8.17" `
                                        -RemediationHint "Planifier le renouvellement du certificat SAML avant expiration."
                                } else {
                                    Write-Log "    Certificat SAML valide ($DaysLeft jours restants)" "SUCCESS"
                                }
                            } catch {
                                Write-Log "    Impossible de lire le certificat SAML : $_" "WARN"
                            }
                        }
                    }
                }
            }
        } else {
            Write-Log "Mode Managed (PHS ou PTA) — pas de dépendance ADFS" "SUCCESS"
        }

    } catch {
        Write-Log "Erreur lecture configuration organisation Entra ID : $_" "WARN"
    }
} else {
    Write-Log "Périmètre 3 ignoré — Microsoft Graph non disponible" "WARN"
    $SkippedChecks.Add("P3 — Mode de synchronisation")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 4 — ATTRIBUTS SENSIBLES SYNCHRONISÉS
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 4 — ATTRIBUTS SENSIBLES SYNCHRONISÉS INUTILEMENT"
Write-Log "Attributs sensibles à vérifier : $($SensitiveAttributes -join ', ')"

if ($ADSyncAvailable) {
    try {
        $GetSyncRules = {
            param($SensitiveAttrs)
            Import-Module ADSync -ErrorAction SilentlyContinue
            $Rules = Get-ADSyncRule -ErrorAction SilentlyContinue |
                Where-Object { $_.Direction -eq "Outbound" -or $_.Direction -eq "Inbound" }
            $SyncedAttrs = @{}
            foreach ($Rule in $Rules) {
                foreach ($Transform in $Rule.AttributeFlowMappings) {
                    if ($Transform.Source -and $SensitiveAttrs -contains $Transform.Source) {
                        if (-not $SyncedAttrs.ContainsKey($Transform.Source)) {
                            $SyncedAttrs[$Transform.Source] = @()
                        }
                        $SyncedAttrs[$Transform.Source] += $Rule.Name
                    }
                }
            }
            $SyncedAttrs
        }

        $SyncedSensitiveAttrs = if ($EntraConnectServer -and $ADSyncSession) {
            Invoke-Command -Session $ADSyncSession -ScriptBlock $GetSyncRules `
                -ArgumentList (, $SensitiveAttributes)
        } else {
            & $GetSyncRules -SensitiveAttrs $SensitiveAttributes
        }

        if ($SyncedSensitiveAttrs.Count -gt 0) {
            Write-Log "Attributs sensibles synchronisés détectés : $($SyncedSensitiveAttrs.Count)" "FOUND"
            foreach ($Attr in $SyncedSensitiveAttrs.Keys) {
                $Rules = $SyncedSensitiveAttrs[$Attr] -join ", "
                Write-Log "  $Attr → synchronisé via règle(s) : $Rules" "WARN"

                Add-Result `
                    -Category "SensitiveAttributes" `
                    -ObjectName $Attr `
                    -ObjectType "SyncAttribute" `
                    -Finding "Attribut sensible '$Attr' synchronisé vers Entra ID via règle(s) : $Rules" `
                    -RiskLevel "MOYEN" `
                    -RegulatoryRef "FINMA §38 · RGPD Art.5 · ISO 27001 A.5.34" `
                    -RemediationHint "Évaluer si cet attribut est nécessaire dans Entra ID. Si non, exclure de la règle de synchronisation dans Entra Connect Sync Rules Editor."
            }
            $TopFindings.Add("$($SyncedSensitiveAttrs.Count) attribut(s) sensible(s) synchronisé(s) inutilement vers Entra ID : $($SyncedSensitiveAttrs.Keys -join ', ')")
        } else {
            Write-Log "Aucun attribut sensible synchronisé détecté dans les règles ADSync" "SUCCESS"
        }

    } catch {
        Write-Log "Erreur lecture règles ADSync : $_" "WARN"
        $SkippedChecks.Add("P4 — Attributs sensibles (erreur lecture règles ADSync)")
    }
} else {
    Write-Log "Périmètre 4 ignoré — module ADSync non disponible" "WARN"
    $SkippedChecks.Add("P4 — Attributs sensibles synchronisés (ADSync requis)")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 5 — SEAMLESS SSO
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 5 — SEAMLESS SSO (KERBEROS)"
Write-Log "Vérification du compte AZUREADSSOACC$ et de la configuration Kerberos"

if ($ADAvailable) {
    try {
        $ADParams = @{ ErrorAction = "SilentlyContinue" }
        if ($DomainController) { $ADParams.Server = $DomainController }

        $SSSOAccount = Get-ADComputer @ADParams `
            -Filter { SamAccountName -eq "AZUREADSSOACC$" } `
            -Properties PasswordLastSet, PasswordNeverExpires, WhenCreated, Description

        if ($SSSOAccount) {
            Write-Log "Compte Seamless SSO trouvé : AZUREADSSOACC$" "SUCCESS"
            Write-Log "  Créé le           : $($SSSOAccount.WhenCreated)"
            Write-Log "  Mot de passe set  : $($SSSOAccount.PasswordLastSet)"
            Write-Log "  PwdNeverExpires   : $($SSSOAccount.PasswordNeverExpires)"

            $PwdAge = if ($SSSOAccount.PasswordLastSet) {
                [math]::Round(((Get-Date) - $SSSOAccount.PasswordLastSet).TotalDays, 0)
            } else { 9999 }

            Write-Log "  Âge du mot de passe : $PwdAge jours"

            # Le ticket Kerberos AZUREADSSOACC$ doit être renouvelé tous les 30 jours
            # (Microsoft recommande une rotation tous les 30 jours)
            if ($PwdAge -gt 30) {
                $Finding = "Mot de passe du compte AZUREADSSOACC$ non renouvelé depuis $PwdAge jours. " +
                           "Microsoft recommande une rotation tous les 30 jours pour limiter la fenêtre " +
                           "d'exploitation d'un ticket Kerberos forgé (Golden Ticket style)."
                $RiskLvl = if ($PwdAge -gt 90) { "ÉLEVÉ" } else { "MOYEN" }
                Write-Log "  $RiskLvl : $Finding" "WARN"

                Add-Result `
                    -Category "SeamlessSSO" `
                    -ObjectName "AZUREADSSOACC$" `
                    -ObjectType "ComputerAccount" `
                    -Finding $Finding `
                    -RiskLevel $RiskLvl `
                    -RegulatoryRef "FINMA §42 · ISO 27001 A.8.5" `
                    -RemediationHint "Renouveler le mot de passe via Update-AzureADSSOForest dans le module MSOnline, ou via l'assistant Entra Connect. À faire tous les 30 jours."

                if ($PwdAge -gt 90) {
                    $TopFindings.Add("ÉLEVÉ : Mot de passe AZUREADSSOACC$ non renouvelé depuis $PwdAge jours — risque de ticket Kerberos expiré ou exploitable")
                }
            } else {
                Write-Log "  Renouvellement récent — OK ($PwdAge jours)" "SUCCESS"
            }

        } else {
            Write-Log "Compte AZUREADSSOACC$ absent — Seamless SSO non configuré (ou mode PTA/Fédération)" "INFO"
        }

    } catch {
        Write-Log "Erreur vérification Seamless SSO : $_" "WARN"
        $SkippedChecks.Add("P5 — Seamless SSO (erreur lecture AD)")
    }
} else {
    Write-Log "Périmètre 5 ignoré — module ActiveDirectory non disponible" "WARN"
    $SkippedChecks.Add("P5 — Seamless SSO (module AD requis)")
}

# ─────────────────────────────────────────────
# PÉRIMÈTRE 6 — ERREURS DE SYNCHRONISATION ET OBJETS EN CONFLIT
# ─────────────────────────────────────────────

Write-Section "PÉRIMÈTRE 6 — ERREURS DE SYNCHRONISATION ET OBJETS EN CONFLIT"

if ($GraphAvailable) {
    try {
        # Objets avec erreurs de provisioning on-premise dans Entra ID
        Write-Log "Recherche des utilisateurs avec erreurs de synchronisation..."

        $UsersWithSyncErrors = Get-MgUser -All `
            -Filter "onPremisesProvisioningErrors/any(x:x/category ne null)" `
            -Property UserPrincipalName, DisplayName, Department, `
                      OnPremisesSamAccountName, OnPremisesProvisioningErrors `
            -ErrorAction SilentlyContinue

        if ($UsersWithSyncErrors -and $UsersWithSyncErrors.Count -gt 0) {
            Write-Log "Utilisateurs avec erreurs de sync : $($UsersWithSyncErrors.Count)" "FOUND"

            foreach ($User in $UsersWithSyncErrors | Select-Object -First 20) {
                foreach ($Error in $User.OnPremisesProvisioningErrors) {
                    $Finding = "Erreur de synchronisation : $($Error.Category) — " +
                               "Valeur conflictuelle : $($Error.Value) — " +
                               "Depuis le : $($Error.OccurredDateTime)"
                    Write-Log "  $($User.UserPrincipalName) : $($Error.Category)" "WARN"

                    Add-Result `
                        -Category "SyncErrors" `
                        -ObjectName $User.UserPrincipalName `
                        -ObjectType "User" `
                        -Finding $Finding `
                        -RiskLevel "MOYEN" `
                        -RegulatoryRef "ISO 27001 A.8.16 · FINMA §38" `
                        -RemediationHint "Corriger la valeur conflictuelle dans AD ($($Error.Value)). Erreur fréquente : doublons de ProxyAddresses ou UserPrincipalName."
                }
            }

            if ($UsersWithSyncErrors.Count -gt 20) {
                Write-Log "  (Affichage limité aux 20 premiers — $($UsersWithSyncErrors.Count) erreurs au total)" "WARN"
            }

            $TopFindings.Add("$($UsersWithSyncErrors.Count) objet(s) avec erreurs de synchronisation actives")
        } else {
            Write-Log "Aucune erreur de synchronisation active détectée" "SUCCESS"
        }

        # Objets dupliqués (Duplicate Attribute Resilience)
        Write-Log "Vérification des objets en quarantaine (Duplicate Attribute Resilience)..."
        $QuarantinedUsers = Get-MgUser -All `
            -Filter "onPremisesProvisioningErrors/any(x:x/category eq 'PropertyConflict')" `
            -Property UserPrincipalName, DisplayName, OnPremisesProvisioningErrors `
            -ErrorAction SilentlyContinue

        if ($QuarantinedUsers -and $QuarantinedUsers.Count -gt 0) {
            Write-Log "Objets en conflit d'attribut (PropertyConflict) : $($QuarantinedUsers.Count)" "WARN"
            $TopFindings.Add("$($QuarantinedUsers.Count) objet(s) en conflit d'attribut (PropertyConflict) — risque de comptes fantômes")
        }

    } catch {
        Write-Log "Erreur vérification objets sync Entra ID : $_" "WARN"
        $SkippedChecks.Add("P6 — Erreurs de synchronisation (erreur requête Graph)")
    }
} else {
    Write-Log "Périmètre 6 ignoré — Microsoft Graph non disponible" "WARN"
    $SkippedChecks.Add("P6 — Erreurs de synchronisation")
}

# ─────────────────────────────────────────────
# CALCUL DU SCORE
# ─────────────────────────────────────────────

Write-Section "CALCUL DU SCORE DE CONFORMITÉ"

$CritiqueCount = ($Results | Where-Object { $_.RiskLevel -eq "CRITIQUE" }).Count
$EleveCount    = ($Results | Where-Object { $_.RiskLevel -eq "ÉLEVÉ"    }).Count
$MoyenCount    = ($Results | Where-Object { $_.RiskLevel -eq "MOYEN"    }).Count
$TotalFindings = $Results.Count

# Score : déduit des findings par poids
# CRITIQUE : -25 pts chacun (plafonné à -75)
# ÉLEVÉ    : -10 pts chacun (plafonné à -30)
# MOYEN    :  -5 pts chacun (plafonné à -20)
$Score = 100
$Score -= [math]::Min($CritiqueCount * 25, 75)
$Score -= [math]::Min($EleveCount    * 10, 30)
$Score -= [math]::Min($MoyenCount    *  5, 20)
$Score  = [math]::Max($Score, 0)

# Bonus si certaines vérifications étaient impossibles
$SkipPenalty = $SkippedChecks.Count * 3
$Score       = [math]::Max($Score - $SkipPenalty, 0)

$ScoreLabel = switch ($true) {
    { $Score -ge 95 } { "OPTIMAL"     ; break }
    { $Score -ge 80 } { "CONFORME"    ; break }
    { $Score -ge 60 } { "PARTIEL"     ; break }
    { $Score -ge 40 } { "INSUFFISANT" ; break }
    default           { "CRITIQUE"    }
}

Write-Log "Score HybridSync : $Score/100 ($ScoreLabel)"
Write-Log "Findings total   : $TotalFindings (CRITIQUE:$CritiqueCount ÉLEVÉ:$EleveCount MOYEN:$MoyenCount)"
Write-Log "Vérifications ignorées : $($SkippedChecks.Count)"

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
    }}, Category, ObjectName |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Log "CSV exporté : $CsvPath ($($Results.Count) findings)" "SUCCESS"

# ─────────────────────────────────────────────
# EXPORT JSON
# ─────────────────────────────────────────────

Write-Section "EXPORT JSON"

$JsonReport = [ordered]@{
    "_schema"           = "iam-federation-lab/audit-hybridsync/v1.0"
    "RunId"             = $RunId
    "Domain"            = "D6 — Hybrid Synchronization"
    "Client"            = $Client
    "Date"              = $DateStamp
    "GeneratedAt"       = $TimeStamp
    "Score"             = $Score
    "ScoreLabel"        = $ScoreLabel
    "Tier0GroupsChecked"= $Tier0Groups
    "Statistics"        = [ordered]@{
        "TotalFindings"       = $TotalFindings
        "CRITIQUE"            = $CritiqueCount
        "ÉLEVÉ"               = $EleveCount
        "MOYEN"               = $MoyenCount
        "Tier0SyncedUsers"    = $Tier0SyncedUsers.Count
        "SkippedChecks"       = $SkippedChecks.Count
    }
    "FindingsByCategory"= ($Results | Group-Object Category |
        ForEach-Object { @{ $_.Name = $_.Count } })
    "SkippedChecks"     = $SkippedChecks
    "TopFindings"       = $TopFindings
    "RegulatoryMapping" = [ordered]@{
        "FINMA_2023_1_S42"  = if ($CritiqueCount -gt 0) { "NON_CONFORME" } elseif ($EleveCount -gt 0) { "PARTIEL" } else { "CONFORME" }
        "CSSF_22806_Ctrl8"  = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
        "DORA_Art9"         = if ($CritiqueCount -gt 0) { "NON_CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "CONFORME" }
        "ISO27001_A816"     = if ($Score -ge 80) { "CONFORME" } elseif ($Score -ge 60) { "PARTIEL" } else { "NON_CONFORME" }
    }
    "NextStep"          = "Remediate-HybridSync.ps1 -AuditReport '$CsvPath' -DryRun"
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
Write-Host "  │  SCORE HYBRID SYNC : $($Score.ToString().PadRight(3))/100 — $($ScoreLabel.PadRight(13))│" -ForegroundColor $ScoreColor
Write-Host "  ├──────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
Write-Host "  │  Findings CRITIQUE  : $($CritiqueCount.ToString().PadRight(31))│" -ForegroundColor $(if ($CritiqueCount -gt 0) { "Red" } else { "White" })
Write-Host "  │  Findings ÉLEVÉ     : $($EleveCount.ToString().PadRight(31))│" -ForegroundColor $(if ($EleveCount -gt 0) { "Yellow" } else { "White" })
Write-Host "  │  Findings MOYEN     : $($MoyenCount.ToString().PadRight(31))│" -ForegroundColor White
Write-Host "  │  Comptes Tier0 sync : $($Tier0SyncedUsers.Count.ToString().PadRight(31))│" -ForegroundColor $(if ($Tier0SyncedUsers.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  │  Vérif. ignorées    : $($SkippedChecks.Count.ToString().PadRight(31))│" -ForegroundColor $(if ($SkippedChecks.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  └──────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

if ($SkippedChecks.Count -gt 0) {
    Write-Host "  VÉRIFICATIONS IGNORÉES (droits/modules manquants) :" -ForegroundColor Yellow
    foreach ($S in $SkippedChecks) { Write-Host "  ⬜ $S" -ForegroundColor Gray }
    Write-Host ""
}

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
Write-Host "  .\Remediate-HybridSync.ps1 -AuditReport '$CsvPath' -DryRun" -ForegroundColor White
Write-Host ""

Write-Log "Audit HybridSync terminé — Score : $Score/100 ($ScoreLabel) — Run ID : $RunId" "SUCCESS"

if ($GraphAvailable)  { Disconnect-MgGraph     -ErrorAction SilentlyContinue }
if ($ADSyncSession)   { Remove-PSSession $ADSyncSession -ErrorAction SilentlyContinue }
