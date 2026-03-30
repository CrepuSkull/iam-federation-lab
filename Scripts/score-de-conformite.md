{
  "Domain": "MFA Coverage",
  "Client": "[CLIENT]",
  "Date": "2026-03-29",
  "Score": 62,
  "ScoreLabel": "INSUFFISANT",
  "TotalEntities": 245,
  "Compliant": 152,
  "NonCompliant": 93,
  "Critical": 12,
  "RegulatoryMapping": {
    "FINMA_42": "PARTIAL",
    "CSSF_Ctrl7": "FAIL",
    "DORA_Art9": "PARTIAL"
  },
  "TopFindings": [
    "12 comptes sans aucune méthode MFA — dont 3 comptes admin",
    "34 comptes avec SMS uniquement — méthode faible",
    "Département Finance : taux MFA 41% (sous seuil critique)"
  ]
}
```


**Échelle de score :**

| Score | Label | Couleur | Signification |
|-------|-------|---------|---------------|
| 0–39 | CRITIQUE | 🔴 | Non-conformité majeure, action immédiate |
| 40–59 | INSUFFISANT | 🟠 | Écarts significatifs, plan de remédiation requis |
| 60–79 | PARTIEL | 🟡 | Base correcte, lacunes documentées |
| 80–94 | CONFORME | 🟢 | Conforme avec points d'amélioration mineurs |
| 95–100 | OPTIMAL | ✅ | Conformité totale, maintien à surveiller |

---

### Spécifications par domaine

---

#### D1 — Audit-MFACoverage.ps1

**Prérequis :** Droits `Reports Reader` ou `Security Reader` sur Entra ID.

**Ce que le script lit :**
- `Get-MgUser` avec propriétés `StrongAuthenticationMethods`, `StrongAuthenticationRequirements`
- Méthodes d'authentification via `Get-MgUserAuthenticationMethod`
- Politiques MFA via `Get-MgPolicyAuthenticationMethodPolicy`
- Logs de connexion pour détecter les méthodes réellement utilisées vs enregistrées

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Taux MFA global | comptes avec ≥1 méthode / total comptes actifs | < 80% |
| Comptes sans MFA | comptes actifs, 0 méthode enregistrée | > 0 si admin |
| MFA faible (SMS only) | comptes avec SMS comme unique méthode | > 20% |
| MFA fort (FIDO2/WHfB) | comptes avec clé physique ou Windows Hello | — informatif |
| Exceptions non documentées | exclusions des politiques MFA sans justification | > 0 |
| MFA enregistré jamais utilisé | méthode enregistrée, 0 utilisation 90j | — informatif |

**Rapport CSV — colonnes :**
`UPN, DisplayName, Department, AccountEnabled, MFARegistered, MFAMethods, LastMFAUsed, MFAStrength, ExcludedFromPolicy, RiskLevel`

---

#### D2 — Audit-LegacyAuth.ps1

**Prérequis :** `Security Reader` Entra ID + accès logs de connexion (Entra ID P1 minimum).

**Ce que le script lit :**
- Logs de connexion Entra ID filtrés sur `clientAppUsed` (valeurs legacy : `Exchange ActiveSync`, `IMAP4`, `MAPI`, `Other clients`, `POP3`, `SMTP`, `Exchange Web Services`)
- Politiques d'accès conditionnel existantes ciblant le blocage legacy
- Configuration Exchange Online : `Get-AuthenticationPolicy`, `Get-TransportConfig`
- Présence de flux ROPC (Resource Owner Password Credentials) dans les logs OAuth

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Comptes avec connexions legacy actives | UPN ayant utilisé un protocole legacy dans les 30 derniers jours | > 0 |
| Volume connexions legacy | nombre total de connexions legacy / total connexions | > 5% |
| Protocoles actifs détectés | liste des protocoles effectivement utilisés | SMTP/IMAP = critique |
| Couverture blocage CA | politique de blocage legacy couvre X% des utilisateurs | < 100% |
| Flux ROPC détectés | applications utilisant ROPC (contourne MFA) | > 0 |

**Rapport CSV — colonnes :**
`UPN, DisplayName, Department, Protocol, LastUsed, ConnectionCount30d, AppDisplayName, IPAddress, CountryCode, BlockedByCA, RiskLevel`

---

#### D6 — Audit-HybridSync.ps1

**Prérequis :** `Directory Reader` AD + `Hybrid Identity Administrator` Entra ID.

**Ce que le script lit :**
- Configuration Entra Connect via `Get-ADSyncConnector`, `Get-ADSyncScheduler`
- Compte de service Entra Connect et ses permissions AD effectives
- Objets exclus de la synchronisation (filtres OU, groupes, attributs)
- Comptes Tier 0 / admins de domaine synchronisés vers le cloud (ne devraient pas l'être)
- Attributs synchronisés : données sensibles RH (salary, personnalInfo) potentiellement exposées
- Seamless SSO : présence du compte `AZUREADSSOACC$` et configuration Kerberos
- Erreurs de synchronisation en cours

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Admins Tier 0 synchronisés | comptes Domain Admins présents dans Entra ID | > 0 |
| Permissions service Entra Connect | droits effectifs du compte de service vs minimum requis | over-privileged |
| Attributs sensibles synchronisés | présence d'attributs RH non nécessaires dans le schéma sync | tout attribut non justifié |
| Erreurs sync actives | objets en erreur de synchronisation | > 0 |
| Âge du certificat Seamless SSO | durée de validité du cert AZUREADSSOACC$ | < 30j = critique |

**Rapport CSV — colonnes :**
`ObjectType, SamAccountName, UPN, SyncStatus, SyncErrors, IsTier0, SensitiveAttributesSynced, ConnectorName, RiskLevel`

---

#### D5 — Audit-FederationTrusts.ps1

**Prérequis :** `Security Reader` + `External Identity Provider` reader.

**Ce que le script lit :**
- Comptes guests Entra B2B : `Get-MgUser -Filter "userType eq 'Guest'"`
- Domaines fédérés : `Get-MgDomain` avec `federationConfiguration`
- Certificats SAML des IdP fédérés et leurs dates d'expiration
- Politiques d'accès conditionnel spécifiques aux guests
- Paramètres de collaboration externe : `Get-MgPolicyCrossTenantAccessPolicy`
- Restrictions de tenant (blocage accès tenants externes non autorisés)
- Si Keycloak : API admin Keycloak pour inventaire realms, clients, flux

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Guests sans connexion 90j | comptes guest actifs, 0 connexion depuis 90j | > 0 |
| Certificats SAML expirant | certs fédération expiration < 30j | > 0 |
| Guests sans politique CA | guests non couverts par une politique d'accès conditionnel | > 0 |
| Domaines fédérés non documentés | domaines fédérés sans justification dans la config | > 0 |
| Collaboration externe ouverte | paramètres autorisant invitations depuis tout domaine | ouvert = critique |

**Rapport CSV — colonnes :**
`EntityType, DisplayName, ExternalOrg, CreatedDate, LastSignIn, DaysSinceSignIn, FederationType, CertExpiry, CoveredByCA, RiskLevel`

---

#### D3 — Audit-ConditionalAccess.ps1

**Prérequis :** `Security Reader` Entra ID.

**Ce que le script lit :**
- Toutes les politiques via `Get-MgIdentityConditionalAccessPolicy`
- État : activé / rapport seul / désactivé
- Applications couvertes vs non couvertes
- Utilisateurs et groupes inclus / exclus
- Conditions : localisation, conformité terminal, risque de connexion, risque utilisateur
- Contrôles : MFA requis, terminal conforme requis, session limitée

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Applications sans politique | apps Entra ID sans aucune politique CA active | > 0 si app sensible |
| Utilisateurs exclus de toutes les politiques | comptes actifs non couverts par aucune politique | > breakglass accounts |
| Politiques sans condition localisation | politiques n'excluant pas les pays à risque | — informatif |
| Politiques en mode rapport seul | politiques non encore actives | > 0 = risque non bloqué |
| Conflits détectés | politiques contradictoires sur même périmètre | > 0 |

**Rapport CSV — colonnes :**
`PolicyName, State, UsersIncluded, UsersExcluded, AppsIncluded, LocationCondition, DeviceCompliance, MFARequired, RiskCondition, ConflictsWith, RiskLevel`

---

#### D4 — Audit-OAuthApplications.ps1

**Prérequis :** `Application Administrator` reader ou `Cloud Application Administrator`.

**Ce que le script lit :**
- Applications d'entreprise : `Get-MgServicePrincipal`
- Inscriptions d'applications : `Get-MgApplication`
- Permissions accordées : `Get-MgServicePrincipalAppRoleAssignment` + OAuth2PermissionGrants
- Secrets et certificats : dates d'expiration
- Logs de connexion par application : dernière utilisation
- Consentements utilisateurs : `Get-MgOAuth2PermissionGrant -Filter "consentType eq 'Principal'"`

**Indicateurs calculés :**

| Indicateur | Calcul | Seuil critique |
|------------|--------|----------------|
| Apps avec permissions `*.All` | permissions Microsoft Graph de type `*.All` accordées | toute permission non justifiée |
| Permissions Application vs Delegated | ratio Application / Delegated (Application = plus risqué) | Application > 20% |
| Apps sans connexion 90j | applications actives sans utilisation récente | > 0 |
| Secrets expirés ou expirant 30j | certificats/secrets d'app dans la zone critique | > 0 |
| Consentements utilisateurs | OAuth grants accordés par des utilisateurs individuels | > 0 si non validés |

**Rapport CSV — colonnes :**
`AppName, AppId, Type, Permissions, PermissionType, HighRiskPermissions, LastSignIn, SecretExpiry, ConsentedBy, RiskLevel`

---

### Spécification du CSV de remédiation — détail

C'est la pièce centrale de la couche remédiation. Son format est commun à tous les domaines.

**Flux complet :**
```
Script Audit      →  Rapport CSV brut (lecture seule, scellé)
        ↓
Script Remediate  →  Proposals CSV (DryRun automatique)
        ↓
Consultant/RSSI   →  Remplit colonne Valider (OUI/NON) + Commentaire
        ↓
Script Remediate  →  Lit CSV validé, exécute OUI uniquement
        ↓
                     Executed CSV + Log + Rapport scellé
