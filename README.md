# iam-federation-lab

> **Audit de fédération et d'authentification — Environnement hybride AD + Entra ID**  
> *Détection des vecteurs d'attaque · Remédiation contrôlée · Conformité FINMA · CSSF · DORA*

---

## Position dans l'écosystème IAM-Lab Framework

| Repo | Rôle | Question centrale |
|------|------|-------------------|
| [iam-foundation-lab](https://github.com/CrepuSkull/iam-foundation-lab) | Audit AD · Migration Entra ID · Fédération OIDC | Quel est l'état réel de mon parc d'identités ? |
| [IAM-Lab-Identity-Lifecycle](https://github.com/CrepuSkull/IAM-Lab-Identity-Lifecycle) | Automatisation JML · RBAC · Orphelins | Comment garantir que chaque identité a les bons droits ? |
| [iam-governance-lab](https://github.com/CrepuSkull/iam-governance-lab) | Recertification · Contrôle continu | Comment maintenir la conformité dans le temps ? |
| [iam-evidence-sealer](https://github.com/CrepuSkull/iam-evidence-sealer) | Scellage SHA-256 · RFC 3161 | Comment prouver ce qui a été fait ? |
| **iam-federation-lab** | Authentification · Fédération · SSO · MFA | **Comment les identités prouvent-elles qu'elles sont bien ce qu'elles prétendent être ?** ← *vous êtes ici* |

Les 4 premiers repos répondent à **"qui a accès à quoi"** — dimension des droits et de la gouvernance.  
`iam-federation-lab` répond à **"comment est-ce qu'on prouve qu'on est bien qui on dit être"** — dimension de l'authentification et de la confiance.

Un compte peut avoir les bons droits (les 4 autres repos sont propres) **et** être compromettable parce que son mécanisme d'authentification est faible : Basic Auth actif, absence de MFA, ticket Kerberos Seamless SSO non renouvelé, permissions OAuth *.All sans justification.

---

## Les 6 domaines d'audit

| # | Domaine | Vecteur d'attaque principal | Priorité |
|---|---------|----------------------------|----------|
| **D1** | MFA Coverage | Compromission par phishing / credential stuffing | 🔴 Critique |
| **D2** | Legacy Auth | Contournement MFA via SMTP, NTLM, Basic Auth, ROPC | 🔴 Critique |
| **D6** | Hybrid Sync | Propagation compromission on-premise → cloud, Tier 0 synchronisés | 🔴 Haute |
| **D5** | Federation & Guests | Guests orphelins, certificats SAML expirés, collaboration externe ouverte | 🟡 Moyenne |
| **D3** | Conditional Access | Gaps de couverture, politiques Report-Only inactives, absence de conditions risque | 🟡 Moyenne |
| **D4** | OAuth/OIDC Apps | Permissions Application *.All, secrets expirés, consentements utilisateurs orphelins | 🟡 Moyenne |

---

## Architecture — deux couches strictement séparées

```
┌──────────────────────────────────────────────────────────────┐
│  COUCHE AUDIT — Lecture seule absolue                        │
│  audit/Audit-*.ps1                                           │
│                                                              │
│  → Connexion en lecture seule (Security Reader minimum)      │
│  → Mesure, calcule un score /100, produit CSV + JSON + LOG   │
│  → Ne modifie rien, ne supprime rien, ne propose rien        │
└─────────────────────────┬────────────────────────────────────┘
                          │ rapport CSV
                          ▼
┌──────────────────────────────────────────────────────────────┐
│  COUCHE REMÉDIATION — Validation humaine obligatoire         │
│  remediate/Remediate-*.ps1                                   │
│                                                              │
│  Temps 1 — DryRun automatique                                │
│    Génère un CSV de propositions, colonne Valider vide       │
│    SHA-256 posé immédiatement sur le CSV propositions        │
│                                                              │
│  Temps 2 — Validation hors script (Excel)                    │
│    Renseigner OUI · Ajouter un commentaire · Sauvegarder     │
│    Validation métier / infrastructure selon le domaine       │
│                                                              │
│  Temps 3 — Exécution sur CSV validé                          │
│    Vérification intégrité colonnes immuables                 │
│    Exécution uniquement des lignes marquées OUI              │
│    SHA-256 posé sur CSV validé + rapport d'exécution         │
└──────────────────────────────────────────────────────────────┘
```

**Règle absolue** : seul `OUI` exact (majuscules) déclenche une action. Toute autre valeur, y compris le vide, est ignorée — jamais d'exécution sur ambiguïté.

---

## Prérequis

### Modules PowerShell

```powershell
# Requis pour tous les domaines Graph
Install-Module Microsoft.Graph -Scope CurrentUser

# Requis pour D2 (analyse Exchange Online)
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# Requis pour D5 Keycloak (si -KeycloakUrl fourni)
# Aucun module supplémentaire — appels REST natifs PowerShell

# Requis pour D6 Hybrid Sync (exécution sur serveur Entra Connect)
# Le module ADSync est installé avec Entra Connect — ou via -EntraConnectServer
```

### Rôles Entra ID (lecture seule — phase audit)

| Domaine | Rôle minimum |
|---------|-------------|
| D1 MFA Coverage | Security Reader |
| D2 Legacy Auth | Security Reader + Reports Reader |
| D3 Conditional Access | Security Reader |
| D4 OAuth Applications | Cloud Application Administrator (Reader) |
| D5 Federation Trusts | Security Reader |
| D6 Hybrid Sync | Hybrid Identity Administrator (Reader) |

---

## Démarrage rapide — D1 MFA Coverage

```powershell
# Étape 1 — Audit (lecture seule)
.\audit\Audit-MFACoverage.ps1 -Client "Banque XYZ" -OutputPath ".\Reports"

# Étape 2 — Générer les propositions
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" -Client "Banque XYZ"
# → Ouvrir le CSV, renseigner OUI dans la colonne Valider, sauvegarder

# Étape 3 — Simuler avant d'exécuter (toujours)
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ" -DryRun

# Étape 4 — Exécuter
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ"

# Étape 5 — Sceller (depuis iam-evidence-sealer/)
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-federation-lab\audit\Audit-MFACoverage.ps1" `
    -Client "Banque XYZ" -Sign -Timestamp
```

---

## Structure du repo

```
iam-federation-lab/
├── audit/
│   ├── Audit-MFACoverage.ps1          D1 — Taux MFA, force des méthodes, exclusions CA
│   ├── Audit-LegacyAuth.ps1           D2 — SMTP/IMAP/NTLM/ROPC actifs, couverture blocage CA
│   ├── Audit-HybridSync.ps1           D6 — Tier 0 sync, compte service, Seamless SSO, erreurs
│   ├── Audit-FederationTrusts.ps1     D5 — Guests B2B, SAML, collaboration externe, Keycloak
│   ├── Audit-ConditionalAccess.ps1    D3 — Inventaire CA, gaps couverture, conditions risque
│   └── Audit-OAuthApplications.ps1   D4 — Permissions *.All, secrets, consentements, orphelines
├── remediate/
│   ├── Remediate-MFACoverage.ps1      D1 — ForceEnrollmentMFA, ExcludeFromException
│   ├── Remediate-LegacyAuth.ps1       D2 — BlockLegacyViaCA, DisableBasicAuthSmtp/Imap/Pop
│   ├── Remediate-HybridSync.ps1       D6 — ExcludeTier0FromSync, RotateSSOAccountPassword
│   ├── Remediate-FederationTrusts.ps1 D5 — DisableInactiveGuest, RestrictInvitePolicy
│   ├── Remediate-ConditionalAccess.ps1 D3 — CreateBaselineCAPolicy, EnableReportOnlyPolicy
│   └── Remediate-OAuthApplications.ps1 D4 — RevokeUserConsent, RenewAppSecret, DisableApp
├── templates/
│   └── Validation-Template.csv        Format CSV de validation réutilisable
├── wiki/                              Documentation GitHub Wiki (4 pages)
├── README.md
└── .gitignore
```

---

## Structure des livrables

```
Reports/
├── Audit-<Domaine>_<date>.csv                        ← Findings triés par niveau de risque
├── Audit-<Domaine>_<date>.json                       ← Score /100 + top findings + mapping réglementaire
├── Audit-<Domaine>_<date>.log                        ← Journal d'exécution horodaté
├── Remediate-<Domaine>_Proposals_<date>.csv          ← CSV à valider (Valider vide)
├── Remediate-<Domaine>_Proposals_<date>.csv.sha256
├── Remediate-<Domaine>_Executed_<date>_<RunId>.csv   ← Ce qui a été fait
├── Remediate-<Domaine>_Executed_<date>_<RunId>.csv.sha256
├── Remediate-<Domaine>_Validated_<date>.csv.sha256   ← Preuve de décision (CSV validé scellé)
└── Remediate-<Domaine>_<date>_<RunId>.log
```

---

## Score de conformité — échelle commune à tous les domaines

| Score | Label | Signification |
|-------|-------|---------------|
| 95–100 | OPTIMAL | Conformité totale, maintien à surveiller |
| 80–94 | CONFORME | Conforme avec points d'amélioration mineurs |
| 60–79 | PARTIEL | Base correcte, lacunes documentées |
| 40–59 | INSUFFISANT | Écarts significatifs, plan de remédiation requis |
| 0–39 | CRITIQUE | Non-conformité majeure, action immédiate |

---

## Mapping réglementaire

| Domaine | FINMA 2023/1 | CSSF 22/806 | DORA 2022/2554 | ISO 27001:2022 |
|---------|-------------|-------------|----------------|----------------|
| D1 MFA Coverage | §42 | Ctrl 7 | Art. 9 §4(b) | A.8.5 |
| D2 Legacy Auth | §42 | Ctrl 7 | Art. 9 §4(b) | A.8.5 |
| D3 Conditional Access | §32 | Ctrl 8 | Art. 9 §4(c) | A.5.15 |
| D4 OAuth/OIDC Apps | §38 | Ctrl 7 | Art. 9 | A.5.15 |
| D5 Federation & Guests | §38 | Ctrl 7 | Art. 12 | A.5.16 |
| D6 Hybrid Sync | §42 | Ctrl 8 | Art. 9 | A.8.16 |

---

## Précautions spécifiques par domaine

| Domaine | Risque opérationnel | Précaution avant d'exécuter |
|---------|--------------------|-----------------------------|
| D2 Legacy Auth | ⚠ Élevé | Vérifier les applications qui utilisent SMTP/IMAP avant désactivation |
| D3 CA Policies | ⚠ Élevé | Créer en Report-Only d'abord · Analyser les logs 48h · Garder un breakglass |
| D5 Federation | ⚠ Moyen | Coordonner avec les partenaires externes avant action sur SAML |
| D6 Hybrid Sync | ⚠ Critique | Valider avec l'équipe infrastructure · Ne jamais supprimer dans Entra ID directement |

---

## Auteur

**Arnaud Montcho** — Consultant IAM/IGA Indépendant  
Spécialisation : Gouvernance des Identités & Conformité Réglementaire (FINMA · CSSF · DORA)  
GitHub : [CrepuSkull](https://github.com/CrepuSkull) · arnaud.montcho@gmail.com

*IAM-Lab Framework — 5 repos · 33 scripts PowerShell · Environnement hybride AD + Entra ID*
