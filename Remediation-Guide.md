# Remediation-Guide — Le flux CSV en 3 temps

> La remédiation ne s'exécute jamais automatiquement.  
> Chaque action passe par une validation humaine explicite dans un fichier CSV.

---

## Principe architectural

```
Script Audit      →  Rapport CSV findings (lecture seule, scellé)
       ↓
Script Remediate  →  CSV Proposals (DryRun automatique, SHA-256 immédiat)
       ↓
Consultant/RSSI   →  Remplit colonne Valider (OUI) + Commentaire
       ↓
Script Remediate  →  Vérifie intégrité CSV → Exécute OUI uniquement
       ↓
                     CSV Executed + Log + SHA-256 (scellable par iam-evidence-sealer)
```

---

## Les 3 temps en détail

### Temps 1 — Génération des propositions (automatique)

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -Client "Banque XYZ"
```

Ce que fait le script :
- Lit le rapport d'audit
- Filtre les comptes/objets à risque (CRITIQUE, ÉLEVÉ, MOYEN)
- Détermine l'action proposée pour chacun
- Génère un CSV de propositions avec la colonne `Valider` vide
- Calcule et pose immédiatement un SHA-256 sur ce CSV

Le SHA-256 du CSV de propositions permet de détecter toute modification des colonnes non-Valider/Commentaire au Temps 3.

### Temps 2 — Validation humaine (hors script)

1. Ouvrir le CSV `Remediate-<Domaine>_Proposals_<date>.csv` dans Excel
2. Lire attentivement la colonne `ActionDetail` pour chaque ligne
3. Renseigner `OUI` dans la colonne `Valider` pour chaque action approuvée
4. Ajouter un commentaire dans la colonne `Commentaire` si pertinent
5. Sauvegarder et retourner le fichier au consultant

**Règles de validation :**

| Valeur dans `Valider` | Résultat |
|----------------------|----------|
| `OUI` (exact, majuscules) | Action exécutée |
| `` (vide) | Ignorée |
| `oui` / `Yes` / `O` / autre | Ignorée |

Seul `OUI` exact déclenche une action. Cette rigueur est intentionnelle — jamais d'exécution sur ambiguïté.

### Temps 3 — Simulation puis exécution

**Toujours simuler d'abord :**

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ" -DryRun
```

**Puis exécuter :**

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ"
```

---

## Ce que vérifie le script avant d'exécuter

1. **Intégrité des colonnes immuables** — les colonnes autres que `Valider` et `Commentaire` ne doivent pas avoir été modifiées. Toute modification = arrêt immédiat.
2. **Comptage des OUI** — affiché avant l'exécution pour confirmation visuelle.
3. **Connexion avec les scopes exacts** — uniquement les scopes nécessaires aux actions validées sont demandés.

---

## Actions disponibles par domaine

### D1 — MFA Coverage

| Action | Description | Impact |
|--------|-------------|--------|
| `ForceEnrollmentMFA` | Envoie une notification d'enrôlement MFA | Faible — notification uniquement |
| `ExcludeFromException` | Retire l'utilisateur d'une exclusion CA | Modéré — l'utilisateur sera soumis aux politiques CA |
| `DisableAccount` | Désactive le compte (comptes inactifs) | Élevé — accès coupé |

### D2 — Legacy Auth

| Action | Description | Risque opérationnel |
|--------|-------------|---------------------|
| `BlockLegacyViaCA` | Crée/active une politique CA bloquant les protocoles legacy | **⚠ Moyen** — peut casser des apps legacy |
| `DisableBasicAuthSmtp` | Désactive Basic Auth SMTP sur la boîte mail | **⚠ Élevé** — vérifier les apps avant |
| `DisableBasicAuthImap` | Désactive Basic Auth IMAP sur la boîte mail | **⚠ Élevé** — vérifier les apps avant |
| `DisableBasicAuthPop` | Désactive Basic Auth POP3 sur la boîte mail | **⚠ Élevé** — vérifier les apps avant |
| `DocumentException` | Documente une exception sans action technique | Aucun |

### D6 — Hybrid Sync

| Action | Description | Risque opérationnel |
|--------|-------------|---------------------|
| `ExcludeTier0FromSync` | Pose l'attribut d'exclusion sur le compte AD | **⚠ Critique** — valider avec l'équipe infra |
| `RemoveSvcAcctFromTier0` | Retire le compte de service d'un groupe Tier 0 | **⚠ Critique** — valider avec l'équipe infra |
| `RotateSSOAccountPassword` | Renouvelle le mot de passe AZUREADSSOACC$ | Modéré — requiert le serveur Entra Connect |
| `ResolveProvisioningError` | Génère les instructions de correction (manuel) | Aucun |
| `DocumentSensitiveAttr` | Documente un attribut comme justifié | Aucun |

### D5 — Federation & Guests

| Action | Description | Précaution |
|--------|-------------|------------|
| `RemoveInactiveGuest` | Supprime définitivement le guest | **⚠ Confirmer avec le propriétaire métier** |
| `DisableInactiveGuest` | Désactive (réversible) | Modéré |
| `RestrictInvitePolicy` | Restreint à `adminsAndGuestInviters` | Faible |
| `CreateGuestCAPolicy` | Crée une politique CA guests en **Report-Only** | Faible — pas bloquant |
| `RenewSAMLCertNote` | Documente — action manuelle sur l'IdP externe | **⚠ Coordonner avec le partenaire** |

### D3 — Conditional Access

| Action | Description | Précaution |
|--------|-------------|------------|
| `EnableReportOnlyPolicy` | Active une politique Report-Only | **⚠ Analyser les logs 48h avant** |
| `CreateBaselineCAPolicy` | Crée MFA baseline en **Report-Only** | Faible — non bloquant jusqu'à activation |
| `CreateRiskSignInPolicy` | Crée politique risque connexion en **Report-Only** | Faible — nécessite Entra ID P2 |
| `CreateRiskUserPolicy` | Crée politique risque utilisateur en **Report-Only** | Faible — nécessite Entra ID P2 |
| `RemoveUserFromExclusion` | Retire un utilisateur des exclusions CA | Modéré |
| `DisableObsoletePolicy` | Désactive une politique redondante | **⚠ Vérifier les dépendances** |

> **Règle D3 :** Toutes les nouvelles politiques CA sont créées en mode `enabledForReportingButNotEnforced` (Report-Only). L'activation en `enabled` est une action séparée qui doit être revalidée après analyse des logs.

### D4 — OAuth/OIDC Apps

| Action | Description | Précaution |
|--------|-------------|------------|
| `RevokeUserConsent` | Révoque les consentements OAuth utilisateurs | **⚠ Déconnecte immédiatement les utilisateurs** |
| `RenewAppSecret` | Crée un nouveau secret (l'ancien reste actif) | Faible — mettre à jour l'app cliente ensuite |
| `RemoveExpiredCredential` | Supprime les secrets/certs expirés | Faible — uniquement les expirés |
| `DisableImplicitFlow` | Désactive le flux implicite OAuth2 | **⚠ Coordonner avec l'équipe dev** |
| `DisableApp` | Désactive un Service Principal (réversible) | Modéré |
| `RemoveApp` | Supprime l'App Registration | **⚠ Confirmer avec le propriétaire** |
| `RemoveWildcardRedirectUri` | Manuel — URI de remplacement requises | Action manuelle uniquement |

---

## Statuts dans le rapport d'exécution

| Statut | Signification |
|--------|---------------|
| `SUCCESS` | Action exécutée avec succès |
| `DRYRUN` | Simulation — aucune modification |
| `SKIP` | Objet introuvable ou déjà dans l'état cible |
| `DOCUMENTED` | Exception documentée sans action technique |
| `MANUAL_REQUIRED` | Action manuelle requise (instructions dans le rapport) |
| `ERROR` | Exception — détail dans la colonne ExecutionDetail |

---

## Scellage des livrables de remédiation

Après exécution, sceller les livrables avec `iam-evidence-sealer` :

```powershell
# Depuis le repo iam-evidence-sealer/
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-federation-lab\remediate\Remediate-MFACoverage.ps1" `
    -Client "Banque XYZ" `
    -Sign -Timestamp
```

Le CSV validé retourné par le consultant est scellé (SHA-256) avant exécution — c'est la preuve de décision. Le rapport d'exécution est scellé après — c'est la preuve de ce qui a été fait.

---

## Boucle d'amélioration continue

Après chaque remédiation, relancer l'audit du même domaine pour mesurer l'amélioration du score :

```powershell
# Exemple après remédiation D1
.\audit\Audit-MFACoverage.ps1 -Client "Banque XYZ"
# Comparer le score JSON avec le rapport précédent
```

L'objectif est de faire progresser le score vers 80+ (CONFORME) sur chaque domaine.

---

*Page suivante : [Regulatory-Coverage](Regulatory-Coverage)*
