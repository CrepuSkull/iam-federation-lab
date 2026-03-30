# Guide de remédiation — Procédure opérationnelle CSV

*Arnaud Montcho — Consultant IAM/IGA · github.com/CrepuSkull*  
*Version 1.0 — Mars 2026*

---

## Principe : aucune action sans décision humaine tracée

Tous les scripts de remédiation du repo `iam-federation-lab` suivent le même flux en 3 temps. La colonne `Valider` du CSV est le mécanisme de contrôle : seul `OUI` exact déclenche une action. Jamais d'exécution sur ambiguïté.

Ce document décrit la procédure opérationnelle complète, du rapport d'audit jusqu'au livrable scellé.

---

## Le flux en 3 temps — vue synthétique

```
┌─────────────────────────────────────────────────────────┐
│  TEMPS 1 — PROPOSALS (automatique)                      │
│                                                         │
│  Commande : .\Remediate-X.ps1 -AuditReport <fichier>   │
│                                                         │
│  → Lit le rapport audit                                 │
│  → Génère CSV avec colonne Valider vide                 │
│  → Calcule SHA-256 du CSV propositions immédiatement    │
│  → Affiche les instructions et s'arrête                 │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼ CSV de propositions
                          
┌─────────────────────────────────────────────────────────┐
│  TEMPS 2 — VALIDATION (humaine, hors script)            │
│                                                         │
│  Ouvrir dans Excel                                      │
│  → Lire ActionDetail pour chaque ligne                  │
│  → Renseigner OUI dans la colonne Valider               │
│  → Ajouter un Commentaire si pertinent                  │
│  → Sauvegarder (ne pas renommer le fichier)             │
│  → Validation avec propriétaire métier / infra          │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼ CSV validé retourné
                          
┌─────────────────────────────────────────────────────────┐
│  TEMPS 3 — EXÉCUTION (sur CSV validé)                   │
│                                                         │
│  Commande : .\Remediate-X.ps1 -AuditReport <A>         │
│                               -ValidatedReport <V>      │
│                               -DryRun (toujours d'abord)│
│                                                         │
│  → Vérifie intégrité des colonnes immuables             │
│  → Simule (DryRun) ou exécute les lignes OUI            │
│  → Scelle le CSV validé (SHA-256)                       │
│  → Produit le rapport d'exécution (scellé)              │
└─────────────────────────────────────────────────────────┘
```

---

## Procédure détaillée — Temps 1

### Commande

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -Client "Banque XYZ"
```

Remplacer `MFACoverage` par le domaine concerné : `LegacyAuth`, `HybridSync`, `FederationTrusts`, `ConditionalAccess`, `OAuthApplications`.

### Ce que le script génère

```
Reports/
└── Remediate-MFACoverage_Proposals_2026-03-29.csv
    Remediate-MFACoverage_Proposals_2026-03-29.csv.sha256   ← posé immédiatement
    Remediate-MFACoverage_2026-03-29_<RunId>.log
```

### Structure du CSV de propositions

| Colonne | Type | Description |
|---------|------|-------------|
| `ID` | Automatique | Identifiant unique de la ligne (001, 002…) |
| `UPN` / `AppName` / `ObjectName` | Automatique | Entité concernée |
| `RiskLevel` | Automatique | CRITIQUE / ÉLEVÉ / MOYEN |
| `ActionType` | Automatique | Identifiant technique de l'action |
| `ActionDetail` | Automatique | Description lisible de ce qui sera fait |
| `RegulatoryReference` | Automatique | Référentiel concerné |
| `Urgency` | Automatique | IMMÉDIAT / SOUS 7 JOURS / PLANIFIÉ |
| **`Valider`** | **À remplir** | **OUI pour approuver, vide pour ignorer** |
| **`Commentaire`** | **À remplir** | **Justification, note, info complémentaire** |

---

## Procédure détaillée — Temps 2

### Règles de remplissage

**La valeur `OUI` est la seule qui déclenche une action.**

| Ce que vous saisissez | Ce qui se passe |
|----------------------|----------------|
| `OUI` | Action exécutée |
| (vide) | Action ignorée — défaut |
| `oui` | Action ignorée |
| `Yes` | Action ignorée |
| `Non` | Action ignorée |
| `O` | Action ignorée |

Cette rigueur est intentionnelle. Elle protège contre les exécutions accidentelles.

### Ce que vous devez faire avant de saisir OUI

**Pour les actions de désactivation Exchange (D2 — DisableBasicAuthSmtp/Imap/Pop) :**  
Vérifier la colonne `AppsDetected`. Contacter les équipes applicatives pour confirmer que l'application référencée supporte Modern Auth. Ne saisir OUI qu'après confirmation.

**Pour les actions Hybrid Sync (D6 — ExcludeTier0FromSync, RemoveSvcAcctFromTier0) :**  
Valider avec l'équipe infrastructure et le RSSI. Planifier une fenêtre de maintenance. Ces actions ont un impact potentiel sur l'ensemble du tenant.

**Pour les actions Conditional Access (D3 — CreateBaselineCAPolicy, EnableReportOnlyPolicy) :**  
Analyser les Sign-in logs de la politique concernée (portail Entra ID → Protection → Accès conditionnel → Insights). Confirmer qu'aucun utilisateur légitime ne serait bloqué.

**Pour les actions sur les guests (D5 — RemoveInactiveGuest) :**  
Contacter le propriétaire métier de la relation (pas seulement IT). La suppression d'un guest coupe l'accès d'une personne externe — une validation humaine non-IT est nécessaire.

**Pour les secrets applicatifs (D4 — RenewAppSecret) :**  
Créer le nouveau secret, mettre à jour l'application cliente, valider en environnement de test, puis saisir OUI pour la suppression de l'ancien.

### Ne pas modifier les autres colonnes

Le script vérifie au Temps 3 que les colonnes immuables n'ont pas été modifiées. Toute modification des colonnes autres que `Valider` et `Commentaire` provoque un arrêt d'urgence.

---

## Procédure détaillée — Temps 3

### Toujours simuler d'abord

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ" `
    -DryRun
```

Le DryRun affiche exactement ce qui sera fait, ligne par ligne, sans modifier quoi que ce soit. Il vérifie aussi que la connexion fonctionne et que les objets cibles existent.

### Puis exécuter

```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport     ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ"
```

### Ce que le script produit

```
Reports/
├── Remediate-MFACoverage_Executed_2026-03-29_A3F8C2D1.csv     ← ce qui a été fait
├── Remediate-MFACoverage_Executed_2026-03-29_A3F8C2D1.csv.sha256
├── Remediate-MFACoverage_Proposals_2026-03-29.csv.sha256       ← preuve de décision
└── Remediate-MFACoverage_2026-03-29_A3F8C2D1.log
```

### Statuts dans le rapport d'exécution

| Statut | Signification |
|--------|---------------|
| `SUCCESS` | Action exécutée avec succès |
| `DRYRUN` | Simulation — aucune modification |
| `SKIP` | Objet introuvable ou déjà dans l'état cible |
| `DOCUMENTED` | Exception documentée, pas d'action technique |
| `MANUAL_REQUIRED` | Action manuelle nécessaire — instructions dans `ExecutionDetail` |
| `ERROR` | Exception — lire la colonne `ExecutionDetail` |

---

## Sceller les livrables de remédiation

Après exécution, sceller avec `iam-evidence-sealer` :

```powershell
# Depuis le repo iam-evidence-sealer/

# Scellage L2 (signature) — pour les missions France / clôture standard
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-federation-lab\remediate\Remediate-MFACoverage.ps1" `
    -Client "Banque XYZ" `
    -Sign

# Scellage L3 (signature + RFC 3161) — pour les missions FINMA / CSSF
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-federation-lab\remediate\Remediate-MFACoverage.ps1" `
    -Client "Banque XYZ" `
    -Sign -Timestamp `
    -TsaUrl "http://timestamp.sectigo.com"
```

---

## Boucle d'amélioration — mesurer le progrès

Après chaque remédiation, relancer l'audit du même domaine et comparer les scores JSON :

```powershell
# Audit initial → score 42/100 INSUFFISANT
.\audit\Audit-MFACoverage.ps1 -Client "Banque XYZ"

# [Remédiation D1]

# Audit de contrôle → score 78/100 PARTIEL
.\audit\Audit-MFACoverage.ps1 -Client "Banque XYZ"

# Comparer les deux JSON pour documenter l'amélioration
```

Le score JSON contient un horodatage — la progression est documentée et scellable comme preuve d'amélioration continue au sens de DORA Art. 15 (tests de résilience).

---

*Pour la cartographie des flux d'authentification : voir `federation-architecture.md`.*  
*Pour le mapping réglementaire détaillé : voir `compliance-mapping.md`.*
