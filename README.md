# iam-federation-lab

# iam-federation-lab

> **Audit de fédération et d'authentification — Environnement hybride AD + Entra ID**  
> *Cartographie des vecteurs d'attaque · Conformité FINMA · CSSF · DORA*

Faisant partie de l'écosystème **IAM-Lab Framework** :
- [iam-foundation-lab](https://github.com/CrepuSkull/iam-foundation-lab) — Audit AD · Migration Entra ID · Fédération OIDC
- [IAM-Lab-Identity-Lifecycle](https://github.com/CrepuSkull/IAM-Lab-Identity-Lifecycle) — Automatisation JML
- [iam-governance-lab](https://github.com/CrepuSkull/iam-governance-lab) — Contrôle continu & Recertification
- [iam-evidence-sealer](https://github.com/CrepuSkull/iam-evidence-sealer) — Intégrité des preuves d'audit
- **iam-federation-lab** — Authentification & Fédération ← *vous êtes ici*

---

## Ce que ce repo audite

Les 4 repos précédents répondent à **"qui a accès à quoi"** — droits, comptes, cycle de vie.

`iam-federation-lab` répond à **"comment est-ce qu'on prouve qu'on est bien qui on dit être, et comment les systèmes se font-ils confiance entre eux"**.

Ce sont deux couches distinctes. Un compte peut avoir les bons droits ET être compromettable parce que son mécanisme d'authentification est faible — NTLM, SMS uniquement, Basic Auth non bloqué.

---

## Architecture — deux couches strictement séparées

```
Couche AUDIT (lecture seule absolue)
  audit/Audit-*.ps1
  → Connecte, lit, mesure, produit CSV + JSON + LOG
  → Ne modifie rien

        ↓ rapport CSV

Couche REMÉDIATION (validation humaine obligatoire)
  remediate/Remediate-*.ps1
  → Lit le rapport audit
  → Génère un CSV de propositions (DryRun automatique)
  → Attend validation "OUI" dans la colonne Valider
  → Exécute uniquement les lignes approuvées
  → Produit un rapport d'exécution scellable
```

---

## Les 6 domaines d'audit

| Domaine | Script Audit | Script Remédiation | Priorité |
|---------|-------------|-------------------|----------|
| **D1** MFA Coverage | `Audit-MFACoverage.ps1` | `Remediate-MFACoverage.ps1` | 🔴 Critique |
| **D2** Legacy Auth (NTLM, Basic, SMTP) | `Audit-LegacyAuth.ps1` | `Remediate-LegacyAuth.ps1` | 🔴 Critique |
| **D6** Hybrid Sync (Entra Connect) | `Audit-HybridSync.ps1` | `Remediate-HybridSync.ps1` | 🔴 Haute |
| **D5** Federation & Guests | `Audit-FederationTrusts.ps1` | `Remediate-FederationTrusts.ps1` | 🟡 Moyenne |
| **D3** Conditional Access | `Audit-ConditionalAccess.ps1` | `Remediate-ConditionalAccess.ps1` | 🟡 Moyenne |
| **D4** OAuth / OIDC Apps | `Audit-OAuthApplications.ps1` | `Remediate-OAuthApplications.ps1` | 🟡 Moyenne |

---

## Démarrage rapide — D1 MFA Coverage

### Prérequis
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
# Rôle requis : Security Reader (lecture seule)
```

### Étape 1 — Audit (lecture seule)
```powershell
.\audit\Audit-MFACoverage.ps1 -Client "Banque XYZ" -OutputPath ".\Reports"
# → Reports/Audit-MFACoverage_<date>.csv
# → Reports/Audit-MFACoverage_<date>.json  (score + findings)
# → Reports/Audit-MFACoverage_<date>.log
```

### Étape 2 — Génération des propositions de remédiation
```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -Client "Banque XYZ"
# → Reports/Remediate-MFACoverage_Proposals_<date>.csv
#   Ouvrir dans Excel, renseigner OUI dans la colonne Valider, sauvegarder
```

### Étape 3 — Simulation sur CSV validé (toujours faire d'abord)
```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ" -DryRun
```

### Étape 4 — Exécution réelle
```powershell
.\remediate\Remediate-MFACoverage.ps1 `
    -AuditReport ".\Reports\Audit-MFACoverage_2026-03-29.csv" `
    -ValidatedReport ".\Reports\Remediate-MFACoverage_Proposals_2026-03-29.csv" `
    -Client "Banque XYZ"
```

### Étape 5 — Sceller les livrables
```powershell
# Depuis iam-evidence-sealer/
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-federation-lab\audit\Audit-MFACoverage.ps1" `
    -Client "Banque XYZ" -Sign -Timestamp
```

---

## Structure des livrables

```
Reports/
├── Audit-MFACoverage_2026-03-29.csv              ← données brutes (tous comptes à risque)
├── Audit-MFACoverage_2026-03-29.json             ← score + findings + mapping réglementaire
├── Audit-MFACoverage_2026-03-29.log              ← journal d'exécution
│
├── Remediate-MFACoverage_Proposals_2026-03-29.csv     ← CSV à valider (Valider = vide)
├── Remediate-MFACoverage_Proposals_2026-03-29.csv.sha256
│
├── Remediate-MFACoverage_Executed_2026-03-29_A3F8.csv ← ce qui a été fait
├── Remediate-MFACoverage_Executed_2026-03-29_A3F8.csv.sha256
└── Remediate-MFACoverage_2026-03-29_A3F8.log
```

---

## Règle de validation CSV

```
Valider = "OUI"   → action exécutée
Valider = ""      → ignorée (défaut)
Valider = autre   → ignorée
```

Seul `OUI` exact (majuscules) déclenche une action. Toute ambiguïté = pas d'exécution.

---

## Mapping réglementaire

| Domaine | FINMA 2023/1 | CSSF 22/806 | DORA | ISO 27001 |
|---------|-------------|-------------|------|-----------|
| D1 MFA | §42 | Ctrl 7 | Art. 9 §4(b) | A.8.5 |
| D2 Legacy Auth | §42 | Ctrl 7 | Art. 9 §4(b) | A.8.5 |
| D3 Accès conditionnel | §32 | Ctrl 8 | Art. 9 §4(c) | A.5.15 |
| D4 OAuth/OIDC | §38 | Ctrl 7 | Art. 9 | A.5.15 |
| D5 Fédération externe | §38 | Ctrl 7 | Art. 12 | A.5.16 |
| D6 Synchro hybride | §42 | Ctrl 8 | Art. 9 | A.8.16 |

---

## Auteur

**Arnaud Montcho** — Consultant IAM/IGA Indépendant  
Spécialisation : Gouvernance des Identités & Conformité Réglementaire (FINMA · CSSF · DORA)  
GitHub : [CrepuSkull](https://github.com/CrepuSkull) · arnaud.montcho@gmail.com
