# Mapping de conformité réglementaire
## iam-federation-lab — FINMA · CSSF · DORA · ISO 27001

*Arnaud Montcho — Consultant IAM/IGA · github.com/CrepuSkull*  
*Version 1.0 — Mars 2026*

---

## Introduction

Ce document établit la correspondance précise entre les contrôles techniques des 6 domaines d'audit du repo `iam-federation-lab` et les exigences des référentiels réglementaires applicables aux secteurs financiers en France, Suisse et Luxembourg.

Il est conçu pour deux audiences :
- **RSSI / Auditeurs techniques** — correspondance contrôle par contrôle
- **DSI / Compliance Officers** — synthèse par référentiel et niveau de couverture

---

## FINMA Circ. 2023/1 — Risques opérationnels et résilience des banques

### Contexte
La Circulaire 2023/1 de la FINMA (entrée en vigueur janvier 2024) remplace la Circ. 2008/21. Elle impose aux banques suisses des exigences de gestion des risques opérationnels avec une attention particulière portée aux systèmes d'information et à la gestion des identités. L'approche est *principles-based* : la FINMA fixe des objectifs, pas des prescriptions techniques.

### Couverture par domaine

| Paragraphe FINMA | Exigence | D1 | D2 | D3 | D4 | D5 | D6 |
|-----------------|----------|----|----|----|----|----|----|
| §32 | Documentation et analyse des risques opérationnels TI | — | — | ✅ | — | — | ✅ |
| §38 | Traçabilité des opérations sur les systèmes d'information | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| §42 | Authentification forte pour les accès aux systèmes critiques | ✅ | ✅ | ✅ | — | — | ✅ |
| §44 | Gestion des accès privilégiés | — | — | — | — | — | ✅ |
| §51 | Conservation et intégrité des preuves | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Détail §42 — Authentification forte

Le §42 exige que l'accès aux systèmes d'information critiques soit protégé par une authentification forte. Le repo couvre cet exigence via :

- **D1** — Mesure précise du taux de couverture MFA par compte, par département, par méthode. Calcul d'un score pondéré selon la force de la méthode (FIDO2 > AuthApp > SMS).
- **D2** — Détection des protocoles qui contournent l'authentification forte. Un compte avec MFA activé et Basic Auth SMTP actif n'est PAS protégé par l'authentification forte au sens de la FINMA.
- **D3** — Vérification que les politiques CA qui imposent le MFA sont effectivement activées (pas en Report-Only).
- **D6** — Vérification que le compte AZUREADSSOACC$ (Seamless SSO Kerberos) est régulièrement renouvelé.

### Niveau de preuve requis pour un contrôle FINMA
**L3 obligatoire** : SHA-256 + Signature X.509 (certificat CA commerciale, pas auto-signé) + Horodatage RFC 3161 via TSA commerciale (Sectigo recommandé).

---

## CSSF Circ. 22/806 — Gestion des risques TIC (Luxembourg)

### Contexte
La CSSF Circ. 22/806 transpose les orientations EBA/GL/2019/04 en droit luxembourgeois. Elle s'applique aux établissements de crédit et entreprises d'investissement domiciliés au Luxembourg. Plus prescriptive que FINMA sur les contrôles techniques attendus.

### Couverture par contrôle

| Contrôle CSSF | Domaine | Exigence | Contrôle technique |
|--------------|---------|----------|-------------------|
| Ctrl 7 | Gestion des identités et accès | MFA obligatoire, non-répudiation | D1 (coverage), D2 (blocage legacy), D6 (Tier 0) |
| Ctrl 7 | Gestion des accès tiers | Contrôle des identités externes | D5 (guests, fédération) |
| Ctrl 7 | Gestion des identités applicatives | Permissions minimales, secrets valides | D4 (OAuth apps) |
| Ctrl 8 | Journalisation et surveillance | Logs d'activité horodatés et conservés | Tous (fichiers .log par RunId) |
| Ctrl 12 | Gestion des incidents | Traçabilité des actions de remédiation | Tous (CSV Executed + SHA-256) |
| Ctrl 15 | Tests et audit | Documentation des tests de conformité | Tous (mode -DryRun loggué) |

### Points de vigilance CSSF spécifiques

**Guests et accès externes (Ctrl 7)**  
La CSSF est particulièrement attentive aux accès tiers. Les comptes guests Entra B2B sans politique CA dédiée sont un écart typiquement relevé lors des inspections. D5 cartographie ces accès et D3 vérifie la couverture CA des guests.

**Non-répudiation des actions sur les comptes (Ctrl 7)**  
Le CSV validé retourné par le consultant est scellé avant exécution (SHA-256). Le rapport d'exécution est scellé après. C'est la chaîne de preuve non-répudiable : décision documentée → exécution tracée → preuve certifiée.

### Niveau de preuve requis pour un contrôle CSSF
**L2 minimum** (SHA-256 + Signature CA commerciale). L3 recommandé pour les livrables de clôture de mission.

---

## DORA — Digital Operational Resilience Act (UE 2022/2554)

### Contexte
DORA est entré en application le 17 janvier 2025. Il s'applique aux entités financières UE et à leurs prestataires TIC critiques. Les premières inspections approfondies sont en cours en 2025-2026.

### Couverture par article

| Article DORA | Exigence | Domaine(s) | Contrôle technique |
|-------------|----------|-----------|-------------------|
| Art. 9 §4(a) | Politique de sécurité des systèmes TIC | D3 | Inventaire et cohérence des politiques CA |
| Art. 9 §4(b) | Protection contre l'accès non autorisé | D1, D2 | MFA généralisé, blocage protocoles legacy |
| Art. 9 §4(c) | Détection des activités anormales | D2, D3, D6 | Logs connexion, CA avec condition risque, surveillance sync |
| Art. 9 §4(d) | Mesures de continuité et reprise | D5 | Alertes expiration certificats SAML |
| Art. 9 (général) | Sécurité des systèmes et outils TIC | D4, D5 | Permissions applicatives, accès tiers |
| Art. 12 §1 | Politiques de journalisation | Tous | Fichiers .log horodatés, RunId unique |
| Art. 12 §3 | Conservation des journaux | Tous | Archivage structuré `Reports/` |
| Art. 12 §8 | Gestion des tiers fournisseurs TIC | D5 | Domaines fédérés, guests, collaboration externe |
| Art. 15 | Tests de résilience | Tous | Mode -DryRun documenté et loggué |

### Point critique DORA — Art. 9 §4(b)

DORA exige des "mesures de protection [...] contre tout accès non autorisé, y compris contre les attaques par des vecteurs numériques". Les protocoles d'authentification legacy (D2) sont exactement ces vecteurs numériques que DORA vise. Un attaquant utilisant SMTP AUTH pour accéder à une boîte mail sans MFA constitue un accès non autorisé non détecté — échec direct sur Art. 9 §4(b).

### Niveau de preuve requis pour DORA
**L2 minimum**. Pour les rapports destinés aux autorités compétentes (BCE, EBA, ESMA) : L3.

---

## ISO 27001:2022

### Couverture par contrôle d'annexe A

| Contrôle | Thème | Domaine(s) | Contrôle technique |
|---------|-------|-----------|-------------------|
| A.5.15 | Contrôle d'accès | D3, D4 | Politiques CA, permissions applicatives |
| A.5.16 | Gestion des identités | D5 | Identités guests et fédérées |
| A.5.17 | Informations d'authentification | D1, D2 | MFA, protocoles d'auth |
| A.5.18 | Droits d'accès | D4 | Permissions OAuth minimales |
| A.5.34 | Confidentialité | D4, D6 | Secrets non commitables, attributs sensibles |
| A.8.2 | Droits d'accès privilégiés | D6 | Tier 0, compte service Entra Connect |
| A.8.5 | Authentification sécurisée | D1, D2, D3 | MFA obligatoire, CA couvrant tout |
| A.8.16 | Surveillance des activités | D6 | Journalisation synchronisation |
| A.8.17 | Synchronisation des horloges | D4, D5 | Expiration secrets et certificats SAML |

---

## Matrice de couverture synthétique — niveau de conformité attendu

Pour un score IAM-Lab de 80+ (CONFORME) :

| Contrôle | Score D1 | Score D2 | Score D3 | Score D4 | Score D5 | Score D6 |
|---------|---------|---------|---------|---------|---------|---------|
| FINMA §42 | ≥ 80 | ≥ 80 | ≥ 70 | — | — | ≥ 80 |
| CSSF Ctrl 7 | ≥ 80 | ≥ 80 | ≥ 70 | ≥ 70 | ≥ 70 | ≥ 80 |
| DORA Art. 9 | ≥ 80 | ≥ 80 | ≥ 70 | ≥ 70 | ≥ 70 | ≥ 70 |
| ISO 27001 | ≥ 80 | ≥ 80 | ≥ 80 | ≥ 80 | ≥ 70 | ≥ 80 |

---

## Mapping des questions types d'audit

### Questions FINMA §42

| Question de l'inspecteur | Script de réponse | Livrable |
|--------------------------|------------------|---------|
| "Pouvez-vous démontrer que l'authentification forte est généralisée ?" | `Audit-MFACoverage.ps1` | Score /100 + taux MFA exact par département |
| "Avez-vous des comptes exemptés de MFA ? Justification ?" | `Audit-MFACoverage.ps1` | Colonne `ExcludedFromMFAPolicy` + politique d'exclusion |
| "Des protocoles d'authentification obsolètes sont-ils encore actifs ?" | `Audit-LegacyAuth.ps1` | Liste connexions SMTP/NTLM + couverture CA de blocage |
| "Vos comptes à privilèges sont-ils dans Entra ID ?" | `Audit-HybridSync.ps1` | Colonne `IsTier0` dans le rapport de sync |

### Questions CSSF Ctrl 7

| Question de l'inspecteur | Script de réponse | Livrable |
|--------------------------|------------------|---------|
| "Comment gérez-vous les accès tiers et prestataires ?" | `Audit-FederationTrusts.ps1` | Inventaire guests B2B + politiques de collaboration |
| "Les applications ont-elles des permissions minimales ?" | `Audit-OAuthApplications.ps1` | Liste permissions *.All avec justifications |
| "Comment sont tracées les actions de remédiation ?" | Tous `Remediate-*.ps1` | CSV Executed + SHA-256 + log |

### Questions DORA Art. 9

| Question de l'inspecteur | Script de réponse | Livrable |
|--------------------------|------------------|---------|
| "Décrivez vos mesures contre les accès non autorisés." | `Audit-MFACoverage.ps1` + `Audit-LegacyAuth.ps1` | Score MFA + rapport legacy avec mapping DORA |
| "Comment détectez-vous les activités anormales ?" | `Audit-ConditionalAccess.ps1` | Conditions de risque Entra ID Protection configurées |
| "Vos journaux sont-ils intègres et conservés ?" | Tous + iam-evidence-sealer | `.log` + `.manifest` + `.sha256` par exécution |

---

## Note sur la valeur probante des preuves

### Hiérarchie des preuves

| Niveau | Technologie | Valeur probante | Usage |
|--------|-------------|----------------|-------|
| L1 Hash | SHA-256 | Intégrité seule | Audits internes, démos |
| L2 Signé | + X.509 (CA commerciale) | Identité + intégrité | Missions clients |
| L3 Horodaté | + RFC 3161 (TSA) | + Antériorité certifiée | FINMA, CSSF, DORA |

### Pourquoi le certificat auto-signé ne suffit pas pour FINMA/CSSF

Un certificat auto-signé (`New-SelfSignedCertificate`) ne peut pas servir de preuve juridique car n'importe qui peut en créer un avec n'importe quel nom. Un auditeur FINMA peut le rejeter car l'identité du signataire n'est pas vérifiable par un tiers indépendant.

Pour une valeur probante reconnue :
- Certificat émis par une CA commerciale (Sectigo, DigiCert, GlobalSign)
- Combiné à un horodatage RFC 3161 via une TSA commerciale reconnue (pas FreeTSA pour les livrables réglementaires)

---

*Pour l'intégration avec iam-evidence-sealer : voir `../README.md` → Étape 5.*  
*Pour la procédure de remédiation complète : voir `remediation-guide.md`.*  
*Pour la cartographie des flux d'authentification : voir `federation-architecture.md`.*
