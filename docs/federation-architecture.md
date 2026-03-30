# Architecture de fédération et flux d'authentification
## Cartographie des flux — Environnement hybride AD + Entra ID

*Arnaud Montcho — Consultant IAM/IGA · github.com/CrepuSkull*  
*Version 1.0 — Mars 2026*

---

## Pourquoi cartographier les flux avant d'auditer

Un audit d'authentification sans cartographie préalable revient à chercher des fuites dans une maison sans en connaître la plomberie. Ce document établit les flux types d'un environnement hybride AD + Entra ID : qui s'authentifie, comment, via quoi, et où les risques se concentrent.

Il sert de référence pour interpréter les résultats des 6 scripts d'audit et prioriser les remédiations.

---

## Section 1 — Vue d'ensemble de l'environnement hybride

### Architecture type

```
INFRASTRUCTURE ON-PREMISE                    CLOUD MICROSOFT
─────────────────────────────               ─────────────────────────────
                                            
  ┌─────────────────────────┐               ┌───────────────────────────┐
  │   Active Directory      │               │      Entra ID (AAD)       │
  │   (Contrôleur de domaine│◄──────sync────│                           │
  │    Kerberos · LDAP · DNS│     Entra     │  Identités synchronisées  │
  │    GPO · SYSVOL)        │    Connect    │  Politiques CA            │
  └──────────┬──────────────┘               │  Entra ID Protection      │
             │                              │  Entra ID Governance      │
             │ Kerberos (interne)           └───────────┬───────────────┘
             │                                          │
  ┌──────────▼──────────────┐               ┌───────────▼───────────────┐
  │   Ressources internes   │               │  Applications cloud       │
  │   Serveurs · Partages   │               │  Microsoft 365 · Teams    │
  │   Applications legacy   │               │  SharePoint · Exchange    │
  │   VPN · RDP             │               │  Applications SaaS SAML   │
  └─────────────────────────┘               │  Applications OAuth/OIDC  │
                                            └───────────────────────────┘
```

### Les deux plans d'authentification qui coexistent

| Plan | Protocoles | Contrôleur | Vecteurs de risque |
|------|-----------|------------|-------------------|
| **On-premise** | Kerberos v5, NTLM v2, LDAP | Active Directory | Pass-the-Hash, Pass-the-Ticket, Golden Ticket |
| **Cloud** | OAuth 2.0, OIDC, SAML 2.0 | Entra ID | Token theft, Consent phishing, MFA bypass via legacy |
| **Hybride** | Mixed | Entra Connect (pont) | Propagation de compromission, sync de comptes Tier 0 |

---

## Section 2 — Les flux d'authentification par cas d'usage

### Flux 1 — Connexion Windows on-premise (Kerberos)

```
Utilisateur           Poste Windows         AD DC              Ressource
    │                     │                     │                    │
    │──Login (pwd)───────►│                     │                    │
    │                     │──AS-REQ (TGT)──────►│                    │
    │                     │◄──AS-REP (TGT)──────│                    │
    │                     │──TGS-REQ───────────►│                    │
    │                     │◄──TGS-REP (ticket)──│                    │
    │                     │──────ticket─────────────────────────────►│
    │◄──Accès accordé────────────────────────────────────────────────│
```

**Risques associés :** Pass-the-Hash sur NTLM, Overpass-the-Hash, Silver Ticket (ticket de service forgé), Golden Ticket (TGT forgé si KRBTGT compromis).

**Contrôle IAM-Lab :** D6 Hybrid Sync surveille les comptes Tier 0 pour s'assurer qu'ils ne sont pas synchronisés dans Entra ID, ce qui exposerait les comptes les plus puissants au plan cloud.

---

### Flux 2 — Authentification Entra ID moderne (OAuth 2.0 + OIDC)

```
Utilisateur          Navigateur             Entra ID          Application
    │                     │                     │                  │
    │──Accès app─────────►│                     │                  │
    │                     │──Auth redirect─────►│                  │
    │◄──Login page────────│                     │                  │
    │──Credentials───────►│                     │                  │
    │                     │──POST credentials──►│                  │
    │                     │   [Évaluation CA]   │                  │
    │                     │   ↓ MFA requis      │                  │
    │◄──MFA challenge─────│                     │                  │
    │──MFA response──────►│                     │                  │
    │                     │◄──Authorization code│                  │
    │                     │──code exchange────────────────────────►│
    │                     │◄──Access token + Refresh token─────────│
    │◄──Contenu app───────│                     │                  │
```

**Contrôles IAM-Lab :**
- D1 : Le MFA est-il exigé et effectivement configuré ?
- D3 : La politique CA est-elle active (pas Report-Only) et couvre-t-elle toutes les apps ?
- D4 : L'application a-t-elle les permissions minimales nécessaires ?

---

### Flux 3 — Authentification legacy contournant le MFA (SMTP AUTH)

```
Application legacy      Exchange Online           Entra ID
      │                        │                     │
      │──SMTP AUTH────────────►│                     │
      │  (user:password        │                     │
      │   en clair / base64)   │                     │
      │                        │──Validation────────►│
      │                        │  Basic Auth         │  ← MFA NON vérifié
      │                        │◄──OK────────────────│
      │◄──250 Auth success─────│                     │
      │                        │                     │
      │  [La politique CA      │                     │
      │   n'est PAS évaluée]   │                     │
```

**Pourquoi c'est critique :** SMTP AUTH, IMAP, POP3 et NTLM ne passent pas par le flux OAuth/OIDC d'Entra ID. La politique d'accès conditionnel — y compris l'obligation de MFA — n'est jamais évaluée. Un attaquant avec un mot de passe valide peut s'authentifier même si l'utilisateur a le MFA activé.

**Contrôle IAM-Lab :** D2 Legacy Auth détecte ces connexions dans les logs Entra ID et vérifie si une politique CA de blocage est active.

---

### Flux 4 — Seamless SSO Kerberos (hybride)

```
Utilisateur        Navigateur          AD DC         Entra ID        Application
    │                  │                 │               │                │
    │──Accès app──────►│                 │               │                │
    │                  │──Kerberos req──►│               │                │
    │                  │◄──Ticket KRB────│               │                │
    │                  │──Ticket KRB────────────────────►│                │
    │                  │   (AZUREADSSOACC$ token)        │                │
    │                  │◄──Access token──────────────────│                │
    │◄──Contenu app────│                 │               │                │
```

**Condition :** L'utilisateur est sur un réseau de confiance (interne) avec un poste joint au domaine.

**Risque :** Si le mot de passe du compte `AZUREADSSOACC$` n'est pas renouvelé régulièrement, un ticket Kerberos forgé pourrait théoriquement usurper l'authentification SSO.

**Contrôle IAM-Lab :** D6 vérifie l'âge du mot de passe AZUREADSSOACC$ et alerte si > 30 jours (recommandation Microsoft).

---

### Flux 5 — Fédération SAML avec un IdP externe (B2B)

```
Utilisateur externe    IdP externe (ADFS/Okta)    Entra ID         Application
       │                        │                     │                   │
       │──Accès app──────────────────────────────────────────────────────►│
       │                        │                     │◄──SAML req───  ───│
       │◄──Redirect vers IdP────────────────────────────                  │
       │──Login────────────────►│                     │                   │
       │◄──SAML Assertion───────│                     │                   │
       │──SAML Assertion─────────────────────────────►│                   │
       │                        │                     │ [Valide le cert]  │
       │                        │                     │──Access token────►│
       │◄──Contenu app────────────────────────────────────────────────────│
```

**Risque :** Si le certificat SAML de l'IdP externe expire, TOUS les utilisateurs de ce domaine sont bloqués instantanément. Si la configuration du domaine fédéré pointe vers un IdP non maîtrisé, c'est une porte d'entrée externe dans le tenant.

**Contrôle IAM-Lab :** D5 vérifie les certificats SAML et leurs dates d'expiration pour chaque domaine fédéré.

---

### Flux 6 — Consentement OAuth / application tierce

```
Utilisateur        Application tierce      Entra ID          Microsoft Graph
    │                       │                   │                    │
    │──Utilise l'app───────►│                   │                    │
    │                       │──Auth request────►│                    │
    │◄──Login + Consent page│                   │                    │
    │  [Écran : cette app   │                   │                    │
    │   veut accéder à      │                   │                    │
    │   vos mails et        │                   │                    │
    │   fichiers]           │                   │                    │
    │──Consent OUI─────────────────────────────►│                    │
    │                       │◄──Access token────│                    │
    │                       │──GET /me/messages─────────────────────►│
    │                       │◄──Mails utilisateur────────────────────│
```

**Risque OAuth Consent Phishing :** Un attaquant crée une application tierce légitime en apparence et envoie un lien d'invitation. L'utilisateur clique, consent, et l'application a maintenant accès à ses mails ou fichiers sans que IT le sache — et sans MFA, car l'authentification s'est faite normalement.

**Contrôle IAM-Lab :** D4 inventorie tous les consentements utilisateurs non-admin et les scopes accordés.

---

## Section 3 — Cartographie des risques par couche

```
COUCHE             RISQUE PRINCIPAL              DOMAINE D'AUDIT    PRIORITÉ
─────────────────────────────────────────────────────────────────────────────
Authentification   Absence de MFA                 D1                 🔴 Critique
                   Protocoles legacy actifs       D2                 🔴 Critique

Contrôle d'accès   Politiques CA lacunaires       D3                 🔴 Haute
                   Guests sans MFA                D5 → D3            🟡 Moyenne

Synchronisation    Tier 0 synchronisés            D6                 🔴 Critique
                   Compte service over-privileged D6                 🔴 Haute

Fédération externe Certificats SAML expirés       D5                 🟡 Moyenne
                   Guests orphelins               D5                 🟡 Moyenne

Applications       Permissions Application *.All  D4                 🟡 Moyenne
                   Secrets expirés                D4                 🟡 Moyenne
                   Consentements utilisateurs     D4                 🟡 Moyenne
```

---

## Section 4 — Points d'intersection entre domaines

Certains risques ne sont détectables que par la combinaison de plusieurs domaines :

**MFA activé mais contournable (D1 + D2)**  
D1 peut indiquer que 95% des comptes ont le MFA. D2 peut révéler que Basic Auth SMTP est actif sur tous ces comptes. Les deux ensemble : le MFA est configuré mais contournable — le résultat réel est 0% de protection effective.

**Politique CA active mais inefficace (D2 + D3)**  
D3 peut montrer une politique CA qui "bloque les protocoles legacy". D2 peut révéler que cette politique est en mode Report-Only depuis 4 mois — non bloquante. Résultat : la politique existe sur le papier, rien n'est bloqué en réalité.

**Guests sans MFA (D1 + D3 + D5)**  
D1 mesure le MFA des membres internes. D5 inventorie les guests. D3 vérifie si une politique CA couvre les guests. La combinaison révèle si les utilisateurs externes s'authentifient sans aucune contrainte de sécurité.

**Applications avec permissions mais sans CA (D3 + D4)**  
D4 peut détecter une application avec des permissions Mail.ReadWrite.All. D3 peut révéler qu'aucune politique CA ne couvre cette application. Résultat : n'importe quelle connexion depuis n'importe quel pays, à n'importe quelle heure, peut accéder à toutes les boîtes mail.

---

## Section 5 — Modèle de maturité authentification

Ce modèle permet de positionner un client et de prioriser les actions.

### Niveau 0 — Non géré
- Pas de MFA généralisé
- Basic Auth actif partout
- Pas de politique CA
- Admins synchronisés dans Entra ID
- Aucun inventaire des applications

### Niveau 1 — Basique
- MFA déployé pour une partie des utilisateurs
- Quelques politiques CA (souvent en Report-Only)
- Protocoles legacy partiellement bloqués
- Entra Connect configuré mais non audité

### Niveau 2 — Structuré
- MFA généralisé (>90%)
- Politiques CA actives couvrant tous les utilisateurs et applications
- Legacy auth bloqué par CA
- Comptes Tier 0 non synchronisés
- Secrets applicatifs inventoriés

### Niveau 3 — Avancé
- MFA fort (FIDO2 / Windows Hello) pour les comptes sensibles
- Conditions de risque Entra ID Protection exploitées
- Seamless SSO AZUREADSSOACC$ renouvelé régulièrement
- Consentements OAuth contrôlés par politique admin
- Score IAM-Lab Framework > 80/100 sur tous les domaines

### Niveau 4 — Optimisé
- Zero Trust complet (vérification systématique de chaque connexion)
- PAM intégré pour les comptes à privilèges
- SIEM avec corrélation des événements d'authentification
- Red team régulier sur les vecteurs d'authentification
- Score IAM-Lab Framework > 95/100

---

## Section 6 — Ordre d'audit recommandé et pourquoi

L'ordre D1 → D2 → D6 → D5 → D3 → D4 n'est pas arbitraire.

**D1 avant D2 :** Connaître la couverture MFA avant d'analyser les contournements MFA donne le vrai niveau d'exposition. Un taux MFA de 60% + legacy auth actif = 60% des comptes ont un MFA inutile.

**D2 avant D3 :** Connaître les protocoles actifs avant d'analyser les CA permet de détecter les politiques CA qui "bloquent" des protocoles qui ne sont pas réellement bloqués (Report-Only).

**D6 tôt :** Un Tier 0 synchronisé est une bombe à retardement. C'est la vérification qui peut justifier une action urgente hors du rythme normal de la mission.

**D5 avant D3 :** Les guests sont souvent exclus des politiques CA. Il faut savoir qui sont les guests (D5) avant d'analyser si les CA les couvrent (D3).

**D3 et D4 en dernier :** Ce sont les domaines les plus complexes et les plus risqués à remedier. Les auditer en dernier permet d'avoir le contexte complet des autres domaines.

---

*Document produit dans le cadre de l'IAM-Lab Framework.*  
*Pour le mapping réglementaire détaillé : voir `compliance-mapping.md`.*  
*Pour la procédure de remédiation : voir `remediation-guide.md`.*
