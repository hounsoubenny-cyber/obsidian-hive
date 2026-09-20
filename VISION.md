# Obsidian Hive — Vision & Roadmap

> Ce document contient l'ambition à long terme du projet — tout ce qui n'est pas encore construit, ou qui n'est encore qu'une esquisse. Le [`README.md`](./README.md) décrit l'état réel du code aujourd'hui ; ce fichier décrit où la Hive va.

---

## Positionnement

> CrowdStrike sert les entreprises du Fortune 500 à 50K$/an. Darktrace vise l'Europe. SentinelOne vise les US.
> **Obsidian Hive est construit pour les infrastructures que les géants occidentaux ignorent.**

Pensée pour tourner sur du matériel modeste et être accessible aux organisations qui n'ont pas de budget de sécurité entreprise, la Hive vise en priorité le marché ouest-africain — PME, banques, télécoms, gouvernements francophones — avant une expansion internationale appuyée sur un historique éprouvé.

```
Phase 1 → Dominer les PME et startups d'Afrique de l'Ouest
Phase 2 → Banques, télécoms, gouvernements d'Afrique francophone
Phase 3 → Multinationales opérant en Afrique
Phase 4 → Expansion internationale
```

---

## Modules à construire

### Transverses
| Module | Description |
|---|---|
| **Risk Scoring Engine** | Score de risque continu par asset, mis à jour à chaque événement |
| **Audit Trail** | Piste d'audit immuable de toutes les actions système et admin |
| **Playbook Engine** | Scripts de remédiation versionnés, testés en sandbox avant déploiement |
| **Smart Alert System** | Alertes groupées par criticité, anti-spam (Info / Warning / Critical) |
| **System Memory** | Mémoire longue durée par asset — historique des attaques, correctifs, patterns |
| **Report Engine** | Rapports PDF/HTML générés automatiquement par scan, incident, simulation |
| **CVE / VulnTracker** | Correspondance services détectés ↔ CVE connues, scoring de sévérité |
| **SIEM-like Log Manager** | Analyse intelligente de logs, détection d'anomalies, stockage horodaté |
| **Cybersecurity Chatbot** | Assistant NLP pour analystes, protégé par ContextGuard |

### Écosystème
| Module | Description |
|---|---|
| **Mail Proxy** | Proxy SMTP/IMAP — intercepte et analyse les emails avant livraison |
| **Mail Integration** | Connecteur API Gmail/Outlook, option de déploiement plus légère que le proxy |
| **Dashboard admin (React)** | Interface d'administration avec mises à jour temps réel WebSocket |

### Différenciation avancée (Phase 3)
| Module | Description |
|---|---|
| **Honeypots dynamiques** | Leurres pilotés par IA pour étudier les attaquants en temps réel |
| **Dark Web Intelligence** | Surveillance des identifiants et infrastructures compromises |
| **UEBA** | Analyse comportementale utilisateurs/entités — détection de menaces internes |
| **Threat Feed Dashboard** | Scoring de menaces en temps réel, priorisation, feed global |
| **Attack Surface Visualizer** | Cartographie interactive de l'infrastructure — assets, liens, zones à risque |
| **Adaptive Zero-Trust Engine** | Vérification de confiance dynamique par requête/utilisateur |
| **Cyber Threat Anticipation** | IA prédictive — anticipe les vecteurs d'attaque avant qu'ils ne se matérialisent |
| **Blockchain Security Layer** | Logs d'audit immuables et infalsifiables |
| **Privacy Guardian** | Anonymisation intelligente des données, conformité type RGPD |
| **Cross-platform Vuln Intelligence** | Corrélation vulnérabilités Web + Mobile + Cloud |
| **Auto-patching** | Propose ou applique des correctifs automatiquement (validation admin) |
| **Social Engineering Simulator** | Campagnes de phishing et simulations d'ingénierie sociale |

### Red / Blue / Purple Team AI (Phase 4)
| Module | Description |
|---|---|
| **Blue Team AI** | Défend, détecte et bloque les attaques du simulateur de façon autonome |
| **Purple Team AI** | Fusion Red+Blue — analyse les interactions, optimise les défenses, ajuste les playbooks |
| **Automated Incident Response** | Playbooks IA — auto-isolation, auto-patch, auto-escalade |

---

## Roadmap long terme

```
Phase 1 → MVP — modules cœur + orchestration (Coralie/Alex)      ~95% fait
Phase 2 → Écosystème complet — dashboard, mail proxy, transverses
Phase 3 → Intelligence avancée — honeypots, dark web, UEBA
Phase 4 → Expansion marché — Red/Blue/Purple Team, Zero-Trust, international
```

---

## Notes de nomenclature

Les tout premiers brouillons du projet (voir `INNOVATIONS/names.txt`) envisageaient un nom façon "HiveMind Security" avec des agents baptisés Scout, Watch, Decoy, Forge, Vault — jamais implémentés sous ces noms. Les vrais agents du code sont **Coralie** et **Alex** ; le simulateur d'attaque (`simulateur_attaque_ia`) joue aujourd'hui le rôle de l'agent offensif autonome, sans avoir besoin d'un nom à part.
