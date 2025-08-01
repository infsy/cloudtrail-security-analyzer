# CloudTrail Security Analyzer 🔍

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail-orange.svg)](https://aws.amazon.com/cloudtrail/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-SOC-red.svg)](https://github.com)

Un outil d'analyse avancé pour les logs AWS CloudTrail, conçu pour les équipes SOC (Security Operations Center) afin d'identifier instantanément les actions critiques et les menaces de sécurité.

## 🎯 Objectif

Cet outil permet aux analystes de sécurité de :
- **Détecter rapidement** les actions critiques dans les logs CloudTrail
- **Identifier** qui a modifié des groupes de sécurité, créé des rôles IAM, ou effectué d'autres actions sensibles
- **Scorer le risque** de chaque événement avec un système de notation intelligent
- **Générer des rapports** détaillés pour l'investigation et la conformité

## 🚨 Actions Critiques Détectées

### 🔐 IAM (Identity & Access Management)
- Création/suppression de rôles et utilisateurs
- Modification de politiques IAM
- Création/suppression de clés d'accès
- Gestion des groupes utilisateurs

### 🌐 Réseau & Sécurité
- **Modifications de groupes de sécurité** (règles entrantes/sortantes)
- Création/suppression de VPC
- Modifications de tables de routage
- Gestion des Internet Gateways

### 📦 Stockage S3
- Modification de politiques de bucket
- Changements d'ACL et de chiffrement
- Configuration d'accès public

### 📊 Surveillance & Conformité
- Arrêt/suppression de CloudTrail
- Désactivation d'AWS Config
- Suppression de logs de sécurité

### 🔑 Gestion des Clés (KMS)
- Création/suppression de clés de chiffrement
- Modification de politiques KMS
- Gestion des grants

## 🛠️ Installation

### Prérequis
```bash
pip install boto3 pandas
```

### Configuration AWS
```bash
aws configure
# ou utiliser des variables d'environnement
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-west-2
```

## 🚀 Utilisation

### Analyse d'un fichier local
```bash
python cloudtrail_analyzer.py --source file --path /path/to/cloudtrail-logs.json
```

### Analyse depuis S3 (recommandé)
```bash
# Analyser les 7 derniers jours
python cloudtrail_analyzer.py --source s3 --path mon-bucket-cloudtrail --days 7

# Analyser avec préfixe personnalisé
python cloudtrail_analyzer.py --source s3 --path mon-bucket --prefix AWSLogs/123456789/CloudTrail/ --days 3
```

### Génération de rapports
```bash
# Rapport CSV pour Excel
python cloudtrail_analyzer.py --source s3 --path mon-bucket --output csv

# Rapport JSON pour intégrations
python cloudtrail_analyzer.py --source s3 --path mon-bucket --output json

# Filtrer par score de risque minimum
python cloudtrail_analyzer.py --source s3 --path mon-bucket --min-risk-score 50
```

### Analyse d'un dossier de logs
```bash
python cloudtrail_analyzer.py --source file --path /var/log/cloudtrail/
```

## 📊 Exemple de Sortie

```
================================================================================
🚨 RAPPORT D'ANALYSE CLOUDTRAIL - ÉVÉNEMENTS CRITIQUES
================================================================================
📊 Nombre d'événements critiques: 15
⏰ Généré le: 2025-08-01 14:30:25
================================================================================

🔍 ÉVÉNEMENT #1 - Score de risque: 85/100
------------------------------------------------------------
⏰ Timestamp: 2025-08-01T12:15:30Z
🎯 Action: AuthorizeSecurityGroupIngress
🌐 Service: ec2.amazonaws.com
👤 Utilisateur: arn:aws:iam::123456789:user/admin-user
🌍 IP Source: 203.0.113.42
📍 Région: us-west-2
🚩 Raisons de criticité:
   • Action critique détectée: network_critical
   • Action depuis IP externe: 203.0.113.42
📦 Ressources impactées:
   • arn:aws:ec2:us-west-2:123456789:security-group/sg-0123456789abcdef0
```

## 🔢 Système de Scoring

Le système attribue des points de risque basés sur :

| Critère | Points | Description |
|---------|--------|-------------|
| **Action critique** | +50 | Action dans la liste des événements critiques |
| **Compte root** | +30 | Action effectuée par le compte root AWS |
| **IP externe** | +20 | Action depuis une IP non-AWS et non-interne |
| **Erreur d'accès** | +25 | Tentative d'accès refusée ou non autorisée |
| **AssumeRole suspect** | +15 | Prise de rôle vers des rôles sensibles |
| **Connexion console** | +10 | Connexion réussie à la console AWS |

**Score total :** 0-100 (limité à 100)

## 📋 Options de Ligne de Commande

```
--source {file,s3}     Source des logs (fichier local ou S3)
--path PATH            Chemin vers fichier/dossier ou nom du bucket S3
--prefix PREFIX        Préfixe S3 (défaut: CloudTrail/)
--days DAYS            Nombre de jours à analyser depuis S3 (défaut: 7)
--output {console,csv,json}  Format de sortie (défaut: console)
--min-risk-score SCORE Score minimum pour filtrer (défaut: 30)
```

## 🔧 Structure du Projet

```
cloudtrail-security-analyzer/
├── cloudtrail_analyzer.py    # Script principal
├── README.md                 # Documentation
├── requirements.txt          # Dépendances Python
├── examples/                 # Exemples de logs
└── docs/                    # Documentation additionnelle
```

## 🎯 Cas d'Usage Typiques

### Investigation de Sécurité
```bash
# Rechercher les actions suspectes des dernières 24h
python cloudtrail_analyzer.py --source s3 --path security-logs --days 1 --min-risk-score 70
```

### Audit de Conformité
```bash
# Générer un rapport mensuel
python cloudtrail_analyzer.py --source s3 --path audit-logs --days 30 --output csv
```

### Monitoring en Temps Réel
```bash
# Intégrer dans un pipeline SOC
python cloudtrail_analyzer.py --source s3 --path realtime-logs --output json | jq '.critical_events[]'
```

## 🔐 Bonnes Pratiques de Sécurité

1. **Permissions minimales** : Utilisez un rôle IAM avec accès en lecture seule aux logs
2. **Chiffrement** : Assurez-vous que vos buckets S3 sont chiffrés
3. **Rotation des clés** : Changez régulièrement vos clés d'accès AWS
4. **Surveillance continue** : Automatisez l'exécution pour un monitoring 24/7

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. Fork le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add AmazingFeature'`)
4. Pushez vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📝 Changelog

### v1.0.0 (2025-08-01)
- 🎉 Version initiale
- ✅ Support des fichiers locaux et S3
- ✅ Détection d'actions critiques IAM, EC2, S3, KMS
- ✅ Système de scoring de risque
- ✅ Export CSV/JSON
- ✅ Interface en ligne de commande

## 🐛 Signaler un Bug

Si vous trouvez un bug, veuillez créer une [issue](https://github.com/votre-username/cloudtrail-security-analyzer/issues) avec :
- Description du problème
- Étapes pour reproduire
- Logs d'erreur (si applicable)
- Environnement (Python version, OS)

## 📧 Support

Pour toute question ou support :
- 📧 Email: votre-email@exemple.com
- 💬 Issues GitHub: [Créer une issue](https://github.com/votre-username/cloudtrail-security-analyzer/issues)

## 📄 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- AWS CloudTrail Documentation
- Communauté de sécurité AWS
- Contributeurs open source

---

**⚠️ Avertissement de Sécurité :** Cet outil est conçu pour l'analyse de sécurité. Assurez-vous de respecter les politiques de sécurité de votre organisation et les réglementations en vigueur lors de l'analyse des logs.

**🔍 Made with ❤️ for SOC Teams**