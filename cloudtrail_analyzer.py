#!/usr/bin/env python3
"""
Analyseur CloudTrail pour Actions Critiques de Sécurité AWS
Auteur: SOC Security Analyst
Description: Parse les logs CloudTrail pour identifier les actions critiques
"""

import json
import gzip
import boto3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import pandas as pd
from pathlib import Path
import argparse
import sys


class CloudTrailAnalyzer:
    def __init__(self):
        self.critical_events = {
            # Actions IAM critiques
            'iam_critical': [
                'CreateRole', 'DeleteRole', 'AttachRolePolicy', 'DetachRolePolicy',
                'PutRolePolicy', 'DeleteRolePolicy', 'CreateUser', 'DeleteUser',
                'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
                'CreateGroup', 'DeleteGroup', 'AddUserToGroup', 'RemoveUserFromGroup',
                'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
                'CreateLoginProfile', 'UpdateLoginProfile', 'DeleteLoginProfile'
            ],

            # Actions EC2/VPC critiques
            'network_critical': [
                'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
                'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
                'CreateSecurityGroup', 'DeleteSecurityGroup',
                'CreateVpc', 'DeleteVpc', 'ModifyVpcAttribute',
                'CreateInternetGateway', 'AttachInternetGateway', 'DetachInternetGateway',
                'CreateRoute', 'DeleteRoute', 'ReplaceRoute',
                'AssociateRouteTable', 'DisassociateRouteTable'
            ],

            # Actions S3 critiques
            's3_critical': [
                'PutBucketPolicy', 'DeleteBucketPolicy', 'PutBucketAcl',
                'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
                'PutBucketEncryption', 'DeleteBucketEncryption'
            ],

            # Actions de configuration critiques
            'config_critical': [
                'StopConfigurationRecorder', 'DeleteConfigurationRecorder',
                'PutConfigurationRecorder', 'DeleteDeliveryChannel',
                'StopLogging', 'DeleteTrail', 'PutEventSelectors'
            ],

            # Actions KMS critiques
            'kms_critical': [
                'CreateKey', 'ScheduleKeyDeletion', 'CancelKeyDeletion',
                'PutKeyPolicy', 'CreateGrant', 'RevokeGrant', 'DisableKey', 'EnableKey'
            ]
        }

        self.suspicious_indicators = [
            'root', 'AssumeRole', 'ConsoleLogin', 'GetSessionToken',
            'decode-authorization-message'
        ]

    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse un fichier de log CloudTrail (JSON ou GZIP)"""
        try:
            if file_path.endswith('.gz'):
                with gzip.open(file_path, 'rt') as f:
                    data = json.load(f)
            else:
                with open(file_path, 'r') as f:
                    data = json.load(f)

            return data.get('Records', [])
        except Exception as e:
            print(f"❌ Erreur lors du parsing de {file_path}: {e}")
            return []

    def parse_s3_logs(self, bucket_name: str, prefix: str = 'CloudTrail/',
                      days_back: int = 7, debug: bool = False,
                      exact_path: str = None) -> List[Dict[str, Any]]:
        """Parse les logs CloudTrail depuis S3"""
        # Validate bucket name format
        if not bucket_name or not bucket_name.replace('-', '').replace('.', '').isalnum():
            print(f"❌ Nom de bucket invalide: '{bucket_name}'")
            return []
            
        s3_client = boto3.client('s3')
        all_records = []
        files_processed = 0
        files_found = 0

        try:
            # Calculer la date de début
            start_date = datetime.now() - timedelta(days=days_back)

            # Si un chemin exact est fourni, l'utiliser
            if exact_path:
                prefix = exact_path
                # Ensure prefix ends with '/' for directory-like paths unless it's a specific file pattern
                if not prefix.endswith(('.json', '.gz')) and not prefix.endswith('/'):
                    prefix += '/'
                if debug:
                    print(f"🔍 Mode chemin exact activé: {prefix}")

            if debug:
                print(f"🔍 Debug - Bucket: {bucket_name}")
                print(f"🔍 Debug - Préfixe: {prefix}")
                print(f"🔍 Debug - Date limite: {start_date}")

            # Lister les objets dans le bucket
            paginator = s3_client.get_paginator('list_objects_v2')

            try:
                page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

                for page in page_iterator:
                    if 'Contents' not in page:
                        if debug:
                            print("🔍 Debug - Aucun contenu trouvé dans cette page")
                        continue

                    if debug:
                        print(f"🔍 Debug - {len(page['Contents'])} objets trouvés dans cette page")

                    for obj in page['Contents']:
                        files_found += 1

                        # Afficher quelques fichiers trouvés en mode debug
                        if debug and files_found <= 5:
                            print(f"🔍 Debug - Fichier trouvé: {obj['Key']} (modifié: {obj['LastModified']})")

                        # Vérifier que c'est un fichier de log (pas un dossier)
                        if obj['Key'].endswith('/'):
                            continue

                        # Vérifier l'extension du fichier (handle .json.gz properly)
                        valid_extensions = ('.json', '.gz', '.json.gz')
                        if not any(obj['Key'].endswith(ext) for ext in valid_extensions):
                            if debug:
                                print(f"🔍 Debug - Fichier ignoré (extension): {obj['Key']}")
                            continue

                        # Filtrer par date si nécessaire (handle timezone properly)
                        file_date = obj['LastModified']
                        if file_date.tzinfo is not None:
                            # Convert to naive datetime in UTC for comparison
                            file_date = file_date.replace(tzinfo=None)
                        if file_date < start_date:
                            if debug and files_found <= 3:  # Fix: use files_found instead of files_processed
                                print(f"🔍 Debug - Fichier trop ancien ignoré: {obj['Key']}")
                            continue

                        print(f"📥 Téléchargement: {obj['Key']} ({obj['Size']} bytes)")

                        try:
                            # Télécharger et parser le fichier avec timeout
                            response = s3_client.get_object(Bucket=bucket_name, Key=obj['Key'])
                            
                            # Handle both .gz and .json.gz files
                            if obj['Key'].endswith('.gz'):
                                try:
                                    content = gzip.decompress(response['Body'].read()).decode('utf-8')
                                except gzip.BadGzipFile:
                                    print(f"❌ Fichier GZIP corrompu: {obj['Key']}")
                                    continue
                            else:
                                content = response['Body'].read().decode('utf-8')
                            
                            # Validate JSON before parsing
                            if not content.strip():
                                print(f"⚠️ Fichier vide ignoré: {obj['Key']}")
                                continue
                                
                            try:
                                data = json.loads(content)
                            except json.JSONDecodeError as e:
                                print(f"❌ JSON invalide dans {obj['Key']}: {e}")
                                continue
                                
                            records = data.get('Records', [])
                            
                            if records:
                                all_records.extend(records)
                                files_processed += 1
                                print(f"✅ Traité: {len(records)} événements dans {obj['Key']}")
                            else:
                                print(f"⚠️ Aucun événement dans: {obj['Key']}")
                                
                        except Exception as e:
                            print(f"❌ Erreur lors du traitement de {obj['Key']}: {type(e).__name__}: {e}")
                            continue

            except Exception as e:
                if "NoSuchBucket" in str(e):
                    print(f"❌ Le bucket '{bucket_name}' n'existe pas ou n'est pas accessible")
                elif "AccessDenied" in str(e):
                    print(f"❌ Accès refusé au bucket '{bucket_name}' ou au préfixe '{prefix}'")
                else:
                    print(f"❌ Erreur S3: {type(e).__name__}: {e}")
                    return []

            print(f"📊 Résumé S3:")
            print(f"   • Fichiers trouvés: {files_found}")
            print(f"   • Fichiers traités: {files_processed}")
            print(f"   • Total événements: {len(all_records)}")

            # Suggestions si aucun fichier trouvé
            if files_found == 0:
                print("\n💡 Suggestions de dépannage:")
                print("   1. Vérifiez le nom du bucket")
                print("   2. Utilisez --debug pour plus d'informations")
                print("   3. Essayez --list-prefixes pour explorer le bucket")
                print("   4. Utilisez --exact-path si vous connaissez le chemin exact")
                print("   5. Vérifiez vos permissions AWS")

            return all_records

        except Exception as e:
            print(f"❌ Erreur lors de la récupération depuis S3: {e}")
            return []

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse un événement CloudTrail"""
        analysis = {
            'timestamp': event.get('eventTime'),
            'event_name': event.get('eventName'),
            'event_source': event.get('eventSource'),
            'user_identity': self._extract_user_identity(event),
            'source_ip': event.get('sourceIPAddress'),
            'user_agent': event.get('userAgent'),
            'aws_region': event.get('awsRegion'),
            'error_code': event.get('errorCode'),
            'error_message': event.get('errorMessage'),
            'is_critical': False,
            'criticality_reason': [],
            'risk_score': 0,
            'resources': self._extract_resources(event)
        }

        # Analyser la criticité
        self._assess_criticality(analysis, event)

        return analysis

    def _extract_user_identity(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extrait les informations d'identité utilisateur"""
        user_identity = event.get('userIdentity', {})
        return {
            'type': user_identity.get('type'),
            'principal_id': user_identity.get('principalId'),
            'arn': user_identity.get('arn'),
            'account_id': user_identity.get('accountId'),
            'user_name': user_identity.get('userName'),
            'session_context': user_identity.get('sessionContext', {})
        }

    def _extract_resources(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrait les ressources impactées"""
        resources = []
        for resource in event.get('resources', []):
            resources.append({
                'arn': resource.get('ARN'),
                'account_id': resource.get('accountId'),
                'type': resource.get('type')
            })
        return resources

    def _assess_criticality(self, analysis: Dict[str, Any], event: Dict[str, Any]):
        """Évalue la criticité d'un événement"""
        event_name = analysis['event_name']
        user_identity = analysis['user_identity']

        risk_score = 0
        reasons = []

        # Vérifier si l'action est dans la liste critique
        for category, actions in self.critical_events.items():
            if event_name in actions:
                analysis['is_critical'] = True
                reasons.append(f"Action critique détectée: {category}")
                risk_score += 50

        # Actions effectuées par root
        if user_identity.get('type') == 'Root':
            reasons.append("Action effectuée par le compte root")
            risk_score += 30

        # Actions depuis une IP externe suspecte
        source_ip = analysis['source_ip']
        if source_ip and not self._is_aws_ip(source_ip) and not self._is_internal_ip(source_ip):
            reasons.append(f"Action depuis IP externe: {source_ip}")
            risk_score += 20

        # Erreurs d'accès
        if analysis['error_code']:
            if 'AccessDenied' in analysis['error_code']:
                reasons.append("Tentative d'accès refusée")
                risk_score += 25
            elif 'UnauthorizedOperation' in analysis['error_code']:
                reasons.append("Opération non autorisée")
                risk_score += 25

        # Actions AssumeRole suspectes
        if event_name == 'AssumeRole':
            assumed_role = event.get('requestParameters', {}).get('roleArn', '')
            if 'OrganizationAccountAccessRole' in assumed_role:
                reasons.append("AssumeRole vers un rôle d'accès organisation")
                risk_score += 15

        # Console login depuis des IPs inhabituelles
        if event_name == 'ConsoleLogin':
            if event.get('responseElements', {}).get('ConsoleLogin') == 'Success':
                reasons.append("Connexion console réussie")
                risk_score += 10

        analysis['criticality_reason'] = reasons
        analysis['risk_score'] = min(risk_score, 100)  # Cap à 100

        if risk_score >= 30:
            analysis['is_critical'] = True

    def _is_aws_ip(self, ip: str) -> bool:
        """Vérifie si l'IP appartient à AWS"""
        aws_services = ['cloudformation', 'config', 's3', 'ec2', 'iam']
        return any(service in ip.lower() for service in aws_services)

    def _is_internal_ip(self, ip: str) -> bool:
        """Vérifie si l'IP est interne (RFC 1918)"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    def generate_report(self, critical_events: List[Dict[str, Any]],
                        output_format: str = 'console') -> None:
        """Génère un rapport des événements critiques"""

        if not critical_events:
            print("✅ Aucun événement critique détecté!")
            return

        # Trier par score de risque décroissant
        critical_events.sort(key=lambda x: x['risk_score'], reverse=True)

        if output_format == 'console':
            self._print_console_report(critical_events)
        elif output_format == 'csv':
            self._export_csv_report(critical_events)
        elif output_format == 'json':
            self._export_json_report(critical_events)

    def _print_console_report(self, events: List[Dict[str, Any]]):
        """Affiche le rapport en console"""
        print("\n" + "=" * 80)
        print("🚨 RAPPORT D'ANALYSE CLOUDTRAIL - ÉVÉNEMENTS CRITIQUES")
        print("=" * 80)
        print(f"📊 Nombre d'événements critiques: {len(events)}")
        print(f"⏰ Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

        for i, event in enumerate(events[:20], 1):  # Top 20
            print(f"\n🔍 ÉVÉNEMENT #{i} - Score de risque: {event['risk_score']}/100")
            print("-" * 60)
            print(f"⏰ Timestamp: {event['timestamp']}")
            print(f"🎯 Action: {event['event_name']}")
            print(f"🌐 Service: {event['event_source']}")
            print(f"👤 Utilisateur: {event['user_identity'].get('arn', 'N/A')}")
            print(f"🌍 IP Source: {event['source_ip']}")
            print(f"📍 Région: {event['aws_region']}")

            if event['error_code']:
                print(f"❌ Erreur: {event['error_code']} - {event['error_message']}")

            if event['criticality_reason']:
                print("🚩 Raisons de criticité:")
                for reason in event['criticality_reason']:
                    print(f"   • {reason}")

            if event['resources']:
                print("📦 Ressources impactées:")
                for resource in event['resources'][:3]:  # Max 3 ressources
                    print(f"   • {resource['arn']}")

    def _export_csv_report(self, events: List[Dict[str, Any]]):
        """Exporte le rapport en CSV"""
        df_data = []
        for event in events:
            df_data.append({
                'Timestamp': event['timestamp'],
                'EventName': event['event_name'],
                'EventSource': event['event_source'],
                'UserARN': event['user_identity'].get('arn', ''),
                'UserType': event['user_identity'].get('type', ''),
                'SourceIP': event['source_ip'],
                'Region': event['aws_region'],
                'RiskScore': event['risk_score'],
                'ErrorCode': event['error_code'] or '',
                'CriticalityReasons': '; '.join(event['criticality_reason'])
            })

        df = pd.DataFrame(df_data)
        filename = f"cloudtrail_critical_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(filename, index=False)
        print(f"📄 Rapport CSV exporté: {filename}")

    def _export_json_report(self, events: List[Dict[str, Any]]):
        """Exporte le rapport en JSON"""
        filename = f"cloudtrail_critical_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump({
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_critical_events': len(events),
                    'analyzer_version': '1.0'
                },
                'critical_events': events
            }, f, indent=2, default=str)
        print(f"📄 Rapport JSON exporté: {filename}")

    def list_s3_structure(self, bucket_name: str, max_depth: int = 3) -> None:
        """Explore la structure du bucket S3 pour aider à trouver les logs"""
        s3_client = boto3.client('s3')

        print(f"🔍 Exploration de la structure du bucket '{bucket_name}':")
        print("=" * 60)

        try:
            # Lister les objets avec différents préfixes communs
            common_prefixes = [
                '',  # racine
                'CloudTrail/',
                'AWSLogs/',
                'cloudtrail/',
                'logs/',
                'aws-cloudtrail/',
            ]

            found_paths = set()

            for prefix in common_prefixes:
                try:
                    paginator = s3_client.get_paginator('list_objects_v2')
                    page_iterator = paginator.paginate(
                        Bucket=bucket_name,
                        Prefix=prefix,
                        Delimiter='/'
                    )

                    for page in page_iterator:
                        # Dossiers
                        for common_prefix in page.get('CommonPrefixes', []):
                            folder_path = common_prefix['Prefix']
                            if folder_path not in found_paths:
                                found_paths.add(folder_path)
                                print(f"📁 {folder_path}")

                        # Fichiers
                        for obj in page.get('Contents', [])[:10]:  # Limiter à 10 fichiers par préfixe
                            if obj['Key'].endswith('.json') or obj['Key'].endswith('.gz'):
                                print(f"📄 {obj['Key']} ({obj['Size']} bytes, {obj['LastModified']})")

                except Exception as e:
                    continue

            print("\n💡 Conseils d'utilisation:")
            print("   • Utilisez --exact-path avec un des chemins trouvés ci-dessus")
            print("   • Les logs CloudTrail sont souvent dans: AWSLogs/ACCOUNT-ID/CloudTrail/REGION/YEAR/MONTH/DAY/")
            print("   • Exemple: --exact-path 'AWSLogs/123456789012/CloudTrail/us-east-1/2025/08/'")

        except Exception as e:
            print(f"❌ Erreur lors de l'exploration: {e}")

    def find_cloudtrail_paths(self, bucket_name: str) -> List[str]:
        """Trouve automatiquement les chemins contenant des logs CloudTrail"""
        s3_client = boto3.client('s3')
        cloudtrail_paths = []

        try:
            # Rechercher les patterns typiques de CloudTrail
            patterns = [
                'AWSLogs/',
                'CloudTrail/',
                'cloudtrail/',
            ]

            for pattern in patterns:
                paginator = s3_client.get_paginator('list_objects_v2')
                page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=pattern)

                for page in page_iterator:
                    for obj in page.get('Contents', []):
                        if obj['Key'].endswith(('.json', '.gz')):
                            # Extraire le chemin du dossier parent
                            path_parts = obj['Key'].split('/')[:-1]  # Retirer le nom du fichier
                            if len(path_parts) > 0:
                                folder_path = '/'.join(path_parts) + '/'
                                if folder_path not in cloudtrail_paths:
                                    cloudtrail_paths.append(folder_path)

            return cloudtrail_paths

        except Exception as e:
            print(f"❌ Erreur lors de la recherche automatique: {e}")
            return []


def main():
    parser = argparse.ArgumentParser(description='Analyseur CloudTrail pour Actions Critiques')
    parser.add_argument('--source', choices=['file', 's3'], default='file',
                        help='Source des logs (file ou s3)')
    parser.add_argument('--path', type=str,
                        help='Chemin vers le fichier de log ou nom du bucket S3')
    parser.add_argument('--prefix', type=str, default='CloudTrail/',
                        help='Préfixe S3 (défaut: CloudTrail/)')
    parser.add_argument('--days', type=int, default=7,
                        help='Nombre de jours à analyser (défaut: 7)')
    parser.add_argument('--output', choices=['console', 'csv', 'json'], default='console',
                        help='Format de sortie du rapport')
    parser.add_argument('--min-risk-score', type=int, default=30,
                        help='Score de risque minimum pour considérer un événement comme critique')
    parser.add_argument('--list-prefixes', action='store_true',
                        help='Explorer la structure du bucket S3 pour trouver les préfixes')
    parser.add_argument('--debug', action='store_true',
                        help='Activer le mode debug pour plus d\'informations')
    parser.add_argument('--exact-path', type=str,
                        help='Chemin exact dans le bucket S3')

    args = parser.parse_args()

    analyzer = CloudTrailAnalyzer()

    # Si l'option --list-prefixes est utilisée
    if args.list_prefixes:
        if not args.path:
            print("❌ Erreur: Veuillez spécifier --path (nom du bucket) avec --list-prefixes")
            sys.exit(1)
        analyzer.list_s3_structure(args.path)
        sys.exit(0)

    if not args.path:
        print("❌ Erreur: Veuillez spécifier --path")
        sys.exit(1)

    print("🔍 Début de l'analyse CloudTrail...")

    # Charger les logs
    if args.source == 'file':
        if Path(args.path).is_file():
            records = analyzer.parse_log_file(args.path)
        else:
            # Plusieurs fichiers dans un dossier
            records = []
            for file_path in Path(args.path).glob('*.json*'):
                records.extend(analyzer.parse_log_file(str(file_path)))
    else:
        # Pass exact_path directly to the method, let it handle prefix logic internally
        records = analyzer.parse_s3_logs(args.path, args.prefix, args.days, args.debug, args.exact_path)

    if not records:
        print("❌ Aucun log trouvé à analyser!")
        sys.exit(1)

    print(f"📊 Analyse de {len(records)} événements...")

    # Analyser les événements
    critical_events = []
    for record in records:
        analysis = analyzer.analyze_event(record)
        if analysis['is_critical'] and analysis['risk_score'] >= args.min_risk_score:
            critical_events.append(analysis)

    # Générer le rapport
    analyzer.generate_report(critical_events, args.output)

    print(f"\n✅ Analyse terminée! {len(critical_events)} événements critiques détectés.")


if __name__ == "__main__":
    main()