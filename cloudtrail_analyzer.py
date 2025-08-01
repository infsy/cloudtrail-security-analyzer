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
                     days_back: int = 7) -> List[Dict[str, Any]]:
        """Parse les logs CloudTrail depuis S3"""
        s3_client = boto3.client('s3')
        all_records = []
        
        try:
            # Calculer la date de début
            start_date = datetime.now() - timedelta(days=days_back)
            
            # Lister les objets dans le bucket
            paginator = s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
            
            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                    
                for obj in page['Contents']:
                    # Filtrer par date si nécessaire
                    if obj['LastModified'].replace(tzinfo=None) < start_date:
                        continue
                    
                    print(f"📥 Téléchargement: {obj['Key']}")
                    
                    # Télécharger et parser le fichier
                    response = s3_client.get_object(Bucket=bucket_name, Key=obj['Key'])
                    
                    if obj['Key'].endswith('.gz'):
                        content = gzip.decompress(response['Body'].read()).decode('utf-8')
                    else:
                        content = response['Body'].read().decode('utf-8')
                    
                    data = json.loads(content)
                    all_records.extend(data.get('Records', []))
            
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
        print("\n" + "="*80)
        print("🚨 RAPPORT D'ANALYSE CLOUDTRAIL - ÉVÉNEMENTS CRITIQUES")
        print("="*80)
        print(f"📊 Nombre d'événements critiques: {len(events)}")
        print(f"⏰ Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
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
    
    args = parser.parse_args()
    
    if not args.path:
        print("❌ Erreur: Veuillez spécifier --path")
        sys.exit(1)
    
    analyzer = CloudTrailAnalyzer()
    
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
        records = analyzer.parse_s3_logs(args.path, args.prefix, args.days)
    
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
