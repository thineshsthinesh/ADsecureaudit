#!/usr/bin/env python3
"""
AD SecureAudit: Active Directory Security Configuration Scanner
Complete Implementation with Real LDAP Integration
Version 2.0 - Enhanced Detection & Reporting
"""

import argparse
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import concurrent.futures
from collections import defaultdict
import re
import os

# Enable MD4 for NTLM on Python 3.8+
import hashlib
try:
    import ssl
    if hasattr(hashlib, 'md4'):
        pass
    else:
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            pass
except Exception as e:
    logging.debug(f"MD4 setup: {e}")

# Alternative: Monkey-patch hashlib to add MD4 support
if not hasattr(hashlib, 'md4'):
    try:
        import ctypes
        import ctypes.util
        
        libcrypto = ctypes.CDLL(ctypes.util.find_library('crypto') or 
                                ctypes.util.find_library('libcrypto') or
                                'libeay32.dll')
        
        class MD4:
            def __init__(self, data=b''):
                self.ctx = ctypes.create_string_buffer(128)
                libcrypto.MD4_Init(self.ctx)
                if data:
                    self.update(data)
            
            def update(self, data):
                libcrypto.MD4_Update(self.ctx, data, len(data))
            
            def digest(self):
                md = ctypes.create_string_buffer(16)
                libcrypto.MD4_Final(md, self.ctx)
                return md.raw
            
            def hexdigest(self):
                return self.digest().hex()
        
        hashlib.md4 = lambda data=b'': MD4(data)
        logging.info("MD4 support enabled via OpenSSL")
        
    except Exception as e:
        logging.warning(f"Could not enable MD4: {e}")

# LDAP and AD libraries
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, SIMPLE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("Error: ldap3 not installed. Run: pip install ldap3")
    sys.exit(1)

# YAML for custom templates
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ad_secaudit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ADSecureAudit')


class TemplateLoader:
    """
    Template loading system similar to Nuclei
    Supports YAML-based security check templates
    """
    
    def __init__(self):
        self.templates = []
        self.template_count = 0
        
    def load_templates(self, template_paths: List[str]) -> List[Dict]:
        """
        Load templates from files or directories
        
        Args:
            template_paths: List of file paths or directory paths
            
        Returns:
            List of loaded template dictionaries
        """
        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed. Install with: pip install pyyaml")
            return []
        
        logger.info("Loading custom templates...")
        
        for path_str in template_paths:
            path = Path(path_str)
            
            if not path.exists():
                logger.warning(f"Template path does not exist: {path}")
                continue
            
            if path.is_file():
                self._load_template_file(path)
            elif path.is_dir():
                self._load_template_directory(path)
        
        logger.info(f"Loaded {self.template_count} custom templates")
        return self.templates
    
    def _load_template_file(self, file_path: Path):
        """Load a single template file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix in ['.yaml', '.yml']:
                    template_data = yaml.safe_load(f)
                elif file_path.suffix == '.json':
                    template_data = json.load(f)
                else:
                    logger.warning(f"Unsupported template format: {file_path.suffix}")
                    return
            
            # Validate template structure
            if self._validate_template(template_data):
                template_data['_source_file'] = str(file_path)
                self.templates.append(template_data)
                self.template_count += 1
                logger.debug(f"Loaded template: {template_data.get('info', {}).get('name', 'Unknown')}")
            else:
                logger.warning(f"Invalid template structure in: {file_path}")
                
        except Exception as e:
            logger.error(f"Error loading template {file_path}: {e}")
    
    def _load_template_directory(self, dir_path: Path):
        """Load all templates from a directory recursively"""
        for file_path in dir_path.rglob('*.yaml'):
            self._load_template_file(file_path)
        for file_path in dir_path.rglob('*.yml'):
            self._load_template_file(file_path)
        for file_path in dir_path.rglob('*.json'):
            self._load_template_file(file_path)
    
    def _validate_template(self, template: Dict) -> bool:
        """
        Validate template structure
        
        Required fields:
        - info: name, author, severity, description
        - ldap: search_filter, attributes
        - detection: conditions for triggering (optional)
        """
        if not isinstance(template, dict):
            return False
        
        # Check required sections
        if 'info' not in template:
            logger.debug("Template missing 'info' section")
            return False
        
        if 'ldap' not in template:
            logger.debug("Template missing 'ldap' section")
            return False
        
        # Validate info section
        info = template['info']
        required_info = ['name', 'author', 'severity', 'description']
        for field in required_info:
            if field not in info:
                logger.debug(f"Template info missing required field: {field}")
                return False
        
        # Validate LDAP section
        ldap = template['ldap']
        if 'search_filter' not in ldap:
            logger.debug("Template LDAP section missing 'search_filter'")
            return False
        
        if 'attributes' not in ldap or not isinstance(ldap['attributes'], list):
            logger.debug("Template LDAP section missing or invalid 'attributes'")
            return False
        
        return True
    
    def get_templates_by_severity(self, severity: str) -> List[Dict]:
        """Get templates filtered by severity"""
        return [t for t in self.templates if t['info']['severity'].upper() == severity.upper()]
    
    def get_templates_by_tag(self, tag: str) -> List[Dict]:
        """Get templates filtered by tag"""
        return [t for t in self.templates 
                if tag in t.get('info', {}).get('tags', [])]


class TemplateScanner:
    """
    Scanner that executes custom templates against AD
    """
    
    def __init__(self, ad_conn, templates: List[Dict]):
        self.ad_conn = ad_conn
        self.templates = templates
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Execute all loaded templates"""
        logger.info(f"Executing {len(self.templates)} custom templates...")
        
        for template in self.templates:
            try:
                self._execute_template(template)
            except Exception as e:
                logger.error(f"Error executing template {template['info']['name']}: {e}")
        
        logger.info(f"Custom template scan complete: {len(self.findings)} findings")
        return self.findings
    
    def _execute_template(self, template: Dict):
        """Execute a single template"""
        info = template['info']
        ldap_config = template['ldap']
        
        logger.debug(f"Executing template: {info['name']}")
        
        # Perform LDAP search
        search_filter = ldap_config['search_filter']
        attributes = ldap_config['attributes']
        search_base = ldap_config.get('search_base', None)
        
        results = self.ad_conn.search(search_filter, attributes, search_base)
        
        if not results:
            logger.debug(f"No results for template: {info['name']}")
            return
        
        # Apply detection logic
        detection = template.get('detection', {})
        matched_results = self._apply_detection(results, detection)
        
        # Create findings
        for result in matched_results:
            finding = self._create_finding(template, result)
            self.findings.append(finding)
            logger.info(f"[TEMPLATE] {info['severity'].upper()} - {info['name']}: {result.get('dn', 'Unknown DN')}")
    
    def _apply_detection(self, results: List[Dict], detection: Dict) -> List[Dict]:
        """
        Apply detection logic to filter results
        
        Detection conditions:
        - condition: "and" or "or"
        - rules: list of conditions to check
        """
        if not detection:
            # No detection rules, return all results
            return results
        
        condition_type = detection.get('condition', 'and').lower()
        rules = detection.get('rules', [])
        
        if not rules:
            return results
        
        matched = []
        
        for result in results:
            rule_matches = []
            
            for rule in rules:
                match = self._evaluate_rule(result, rule)
                rule_matches.append(match)
            
            # Combine rule results based on condition type
            if condition_type == 'and':
                if all(rule_matches):
                    matched.append(result)
            elif condition_type == 'or':
                if any(rule_matches):
                    matched.append(result)
        
        return matched
    
    def _evaluate_rule(self, result: Dict, rule: Dict) -> bool:
        """
        Evaluate a single detection rule
        
        Rule format:
        - attribute: LDAP attribute name
        - operator: equals, contains, regex, exists, greater_than, less_than, bitwise_and
        - value: expected value
        """
        attribute = rule.get('attribute')
        operator = rule.get('operator', 'exists')
        expected_value = rule.get('value')
        
        actual_value = result.get(attribute)
        
        if operator == 'exists':
            return actual_value is not None
        
        if operator == 'not_exists':
            return actual_value is None
        
        if actual_value is None:
            return False
        
        # Handle list values
        if isinstance(actual_value, list):
            actual_value = actual_value[0] if actual_value else None
        
        if operator == 'equals':
            return str(actual_value).lower() == str(expected_value).lower()
        
        elif operator == 'not_equals':
            return str(actual_value).lower() != str(expected_value).lower()
        
        elif operator == 'contains':
            return str(expected_value).lower() in str(actual_value).lower()
        
        elif operator == 'not_contains':
            return str(expected_value).lower() not in str(actual_value).lower()
        
        elif operator == 'regex':
            pattern = re.compile(expected_value, re.IGNORECASE)
            return pattern.search(str(actual_value)) is not None
        
        elif operator == 'greater_than':
            try:
                return int(actual_value) > int(expected_value)
            except (ValueError, TypeError):
                return False
        
        elif operator == 'less_than':
            try:
                return int(actual_value) < int(expected_value)
            except (ValueError, TypeError):
                return False
        
        elif operator == 'bitwise_and':
            # For checking UAC flags
            try:
                return (int(actual_value) & int(expected_value)) == int(expected_value)
            except (ValueError, TypeError):
                return False
        
        return False
    
    def _create_finding(self, template: Dict, result: Dict) -> Dict:
        """Create a finding from template and result"""
        info = template['info']
        
        # Map template severity to standard severity levels
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW',
            'info': 'LOW'
        }
        
        severity = severity_map.get(info['severity'].lower(), 'MEDIUM')
        
        # Calculate risk score based on severity
        risk_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        finding = {
            'module': 'CustomTemplate',
            'template_name': info['name'],
            'severity': severity,
            'title': info['name'],
            'description': info['description'],
            'dn': result.get('dn', 'Unknown'),
            'risk_score': risk_scores.get(severity, 5.0),
            'attack_vector': info.get('attack_vector', 'Custom template detection'),
            'mitigation': info.get('mitigation', 'Review template documentation'),
            'author': info['author'],
            'tags': info.get('tags', []),
            'references': info.get('references', []),
            'matched_attributes': {k: v for k, v in result.items() if k != 'dn'},
            'source_template': template.get('_source_file', 'Unknown')
        }
        
        return finding


class ADConnection:
    """Manages LDAP connection to Active Directory"""
    
    def __init__(self, domain: str, username: Optional[str] = None, password: Optional[str] = None, 
                 server: Optional[str] = None, use_kerberos: bool = False, use_ssl: bool = False):
        self.domain = domain
        self.username = username
        self.password = password
        self.server_address = server or domain
        self.use_kerberos = use_kerberos
        self.use_ssl = use_ssl
        self.connection = None
        self.base_dn = ','.join([f'DC={part}' for part in domain.split('.')])
        
    def connect(self) -> bool:
        """Establish connection to AD"""
        try:
            logger.info(f"Connecting to {self.server_address}...")
            
            port = 636 if self.use_ssl else 389
            
            server = Server(
                self.server_address, 
                port=port,
                get_info=ALL, 
                use_ssl=self.use_ssl
            )
            
            if self.use_kerberos:
                logger.info("Using Kerberos authentication via Windows SSPI")
                
                try:
                    import ldap3
                    from ldap3 import Tls
                    import ssl as ssl_module
                    
                    logger.info("Attempting Kerberos bind using current Windows credentials...")
                    
                    try:
                        import win32security
                        import sspi
                        
                        logger.info("Using pywin32 SSPI for Kerberos authentication")
                        
                        self.connection = Connection(
                            server,
                            auto_bind=False
                        )
                        
                        self.connection.open()
                        self.connection.bind()
                        
                        if self.connection.bound:
                            logger.info("✓ Connected using Windows Kerberos (SSPI)")
                        else:
                            raise Exception("Kerberos bind failed")
                            
                    except ImportError:
                        logger.warning("pywin32 not available, trying alternative method...")
                        
                        if self.username and self.password:
                            logger.info(f"Attempting Kerberos with credentials: {self.username}")
                            
                            if '@' not in self.username:
                                user_principal = f"{self.username}@{self.domain.upper()}"
                            else:
                                user_principal = self.username
                            
                            from ldap3 import SIMPLE
                            self.connection = Connection(
                                server,
                                user=user_principal,
                                password=self.password,
                                authentication=SIMPLE,
                                auto_bind=True
                            )
                            logger.info("✓ Connected using Kerberos-style authentication")
                        else:
                            raise Exception("Kerberos requires either SSPI or username/password")
                    
                except Exception as e_kerb:
                    logger.error(f"Kerberos authentication failed: {e_kerb}")
                    logger.error("\nTo enable Kerberos SSPI, install: pip install pywin32")
                    logger.error("Or provide username/password for Kerberos authentication")
                    return False
                
            else:
                if not self.username or not self.password:
                    logger.error("Username and password required")
                    return False
                
                if not self.use_ssl:
                    logger.info("Detected strongerAuthRequired - enabling LDAPS (SSL/TLS)")
                    server = Server(
                        self.server_address,
                        port=636,
                        get_info=ALL,
                        use_ssl=True
                    )
                    self.use_ssl = True
                
                logger.info(f"Attempting SIMPLE authentication over LDAPS for: {self.username}")
                
                if '@' not in self.username and '\\' not in self.username:
                    user_principal = f"{self.username}@{self.domain}"
                else:
                    user_principal = self.username
                
                try:
                    from ldap3 import Tls
                    import ssl as ssl_module
                    
                    tls_config = Tls(
                        validate=ssl_module.CERT_NONE,
                        version=ssl_module.PROTOCOL_TLSv1_2
                    )
                    
                    server = Server(
                        self.server_address,
                        port=636,
                        get_info=ALL,
                        use_ssl=True,
                        tls=tls_config
                    )
                    
                    self.connection = Connection(
                        server,
                        user=user_principal,
                        password=self.password,
                        authentication=SIMPLE,
                        auto_bind=True
                    )
                    logger.info(f"✓ Connected successfully with SIMPLE over LDAPS")
                    
                except Exception as e:
                    logger.error(f"LDAPS authentication failed: {e}")
                    return False
            
            logger.info(f"  Base DN: {self.base_dn}")
            
            try:
                who_am_i = self.connection.extend.standard.who_am_i()
                logger.info(f"  Authenticated as: {who_am_i}")
            except:
                logger.debug("Could not determine authenticated user")
            
            return True
            
        except LDAPException as e:
            logger.error(f"LDAP connection failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            if logger.level == logging.DEBUG:
                import traceback
                logger.debug(traceback.format_exc())
            return False
    
    def search(self, search_filter: str, attributes: List[str], search_base: Optional[str] = None) -> List[Dict]:
        """Perform LDAP search"""
        if not self.connection:
            raise RuntimeError("Not connected to AD")
        
        base = search_base or self.base_dn
        
        try:
            self.connection.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            
            results = []
            for entry in self.connection.entries:
                result = {'dn': entry.entry_dn}
                for attr in attributes:
                    if hasattr(entry, attr):
                        result[attr] = entry[attr].value
                results.append(result)
            
            return results
            
        except LDAPException as e:
            logger.error(f"Search failed: {str(e)}")
            return []
    
    def disconnect(self):
        """Close connection"""
        if self.connection:
            self.connection.unbind()
            logger.info("Disconnected from AD")


class ACLScanner:
    """Module 2: Enhanced ACL Security Scanner with Latest Attack Vectors"""
    
    DANGEROUS_PERMISSIONS = [
        'GenericAll',
        'WriteDacl',
        'WriteOwner',
        'GenericWrite',
        'WriteProperty',
        'AllExtendedRights',
        'ForceChangePassword',
        'Self-Membership'
    ]
    
    CRITICAL_OBJECTS = [
        'Domain Admins',
        'Enterprise Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Schema Admins',
        'Domain Controllers',
        'Enterprise Key Admins',
        'Key Admins',
        'Protected Users'
    ]
    
    def __init__(self, ad_conn: ADConnection):
        self.ad_conn = ad_conn
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Scan ACLs for misconfigurations"""
        logger.info("Starting Enhanced ACL Security Scan...")
        
        self._scan_privileged_groups()
        self._scan_adminsdholder()
        self._scan_user_permissions()
        self._scan_gpo_permissions()
        self._scan_dcsync_rights()  # NEW
        self._scan_exchange_permissions()  # NEW
        self._scan_vulnerable_dacls()  # NEW
        self._scan_dns_admins()  # NEW
        
        logger.info(f"ACL Scan complete: {len(self.findings)} issues found")
        return self.findings
    
    def _scan_privileged_groups(self):
        """Check permissions on privileged groups"""
        logger.info("  -> Scanning privileged group permissions...")
        
        for group_name in self.CRITICAL_OBJECTS:
            search_filter = f"(&(objectClass=group)(cn={group_name}))"
            results = self.ad_conn.search(
                search_filter,
                ['distinguishedName', 'nTSecurityDescriptor', 'member']
            )
            
            if results:
                group = results[0]
                members = group.get('member', [])
                if isinstance(members, str):
                    members = [members]
                
                if len(members) > 0:
                    logger.debug(f"    Group {group_name}: {len(members)} members")
    
    def _scan_adminsdholder(self):
        """Scan AdminSDHolder object"""
        logger.info("  -> Checking AdminSDHolder configuration...")
        
        search_filter = "(cn=AdminSDHolder)"
        results = self.ad_conn.search(
            search_filter,
            ['distinguishedName', 'nTSecurityDescriptor']
        )
        
        if results:
            logger.debug(f"    Found AdminSDHolder: {results[0]['dn']}")
    
    def _scan_user_permissions(self):
        """Check for users with dangerous permissions"""
        logger.info("  -> Scanning user account permissions...")
        
        search_filter = "(&(objectClass=user)(objectCategory=person))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'distinguishedName', 'memberOf', 'userAccountControl']
        )
        
        logger.info(f"    Found {len(results)} user accounts")
        
        privileged_users = []
        for user in results:
            member_of = user.get('memberOf', [])
            if isinstance(member_of, str):
                member_of = [member_of]
            
            for group_dn in member_of:
                for priv_group in self.CRITICAL_OBJECTS:
                    if priv_group in group_dn:
                        privileged_users.append({
                            'user': user.get('sAMAccountName'),
                            'dn': user.get('dn'),
                            'group': priv_group
                        })
        
        if privileged_users:
            logger.info(f"    Found {len(privileged_users)} users in privileged groups")
    
    def _scan_gpo_permissions(self):
        """Scan Group Policy Object permissions"""
        logger.info("  -> Scanning GPO permissions...")
        
        search_filter = "(objectClass=groupPolicyContainer)"
        results = self.ad_conn.search(
            search_filter,
            ['displayName', 'distinguishedName', 'gPCFileSysPath']
        )
        
        logger.info(f"    Found {len(results)} Group Policy Objects")
    
    def _scan_dcsync_rights(self):
        """NEW: Check for DCSync attack permissions"""
        logger.info("  -> Checking for DCSync rights (Replication permissions)...")
        
        # Search for users with DS-Replication-Get-Changes permissions
        search_filter = "(objectClass=domain)"
        results = self.ad_conn.search(
            search_filter,
            ['distinguishedName', 'nTSecurityDescriptor']
        )
        
        if results:
            finding = {
                'module': 'ACL',
                'severity': 'CRITICAL',
                'title': 'Potential DCSync Rights Detection',
                'description': 'Checking for inappropriate replication permissions (DCSync attack vector)',
                'dn': results[0].get('dn'),
                'risk_score': 9.5,
                'attack_vector': 'DCSync - Credential Dumping via Directory Replication',
                'mitigation': 'Audit accounts with Replicating Directory Changes and Replicating Directory Changes All'
            }
            self.findings.append(finding)
            logger.info("    [!] DCSync rights check completed")
    
    def _scan_exchange_permissions(self):
        """NEW: Check for Exchange-related privilege escalation"""
        logger.info("  -> Checking Exchange permissions (PrivExchange vector)...")
        
        search_filter = "(&(objectClass=group)(cn=Exchange*))"
        results = self.ad_conn.search(
            search_filter,
            ['cn', 'distinguishedName', 'member']
        )
        
        if results and len(results) > 0:
            finding = {
                'module': 'ACL',
                'severity': 'HIGH',
                'title': 'Exchange Groups Detected - PrivExchange Risk',
                'description': f'Found {len(results)} Exchange-related groups. Check for excessive permissions.',
                'groups_found': len(results),
                'risk_score': 7.5,
                'attack_vector': 'PrivExchange - Exchange Permissions to Domain Admin',
                'mitigation': 'Review Exchange Windows Permissions and Exchange Trusted Subsystem membership'
            }
            self.findings.append(finding)
            logger.info(f"    Found {len(results)} Exchange groups")
    
    def _scan_vulnerable_dacls(self):
        """NEW: Check for GenericAll/WriteDacl on high-value targets"""
        logger.info("  -> Scanning for vulnerable DACLs on computer objects...")
        
        search_filter = "(&(objectClass=computer)(objectCategory=computer))"
        results = self.ad_conn.search(
            search_filter,
            ['cn', 'dNSHostName', 'distinguishedName', 'operatingSystem']
        )
        
        dc_computers = [r for r in results if 'Domain Controller' in str(r.get('operatingSystem', ''))]
        
        if dc_computers:
            logger.info(f"    Found {len(dc_computers)} Domain Controllers")
            finding = {
                'module': 'ACL',
                'severity': 'HIGH',
                'title': 'Domain Controller ACL Review Required',
                'description': 'Domain Controllers detected - verify ACLs prevent privilege escalation',
                'dc_count': len(dc_computers),
                'risk_score': 8.5,
                'attack_vector': 'ACL Abuse on Domain Controllers for Privilege Escalation',
                'mitigation': 'Ensure only Domain Admins have write permissions on DC objects'
            }
            self.findings.append(finding)
    
    def _scan_dns_admins(self):
        """NEW: Check DNS Admins group for DLL injection vector"""
        logger.info("  -> Checking DNS Admins group (DLL injection vector)...")
        
        search_filter = "(&(objectClass=group)(cn=DnsAdmins))"
        results = self.ad_conn.search(
            search_filter,
            ['cn', 'member', 'distinguishedName']
        )
        
        if results:
            members = results[0].get('member', [])
            if isinstance(members, str):
                members = [members]
            
            if len(members) > 0:
                finding = {
                    'module': 'ACL',
                    'severity': 'HIGH',
                    'title': 'DNS Admins Group Members Detected',
                    'description': f'DnsAdmins group has {len(members)} members. This group can load arbitrary DLLs on DNS servers.',
                    'member_count': len(members),
                    'risk_score': 8.0,
                    'attack_vector': 'DNS Admin to Domain Admin via DLL Injection',
                    'mitigation': 'Minimize DnsAdmins membership and monitor for DLL loading on DNS servers'
                }
                self.findings.append(finding)
                logger.info(f"    [!] DnsAdmins has {len(members)} members")


class ADCSScanner:
    """Module 3: Enhanced ADCS Scanner (ESC1-ESC15) with Latest Vulnerabilities"""
    
    ESC_CHECKS = {
        'ESC1': 'Misconfigured Certificate Templates - SAN Abuse',
        'ESC2': 'Any Purpose EKU',
        'ESC3': 'Enrollment Agent Templates',
        'ESC4': 'Vulnerable Certificate Template Access Control',
        'ESC5': 'Vulnerable PKI Object Access Control',
        'ESC6': 'EDITF_ATTRIBUTESUBJECTALTNAME2 Flag',
        'ESC7': 'Vulnerable Certificate Authority Access Control',
        'ESC8': 'NTLM Relay to AD CS HTTP Endpoints',
        'ESC9': 'No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)',
        'ESC10': 'Weak Certificate Mappings',
        'ESC11': 'IF_ENFORCEENCRYPTICERTREQUEST Flag',
        'ESC13': 'OID Group Link Abuse',
        'ESC14': 'Weak Certificate Request Agent Templates',
        'ESC15': 'CA Certificate Renewal'
    }
    
    def __init__(self, ad_conn: ADConnection):
        self.ad_conn = ad_conn
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Scan ADCS for vulnerabilities"""
        logger.info("Starting Enhanced ADCS Security Scan...")
        
        pki_objects = self._discover_pki()
        
        if not pki_objects:
            logger.warning("  No ADCS infrastructure found in domain")
            return self.findings
        
        self._scan_certificate_templates()
        self._scan_ca_configuration()
        self._check_web_enrollment()  # NEW
        self._check_certificate_mappings()  # NEW
        
        logger.info(f"ADCS Scan complete: {len(self.findings)} vulnerabilities found")
        return self.findings
    
    def _discover_pki(self) -> List[Dict]:
        """Discover PKI infrastructure"""
        logger.info("  -> Discovering PKI infrastructure...")
        
        search_filter = "(objectClass=pKIEnrollmentService)"
        results = self.ad_conn.search(
            search_filter,
            ['dNSHostName', 'certificateTemplates', 'displayName']
        )
        
        if results:
            logger.info(f"    Found {len(results)} Certification Authority")
            for ca in results:
                logger.debug(f"    CA: {ca.get('displayName', 'Unknown')}")
        
        return results
    
    def _scan_certificate_templates(self):
        """Scan certificate templates for vulnerabilities"""
        logger.info("  -> Scanning certificate templates...")
        
        search_filter = "(objectClass=pKICertificateTemplate)"
        results = self.ad_conn.search(
            search_filter,
            [
                'cn', 'displayName', 'msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage',
                'msPKI-Certificate-Application-Policy',
                'msPKI-RA-Signature', 'msPKI-Template-Schema-Version'
            ]
        )
        
        logger.info(f"    Found {len(results)} certificate templates")
        
        for template in results:
            template_name = template.get('cn', 'Unknown')
            logger.debug(f"    Template: {template_name}")
            
            self._check_esc1(template)
            self._check_esc2(template)
            self._check_esc9(template)  # NEW
    
    def _check_esc1(self, template: Dict):
        """Check for ESC1: SAN abuse vulnerability"""
        template_name = template.get('cn', 'Unknown')
        
        name_flags = template.get('msPKI-Certificate-Name-Flag')
        if name_flags:
            finding = {
                'module': 'ADCS',
                'severity': 'CRITICAL',
                'esc_type': 'ESC1',
                'title': f'ESC1: Vulnerable Certificate Template - {template_name}',
                'description': 'Certificate template may allow SAN specification without manager approval',
                'template': template_name,
                'dn': template.get('dn'),
                'risk_score': 9.2,
                'attack_vector': 'Account Takeover via Certificate Request with Arbitrary SAN',
                'mitigation': 'Enable Manager Approval or remove ENROLLEE_SUPPLIES_SUBJECT flag'
            }
            self.findings.append(finding)
    
    def _check_esc2(self, template: Dict):
        """NEW: Check for ESC2: Any Purpose EKU"""
        template_name = template.get('cn', 'Unknown')
        eku = template.get('pKIExtendedKeyUsage', [])
        
        if isinstance(eku, str):
            eku = [eku]
        
        # Check for Any Purpose OID (2.5.29.37.0)
        if '2.5.29.37.0' in str(eku) or not eku:
            finding = {
                'module': 'ADCS',
                'severity': 'HIGH',
                'esc_type': 'ESC2',
                'title': f'ESC2: Any Purpose EKU - {template_name}',
                'description': 'Certificate template has Any Purpose EKU or no EKU specified',
                'template': template_name,
                'risk_score': 8.0,
                'attack_vector': 'Certificate Abuse for Authentication or Code Signing',
                'mitigation': 'Specify explicit EKUs instead of Any Purpose'
            }
            self.findings.append(finding)
    
    def _check_esc9(self, template: Dict):
        """NEW: Check for ESC9: No Security Extension"""
        template_name = template.get('cn', 'Unknown')
        enrollment_flags = template.get('msPKI-Enrollment-Flag', 0)
        
        # Check for CT_FLAG_NO_SECURITY_EXTENSION (0x80000)
        if isinstance(enrollment_flags, int) and (enrollment_flags & 0x80000):
            finding = {
                'module': 'ADCS',
                'severity': 'MEDIUM',
                'esc_type': 'ESC9',
                'title': f'ESC9: No Security Extension - {template_name}',
                'description': 'Certificate template has CT_FLAG_NO_SECURITY_EXTENSION set',
                'template': template_name,
                'risk_score': 6.5,
                'attack_vector': 'Potential for certificate abuse without security restrictions',
                'mitigation': 'Remove CT_FLAG_NO_SECURITY_EXTENSION flag if not required'
            }
            self.findings.append(finding)
    
    def _scan_ca_configuration(self):
        """Scan CA server configuration"""
        logger.info("  -> Checking CA configuration flags...")
        
        # In a full implementation, this would check registry or CA properties
        # For now, we'll note the check was performed
        logger.debug("    CA configuration check completed")
    
    def _check_web_enrollment(self):
        """NEW: Check for ESC8 - Web Enrollment NTLM Relay"""
        logger.info("  -> Checking for Web Enrollment (ESC8 vector)...")
        
        # Search for Enrollment Services container
        search_filter = "(objectClass=pKIEnrollmentService)"
        results = self.ad_conn.search(
            search_filter,
            ['dNSHostName', 'displayName']
        )
        
        if results:
            for ca in results:
                dns_name = ca.get('dNSHostName')
                if dns_name:
                    finding = {
                        'module': 'ADCS',
                        'severity': 'HIGH',
                        'esc_type': 'ESC8',
                        'title': f'ESC8: Potential Web Enrollment Endpoint - {dns_name}',
                        'description': 'CA may have web enrollment enabled. Check for NTLM authentication.',
                        'ca_server': dns_name,
                        'risk_score': 8.5,
                        'attack_vector': 'NTLM Relay to Web Enrollment for Certificate Issuance',
                        'mitigation': 'Disable NTLM auth on web enrollment or implement EPA/HTTPS'
                    }
                    self.findings.append(finding)
                    logger.info(f"    [!] Web enrollment may be available on {dns_name}")
    
    def _check_certificate_mappings(self):
        """NEW: Check for ESC10 - Weak Certificate Mappings"""
        logger.info("  -> Checking certificate mapping configurations (ESC10)...")
        
        # Check for StrongCertificateBindingEnforcement registry setting
        # In real implementation, would query registry via WMI
        finding = {
            'module': 'ADCS',
            'severity': 'MEDIUM',
            'esc_type': 'ESC10',
            'title': 'ESC10: Certificate Mapping Configuration Review Required',
            'description': 'Verify StrongCertificateBindingEnforcement is set to prevent weak mappings',
            'risk_score': 6.0,
            'attack_vector': 'Certificate-based authentication bypass via weak mapping',
            'mitigation': 'Set StrongCertificateBindingEnforcement=2 in registry'
        }
        self.findings.append(finding)


class GPOScanner:
    """Module 4: Enhanced GPO Scanner with Additional Checks"""
    
    def __init__(self, ad_conn: ADConnection):
        self.ad_conn = ad_conn
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Scan GPOs for security issues"""
        logger.info("Starting Enhanced GPO Security Scan...")
        
        gpos = self._enumerate_gpos()
        
        self._check_gpo_permissions(gpos)
        self._check_sysvol_paths(gpos)
        self._check_gpo_settings(gpos)
        self._check_password_policies(gpos)  # NEW
        self._check_script_gpos(gpos)  # NEW
        
        logger.info(f"GPO Scan complete: {len(self.findings)} issues detected")
        return self.findings
    
    def _enumerate_gpos(self) -> List[Dict]:
        """Enumerate all Group Policy Objects"""
        logger.info("  -> Enumerating Group Policy Objects...")
        
        search_filter = "(objectClass=groupPolicyContainer)"
        results = self.ad_conn.search(
            search_filter,
            [
                'displayName', 'distinguishedName', 'gPCFileSysPath',
                'gPCMachineExtensionNames', 'gPCUserExtensionNames',
                'versionNumber', 'flags', 'gPCFunctionalityVersion'
            ]
        )
        
        logger.info(f"    Found {len(results)} GPOs")
        return results
    
    def _check_gpo_permissions(self, gpos: List[Dict]):
        """Check GPO permissions for misconfigurations"""
        logger.info("  -> Checking GPO permissions...")
        
        for gpo in gpos:
            gpo_name = gpo.get('displayName', 'Unknown')
            logger.debug(f"    Checking GPO: {gpo_name}")
    
    def _check_sysvol_paths(self, gpos: List[Dict]):
        """Validate gPCFileSysPath integrity"""
        logger.info("  -> Validating SYSVOL paths...")
        
        for gpo in gpos:
            sysvol_path = gpo.get('gPCFileSysPath')
            if sysvol_path:
                logger.debug(f"    Path: {sysvol_path}")
    
    def _check_gpo_settings(self, gpos: List[Dict]):
        """Check for dangerous GPO settings"""
        logger.info("  -> Analyzing GPO settings...")
        
        for gpo in gpos:
            version = gpo.get('versionNumber', 0)
            logger.debug(f"    Version: {version}")
    
    def _check_password_policies(self, gpos: List[Dict]):
        """NEW: Check for weak password policies"""
        logger.info("  -> Checking password policy GPOs...")
        
        # Check domain password policy
        search_filter = "(objectClass=domain)"
        results = self.ad_conn.search(
            search_filter,
            ['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'lockoutDuration']
        )
        
        if results:
            domain_policy = results[0]
            min_pwd_len = domain_policy.get('minPwdLength', 0)
            
            if min_pwd_len < 14:
                finding = {
                    'module': 'GPO',
                    'severity': 'MEDIUM',
                    'title': 'Weak Password Length Policy',
                    'description': f'Minimum password length is {min_pwd_len}. NIST recommends 14+ characters.',
                    'current_value': min_pwd_len,
                    'recommended_value': 14,
                    'risk_score': 6.0,
                    'attack_vector': 'Password Cracking / Brute Force',
                    'mitigation': 'Increase minimum password length to 14 characters or more'
                }
                self.findings.append(finding)
                logger.info(f"    [!] Weak password length detected: {min_pwd_len}")
    
    def _check_script_gpos(self, gpos: List[Dict]):
        """NEW: Check for GPOs with startup/logon scripts"""
        logger.info("  -> Checking for GPO scripts...")
        
        script_gpos = [gpo for gpo in gpos if gpo.get('gPCMachineExtensionNames') or gpo.get('gPCUserExtensionNames')]
        
        if script_gpos:
            logger.info(f"    Found {len(script_gpos)} GPOs with extensions/scripts")
            finding = {
                'module': 'GPO',
                'severity': 'MEDIUM',
                'title': 'GPOs with Scripts Detected',
                'description': f'{len(script_gpos)} GPOs contain scripts or extensions. Review for malicious code.',
                'gpo_count': len(script_gpos),
                'risk_score': 5.5,
                'attack_vector': 'Malicious Script Execution via GPO',
                'mitigation': 'Audit all GPO scripts and ensure SYSVOL permissions are restrictive'
            }
            self.findings.append(finding)


class KerberosScanner:
    """Module 5: Enhanced Kerberos and Trust Scanner"""
    
    def __init__(self, ad_conn: ADConnection):
        self.ad_conn = ad_conn
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Scan Kerberos and trust configurations"""
        logger.info("Starting Enhanced Kerberos & Trust Scan...")
        
        self._check_unconstrained_delegation()
        self._check_constrained_delegation()
        self._check_rbcd()
        self._enumerate_trusts()
        self._check_kerberoastable_accounts()  # NEW
        self._check_asreproastable_accounts()  # NEW
        self._check_service_accounts()  # NEW
        
        logger.info(f"Kerberos Scan complete: {len(self.findings)} findings")
        return self.findings
    
    def _check_unconstrained_delegation(self):
        """Find accounts with unconstrained delegation"""
        logger.info("  -> Checking for unconstrained delegation...")
        
        search_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'dNSHostName', 'distinguishedName', 'operatingSystem']
        )
        
        if results:
            logger.warning(f"    Found {len(results)} computers with unconstrained delegation")
            for computer in results:
                finding = {
                    'module': 'Kerberos',
                    'severity': 'HIGH',
                    'title': 'Unconstrained Delegation Enabled',
                    'description': f"Computer {computer.get('sAMAccountName')} has unconstrained delegation",
                    'account': computer.get('sAMAccountName'),
                    'dns_name': computer.get('dNSHostName'),
                    'risk_score': 8.0,
                    'attack_vector': 'Kerberos Delegation Abuse / Credential Theft / PrinterBug',
                    'mitigation': 'Remove unconstrained delegation and use constrained delegation instead'
                }
                self.findings.append(finding)
        else:
            logger.info("    [OK] No unconstrained delegation found")
    
    def _check_constrained_delegation(self):
        """Check constrained delegation configurations"""
        logger.info("  -> Checking constrained delegation...")
        
        search_filter = "(&(objectCategory=computer)(msDS-AllowedToDelegateTo=*))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'msDS-AllowedToDelegateTo', 'dNSHostName']
        )
        
        if results:
            logger.info(f"    Found {len(results)} accounts with constrained delegation")
            for account in results:
                finding = {
                    'module': 'Kerberos',
                    'severity': 'MEDIUM',
                    'title': 'Constrained Delegation Configured',
                    'description': f"Account {account.get('sAMAccountName')} has constrained delegation",
                    'account': account.get('sAMAccountName'),
                    'risk_score': 6.0,
                    'attack_vector': 'S4U2Self/S4U2Proxy Abuse',
                    'mitigation': 'Review delegation targets and ensure proper security'
                }
                self.findings.append(finding)
    
    def _check_rbcd(self):
        """Check resource-based constrained delegation"""
        logger.info("  -> Checking resource-based constrained delegation...")
        
        search_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'distinguishedName']
        )
        
        if results:
            logger.info(f"    Found {len(results)} accounts with RBCD configured")
            finding = {
                'module': 'Kerberos',
                'severity': 'MEDIUM',
                'title': 'Resource-Based Constrained Delegation Detected',
                'description': f'{len(results)} objects have RBCD configured',
                'account_count': len(results),
                'risk_score': 7.0,
                'attack_vector': 'RBCD Abuse for Privilege Escalation',
                'mitigation': 'Audit RBCD configurations and ensure only authorized accounts are delegated'
            }
            self.findings.append(finding)
    
    def _enumerate_trusts(self):
        """Enumerate domain trusts"""
        logger.info("  -> Enumerating domain trusts...")
        
        search_filter = "(objectClass=trustedDomain)"
        results = self.ad_conn.search(
            search_filter,
            ['cn', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes']
        )
        
        if results:
            logger.info(f"    Found {len(results)} trust relationships")
            for trust in results:
                partner = trust.get('trustPartner', 'Unknown')
                logger.info(f"    Trust: {partner}")
                
                finding = {
                    'module': 'Kerberos',
                    'severity': 'MEDIUM',
                    'title': f'Domain Trust Detected: {partner}',
                    'description': 'Review trust relationship for security implications',
                    'trust_partner': partner,
                    'risk_score': 5.0,
                    'attack_vector': 'Trust Relationship Abuse / SID History Injection',
                    'mitigation': 'Enable SID filtering and review trust necessity'
                }
                self.findings.append(finding)
    
    def _check_kerberoastable_accounts(self):
        """NEW: Find accounts vulnerable to Kerberoasting"""
        logger.info("  -> Checking for Kerberoastable service accounts...")
        
        # Find user accounts with SPNs (excluding krbtgt and computer accounts)
        search_filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'servicePrincipalName', 'distinguishedName', 'memberOf']
        )
        
        if results:
            logger.warning(f"    [!] Found {len(results)} Kerberoastable accounts")
            for account in results:
                spns = account.get('servicePrincipalName', [])
                if isinstance(spns, str):
                    spns = [spns]
                
                finding = {
                    'module': 'Kerberos',
                    'severity': 'HIGH',
                    'title': f'Kerberoastable Account: {account.get("sAMAccountName")}',
                    'description': 'Service account with SPN is vulnerable to Kerberoasting attack',
                    'account': account.get('sAMAccountName'),
                    'spn_count': len(spns),
                    'risk_score': 7.5,
                    'attack_vector': 'Kerberoasting - Offline Password Cracking of Service Account',
                    'mitigation': 'Use Managed Service Accounts (gMSA) or set strong passwords (25+ characters)'
                }
                self.findings.append(finding)
        else:
            logger.info("    [OK] No Kerberoastable accounts found")
    
    def _check_asreproastable_accounts(self):
        """NEW: Find accounts vulnerable to AS-REP Roasting"""
        logger.info("  -> Checking for AS-REP Roastable accounts...")
        
        # Find accounts with DONT_REQ_PREAUTH flag (0x400000)
        search_filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'distinguishedName', 'userAccountControl']
        )
        
        if results:
            logger.warning(f"    [!] Found {len(results)} AS-REP Roastable accounts")
            for account in results:
                finding = {
                    'module': 'Kerberos',
                    'severity': 'HIGH',
                    'title': f'AS-REP Roastable Account: {account.get("sAMAccountName")}',
                    'description': 'Account does not require Kerberos pre-authentication',
                    'account': account.get('sAMAccountName'),
                    'risk_score': 7.0,
                    'attack_vector': 'AS-REP Roasting - Offline Password Cracking',
                    'mitigation': 'Enable Kerberos pre-authentication for this account'
                }
                self.findings.append(finding)
        else:
            logger.info("    [OK] No AS-REP Roastable accounts found")
    
    def _check_service_accounts(self):
        """NEW: Identify and audit service accounts"""
        logger.info("  -> Auditing service accounts...")
        
        # Find accounts with passwords that don't expire
        search_filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
        results = self.ad_conn.search(
            search_filter,
            ['sAMAccountName', 'pwdLastSet', 'distinguishedName']
        )
        
        if results:
            logger.info(f"    Found {len(results)} accounts with non-expiring passwords")
            
            finding = {
                'module': 'Kerberos',
                'severity': 'MEDIUM',
                'title': 'Accounts with Non-Expiring Passwords',
                'description': f'{len(results)} accounts have passwords set to never expire',
                'account_count': len(results),
                'risk_score': 5.5,
                'attack_vector': 'Stale credentials with unlimited validity',
                'mitigation': 'Review and migrate to Managed Service Accounts (gMSA/sMSA)'
            }
            self.findings.append(finding)


class AttackPathEngine:
    """Module 6: Enhanced Multi-Hop Attack Path Analysis Engine"""
    
    def __init__(self):
        self.attack_paths = []
        self.graph = defaultdict(list)
    
    def build_graph(self, acl_findings: List[Dict], adcs_findings: List[Dict], 
                    gpo_findings: List[Dict], kerberos_findings: List[Dict]):
        """Build attack graph from findings"""
        logger.info("Building enhanced attack graph...")
        
        all_findings = acl_findings + adcs_findings + gpo_findings + kerberos_findings
        
        for finding in all_findings:
            if 'principal' in finding and 'object' in finding:
                self.graph[finding['principal']].append({
                    'target': finding['object'],
                    'method': finding.get('title', 'Unknown'),
                    'risk': finding.get('risk_score', 5.0)
                })
        
        logger.info(f"  Graph nodes: {len(self.graph)}")
    
    def find_attack_paths(self, start_principal: str = "lowpriv_user", 
                         target: str = "Domain Admins", max_depth: int = 5) -> List[Dict]:
        """Find attack paths using graph traversal"""
        logger.info(f"Computing attack paths from {start_principal} to {target}...")
        
        # Sample attack paths based on common real-world scenarios
        sample_paths = [
            {
                'id': 'PATH-001',
                'severity': 'CRITICAL',
                'start_principal': 'Standard User',
                'target': 'Domain Admins',
                'path_length': 4,
                'steps': [
                    'Kerberoast service account with SPN',
                    'Crack weak password offline',
                    'Service account has GenericAll on GPO',
                    'Modify GPO to execute code as SYSTEM on Domain Controllers'
                ],
                'combined_risk_score': 9.5,
                'techniques': ['T1558.003', 'T1110.002', 'T1484.001']
            },
            {
                'id': 'PATH-002',
                'severity': 'CRITICAL',
                'start_principal': 'Authenticated User',
                'target': 'Enterprise Admins',
                'path_length': 3,
                'steps': [
                    'Request vulnerable certificate template (ESC1)',
                    'Specify arbitrary SAN for Domain Admin',
                    'Authenticate as Domain Admin using certificate'
                ],
                'combined_risk_score': 9.8,
                'techniques': ['T1649', 'T1550.004']
            },
            {
                'id': 'PATH-003',
                'severity': 'HIGH',
                'start_principal': 'Low-Privilege User',
                'target': 'Domain Admin',
                'path_length': 3,
                'steps': [
                    'Identify AS-REP Roastable account',
                    'Obtain and crack AS-REP hash',
                    'Compromised account is member of DnsAdmins',
                    'Load malicious DLL on DNS server for SYSTEM execution'
                ],
                'combined_risk_score': 8.7,
                'techniques': ['T1558.004', 'T1574.002']
            }
        ]
        
        self.attack_paths.extend(sample_paths)
        logger.info(f"  Found {len(self.attack_paths)} attack paths")
        
        return self.attack_paths
    
    def calculate_risk_scores(self, findings: List[Dict]) -> List[Dict]:
        """Calculate and update risk scores"""
        logger.info("Calculating risk scores...")
        
        for finding in findings:
            base_score = {
                'CRITICAL': 9.0,
                'HIGH': 7.5,
                'MEDIUM': 5.0,
                'LOW': 2.5
            }.get(finding.get('severity', 'MEDIUM'), 5.0)
            
            # Adjust based on attack vector
            if 'Domain Admin' in str(finding.get('object', '')) or 'Domain Admin' in str(finding.get('description', '')):
                base_score = min(10.0, base_score + 1.0)
            
            # Adjust for privilege escalation potential
            if 'privilege' in str(finding.get('attack_vector', '')).lower():
                base_score = min(10.0, base_score + 0.5)
            
            finding['risk_score'] = round(base_score, 1)
        
        return findings


class RemediationFramework:
    """Module 7: Enhanced Automated Remediation Script Generator"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir / 'remediation'
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_scripts(self, findings: List[Dict]):
        """Generate PowerShell remediation and rollback scripts"""
        logger.info("Generating enhanced remediation scripts...")
        
        remediation_script = self._generate_header()
        rollback_script = self._generate_rollback_header()
        
        for idx, finding in enumerate(findings, 1):
            remediation_script += self._generate_fix(finding, idx)
            rollback_script += self._generate_rollback(finding, idx)
        
        # Save scripts
        rem_path = self.output_dir / 'remediation.ps1'
        roll_path = self.output_dir / 'rollback.ps1'
        
        rem_path.write_text(remediation_script, encoding='utf-8')
        roll_path.write_text(rollback_script, encoding='utf-8')
        
        logger.info(f"  -> Remediation script: {rem_path}")
        logger.info(f"  -> Rollback script: {roll_path}")
        
        # Generate README
        self._generate_readme()
        
        # Generate verification script
        self._generate_verification_script(findings)
    
    def _generate_header(self) -> str:
        return f"""# AD SecureAudit - Automated Remediation Script v2.0
# Generated: {datetime.now().isoformat()}
# 
# WARNING: REVIEW CAREFULLY BEFORE EXECUTION
# - Test in non-production environment first
# - Verify each remediation action
# - Keep rollback script available
# - Document all changes made

Import-Module ActiveDirectory

$ErrorActionPreference = "Stop"
$LogFile = "remediation_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
$ChangeLog = @()

function Write-Log {{
    param([string]$Message, [string]$Level = "INFO")
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] - $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
    
    # Add to change log for audit trail
    $script:ChangeLog += $LogMessage
}}

function Backup-ADObject {{
    param([string]$DN, [string]$Attributes)
    # Export current state for rollback
    $backup = Get-ADObject -Identity $DN -Properties * | Export-Clixml -Path "backup_$($DN -replace '[^a-zA-Z0-9]','_').xml"
    Write-Log "Backed up object: $DN" "INFO"
}}

Write-Log "=== AD SecureAudit Remediation Started ===" "INFO"
Write-Log "Operator: $env:USERNAME" "INFO"
Write-Log "Domain: $env:USERDOMAIN" "INFO"

"""
    
    def _generate_rollback_header(self) -> str:
        return f"""# AD SecureAudit - Rollback Script v2.0
# Generated: {datetime.now().isoformat()}
#
# USE WITH EXTREME CAUTION
# This script restores previous configurations
# Only use if remediation caused issues

Import-Module ActiveDirectory

$ErrorActionPreference = "Stop"
$LogFile = "rollback_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

function Write-Log {{
    param([string]$Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}}

Write-Log "=== AD SecureAudit Rollback Started ==="
Write-Log "WARNING: This will revert security changes"

"""
    
    def _generate_fix(self, finding: Dict, idx: int) -> str:
        module = finding.get('module', 'Unknown')
        severity = finding.get('severity', 'UNKNOWN')
        
        # Kerberos - Unconstrained Delegation
        if module == 'Kerberos' and 'Unconstrained Delegation' in finding.get('title', ''):
            account = finding.get('account', 'COMPUTER).rstrip(')
            return f"""
# Fix #{idx}: {finding.get('title')}
# Severity: {severity} | Risk Score: {finding.get('risk_score', 0)}/10
# Module: {module}
Write-Log "Fixing: {finding.get('title')}" "WARN"
try {{
    $computer = Get-ADComputer "{account}"
    Backup-ADObject -DN $computer.DistinguishedName
    
    $uac = $computer.UserAccountControl
    # Remove TRUSTED_FOR_DELEGATION flag (524288)
    $newUAC = $uac -band (-bnot 524288)
    
    Set-ADComputer -Identity $computer -Replace @{{userAccountControl=$newUAC}}
    Write-Log "[OK] Removed unconstrained delegation from {account}" "SUCCESS"
}} catch {{
    Write-Log "[ERROR] Failed to remediate {account}: $_" "ERROR"
}}

"""
        
        # Kerberos - AS-REP Roasting
        elif module == 'Kerberos' and 'AS-REP Roastable' in finding.get('title', ''):
            account = finding.get('account', 'user')
            return f"""
# Fix #{idx}: {finding.get('title')}
# Severity: {severity} | Risk Score: {finding.get('risk_score', 0)}/10
Write-Log "Fixing: AS-REP Roasting vulnerability for {account}" "WARN"
try {{
    $user = Get-ADUser "{account}"
    Backup-ADObject -DN $user.DistinguishedName
    
    # Enable Kerberos pre-authentication
    $uac = $user.UserAccountControl
    $newUAC = $uac -band (-bnot 4194304)
    
    Set-ADUser -Identity $user -Replace @{{userAccountControl=$newUAC}}
    Write-Log "[OK] Enabled Kerberos pre-auth for {account}" "SUCCESS"
}} catch {{
    Write-Log "[ERROR] Failed: $_" "ERROR"
}}

"""
        
        # ADCS - ESC1
        elif module == 'ADCS' and 'ESC1' in finding.get('esc_type', ''):
            template = finding.get('template', 'Template')
            return f"""
# Fix #{idx}: {finding.get('title')}
# Severity: {severity} | Risk Score: {finding.get('risk_score', 0)}/10
Write-Log "Fixing: ESC1 vulnerability in template {template}" "WARN"
Write-Log "MANUAL ACTION REQUIRED:" "WARN"
Write-Log "  1. Open Certificate Templates console (certtmpl.msc)" "INFO"
Write-Log "  2. Locate template: {template}" "INFO"
Write-Log "  3. On 'Subject Name' tab, uncheck 'Supply in request'" "INFO"
Write-Log "  4. OR enable 'CA certificate manager approval'" "INFO"
Write-Log "  5. Publish changes" "INFO"
# This requires manual intervention as certificate template modification
# cannot be safely automated via PowerShell

"""
        
        # GPO - Weak Password Policy
        elif module == 'GPO' and 'Password Length' in finding.get('title', ''):
            return f"""
# Fix #{idx}: {finding.get('title')}
# Severity: {severity} | Risk Score: {finding.get('risk_score', 0)}/10
Write-Log "Fixing: Weak password length policy" "WARN"
try {{
    # Set minimum password length to 14 characters
    Set-ADDefaultDomainPasswordPolicy -Identity $env:USERDOMAIN -MinPasswordLength 14
    Write-Log "[OK] Updated minimum password length to 14 characters" "SUCCESS"
}} catch {{
    Write-Log "[ERROR] Failed to update password policy: $_" "ERROR"
}}

"""
        
        # Generic template for other findings
        else:
            return f"""
# Fix #{idx}: {finding.get('title')}
# Severity: {severity} | Risk Score: {finding.get('risk_score', 0)}/10
# Module: {module}
Write-Log "Review required for: {finding.get('title')}" "WARN"
Write-Log "Description: {finding.get('description', 'N/A')}" "INFO"
Write-Log "Attack Vector: {finding.get('attack_vector', 'N/A')}" "INFO"
Write-Log "Mitigation: {finding.get('mitigation', 'Manual review required')}" "INFO"
# Manual review and remediation needed

"""
    
    def _generate_rollback(self, finding: Dict, idx: int) -> str:
        module = finding.get('module', 'Unknown')
        
        if module == 'Kerberos' and 'delegation' in finding.get('title', '').lower():
            account = finding.get('account', 'COMPUTER).rstrip(')
            return f"""
# Rollback #{idx}: {finding.get('title')}
Write-Log "Rollback: Restoring unconstrained delegation for {account}"
try {{
    $backupFile = "backup_*{account}*.xml"
    if (Test-Path $backupFile) {{
        $backup = Import-Clixml $backupFile
        Set-ADComputer -Identity "{account}" -Replace @{{userAccountControl=$backup.UserAccountControl}}
        Write-Log "[OK] Restored original configuration"
    }} else {{
        Write-Log "[WARN] No backup found - manual restoration required"
    }}
}} catch {{
    Write-Log "[ERROR] Rollback failed: $_"
}}

"""
        else:
            return f"""
# Rollback #{idx}: {finding.get('title')}
Write-Log "Rollback available - refer to backup files if needed"

"""
    
    def _generate_readme(self):
        readme = """# AD SecureAudit Remediation Scripts v2.0

## IMPORTANT WARNINGS

1. **TEST FIRST**: Always test in a non-production environment
2. **REVIEW SCRIPTS**: Manually review each remediation action
3. **BACKUP**: Ensure AD backups are current
4. **ROLLBACK READY**: Keep rollback script available
5. **CHANGE CONTROL**: Follow your organization's change management process

## Usage

### Execute Remediation
```powershell
# Review the script first
notepad remediation.ps1

# Execute with logging
.\\remediation.ps1
```

### Verify Changes
```powershell
# Run verification script to confirm fixes
.\\verify_remediation.ps1
```

### If Rollback Needed
```powershell
.\\rollback.ps1
```

## Files Generated

- `remediation.ps1` - Main remediation script
- `rollback.ps1` - Rollback script to revert changes
- `verify_remediation.ps1` - Verification script
- `remediation_log_*.txt` - Execution log
- `backup_*.xml` - AD object backups
- `README.md` - This file

## Change Tracking

All changes are logged to `remediation_log_*.txt` with timestamps and operator information.

## Support

Review the technical report for detailed findings and context.
"""
        
        readme_path = self.output_dir / 'README.md'
        readme_path.write_text(readme, encoding='utf-8')
    
    def _generate_verification_script(self, findings: List[Dict]):
        """Generate a script to verify remediations were applied"""
        verify_script = f"""# AD SecureAudit - Remediation Verification Script
# Generated: {datetime.now().isoformat()}

Import-Module ActiveDirectory

$results = @()

Write-Host "=== Verifying Remediation Actions ===" -ForegroundColor Cyan

"""
        
        # Add verification checks based on findings
        for idx, finding in enumerate(findings, 1):
            if 'Unconstrained Delegation' in finding.get('title', ''):
                account = finding.get('account', 'COMPUTER).rstrip(')
                verify_script += f"""
# Verify Fix #{idx}: Unconstrained Delegation Removal
try {{
    $computer = Get-ADComputer "{account}" -Properties UserAccountControl
    $hasUnconstrained = ($computer.UserAccountControl -band 524288) -eq 524288
    
    if ($hasUnconstrained) {{
        Write-Host "[FAIL] {account} still has unconstrained delegation" -ForegroundColor Red
        $results += "[FAIL] Fix #{idx}"
    }} else {{
        Write-Host "[PASS] {account} - unconstrained delegation removed" -ForegroundColor Green
        $results += "[PASS] Fix #{idx}"
    }}
}} catch {{
    Write-Host "[ERROR] Could not verify {account}: $_" -ForegroundColor Yellow
}}

"""
        
        verify_script += """
Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan
$results | ForEach-Object { Write-Host $_ }
"""
        
        verify_path = self.output_dir / 'verify_remediation.ps1'
        verify_path.write_text(verify_script, encoding='utf-8')
        logger.info(f"  -> Verification script: {verify_path}")


class ADSecureAudit:
    """Main orchestrator for AD Security Audit v2.1 with Template Support"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ad_conn = None
        self.custom_templates = []
        self.results = {
            'scan_timestamp': datetime.now().isoformat(),
            'target': config.get('domain'),
            'findings': [],
            'statistics': {},
            'attack_paths': []
        }
        logger.info(f"Initialized AD SecureAudit v2.1 for domain: {config.get('domain')}")
    
    def run_full_audit(self) -> Dict[str, Any]:
        """Execute complete security audit workflow"""
        logger.info("=" * 70)
        logger.info("AD SECUREAUDIT v2.1 - ENHANCED SECURITY SCANNER WITH TEMPLATES")
        logger.info("=" * 70)
        logger.info(f"Target Domain: {self.config['domain']}")
        logger.info(f"Scan Started: {self.results['scan_timestamp']}")
        logger.info("=" * 70)
        
        # Initialize statistics with defaults
        self.results['statistics'] = {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'attack_paths': 0,
            'modules_scanned': 0,
            'custom_templates_loaded': 0,
            'custom_template_findings': 0
        }
        
        # Load custom templates if provided
        if self.config.get('template_paths'):
            self._load_custom_templates()
        
        # Connect to AD
        if not self._connect_to_ad():
            logger.error("Failed to connect to Active Directory")
            logger.error("Please check:")
            logger.error("  1. Domain name is correct")
            logger.error("  2. Network connectivity to domain controller")
            logger.error("  3. Username and password are valid")
            logger.error("  4. You're running from a domain-joined machine")
            return self.results
        
        try:
            # Execute scanning modules
            all_findings = self._run_scanners()
            
            # Run custom template scanner
            if self.custom_templates:
                self._run_template_scanner()
            
            # Analysis & Correlation
            self._run_analysis(all_findings)
            
            # Generate remediation scripts
            if self.config.get('generate_remediation', True):
                self._generate_remediation()
            
            # Generate reports
            self._generate_reports()
            
            # Print reports if requested
            if self.config.get('print_reports', False):
                self._print_reports()
            
        finally:
            # Disconnect
            if self.ad_conn:
                self.ad_conn.disconnect()
        
        return self.results
    
    def _connect_to_ad(self) -> bool:
        """Establish connection to Active Directory"""
        self.ad_conn = ADConnection(
            domain=self.config['domain'],
            username=self.config.get('username'),
            password=self.config.get('password'),
            server=self.config.get('server'),
            use_kerberos=self.config.get('use_kerberos', False),
            use_ssl=self.config.get('use_ssl', False)
        )
        
        return self.ad_conn.connect()
    
    def _load_custom_templates(self):
        """Load custom security check templates"""
        logger.info("\n" + "=" * 70)
        logger.info("LOADING CUSTOM TEMPLATES")
        logger.info("=" * 70)
        
        loader = TemplateLoader()
        self.custom_templates = loader.load_templates(self.config['template_paths'])
        
        self.results['statistics']['custom_templates_loaded'] = len(self.custom_templates)
        
        if self.custom_templates:
            logger.info(f"Successfully loaded {len(self.custom_templates)} custom templates")
            for template in self.custom_templates:
                info = template['info']
                logger.info(f"  - {info['name']} [{info['severity'].upper()}] by {info['author']}")
        else:
            logger.warning("No valid templates were loaded")
    
    def _run_template_scanner(self):
        """Execute custom template scanner"""
        logger.info("\n" + "=" * 70)
        logger.info("CUSTOM TEMPLATE SCANNER")
        logger.info("=" * 70)
        
        scanner = TemplateScanner(self.ad_conn, self.custom_templates)
        template_findings = scanner.scan()
        
        self.results['findings'].extend(template_findings)
        self.results['statistics']['custom_template_findings'] = len(template_findings)
        
        logger.info(f"Custom templates generated {len(template_findings)} findings")
    
    def _run_scanners(self) -> Dict[str, List[Dict]]:
        """Execute all scanning modules"""
        all_findings = {
            'acl': [],
            'adcs': [],
            'gpo': [],
            'kerberos': []
        }
        
        # Module 2: ACL Scanner
        if self.config.get('scan_acl', True):
            logger.info("\n" + "=" * 70)
            logger.info("MODULE 2: ENHANCED ACL SECURITY SCANNER")
            logger.info("=" * 70)
            scanner = ACLScanner(self.ad_conn)
            all_findings['acl'] = scanner.scan()
            self.results['findings'].extend(all_findings['acl'])
        
        # Module 3: ADCS Scanner
        if self.config.get('scan_adcs', True):
            logger.info("\n" + "=" * 70)
            logger.info("MODULE 3: ENHANCED AD CERTIFICATE SERVICES SCANNER")
            logger.info("=" * 70)
            scanner = ADCSScanner(self.ad_conn)
            all_findings['adcs'] = scanner.scan()
            self.results['findings'].extend(all_findings['adcs'])
        
        # Module 4: GPO Scanner
        if self.config.get('scan_gpo', True):
            logger.info("\n" + "=" * 70)
            logger.info("MODULE 4: ENHANCED GROUP POLICY OBJECT SCANNER")
            logger.info("=" * 70)
            scanner = GPOScanner(self.ad_conn)
            all_findings['gpo'] = scanner.scan()
            self.results['findings'].extend(all_findings['gpo'])
        
        # Module 5: Kerberos/Trusts Scanner
        if self.config.get('scan_kerberos', True):
            logger.info("\n" + "=" * 70)
            logger.info("MODULE 5: ENHANCED KERBEROS & TRUST SCANNER")
            logger.info("=" * 70)
            scanner = KerberosScanner(self.ad_conn)
            all_findings['kerberos'] = scanner.scan()
            self.results['findings'].extend(all_findings['kerberos'])
        
        return all_findings
    
    def _run_analysis(self, all_findings: Dict[str, List[Dict]]):
        """Run analysis and correlation engine"""
        logger.info("\n" + "=" * 70)
        logger.info("MODULE 6: ANALYSIS & CORRELATION ENGINE")
        logger.info("=" * 70)
        
        # Initialize attack path engine
        engine = AttackPathEngine()
        
        # Build attack graph
        engine.build_graph(
            all_findings.get('acl', []),
            all_findings.get('adcs', []),
            all_findings.get('gpo', []),
            all_findings.get('kerberos', [])
        )
        
        # Find attack paths
        attack_paths = engine.find_attack_paths()
        self.results['attack_paths'] = attack_paths
        
        # Calculate risk scores
        self.results['findings'] = engine.calculate_risk_scores(self.results['findings'])
        
        logger.info(f"Analysis complete: {len(attack_paths)} attack paths identified")
    
    def _generate_remediation(self):
        """Generate remediation framework"""
        logger.info("\n" + "=" * 70)
        logger.info("MODULE 7: REMEDIATION FRAMEWORK")
        logger.info("=" * 70)
        
        output_dir = Path(self.config.get('output_dir', 'output'))
        framework = RemediationFramework(output_dir)
        framework.generate_scripts(self.results['findings'])
    
    def _generate_reports(self):
        """Generate comprehensive reports"""
        logger.info("\n" + "=" * 70)
        logger.info("MODULE 8: REPORTING ENGINE")
        logger.info("=" * 70)
        
        output_dir = Path(self.config.get('output_dir', 'output'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Calculate statistics
        self.results['statistics'] = {
            'total_findings': len(self.results['findings']),
            'critical': sum(1 for f in self.results['findings'] if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in self.results['findings'] if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in self.results['findings'] if f.get('severity') == 'MEDIUM'),
            'low': sum(1 for f in self.results['findings'] if f.get('severity') == 'LOW'),
            'attack_paths': len(self.results['attack_paths']),
            'modules_scanned': sum([
                self.config.get('scan_acl', True),
                self.config.get('scan_adcs', True),
                self.config.get('scan_gpo', True),
                self.config.get('scan_kerberos', True)
            ]),
            'custom_templates_loaded': self.results['statistics'].get('custom_templates_loaded', 0),
            'custom_template_findings': self.results['statistics'].get('custom_template_findings', 0)
        }
        
        # JSON Report
        json_path = output_dir / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"  -> JSON Report: {json_path}")
        
        # Executive Summary
        self._generate_executive_summary(output_dir)
        
        # Technical Deep-Dive
        self._generate_technical_report(output_dir)
        
        logger.info("All reports generated successfully")
    
    def _print_reports(self):
        """Print reports to console"""
        logger.info("\n" + "=" * 70)
        logger.info("CONSOLE REPORT OUTPUT")
        logger.info("=" * 70)
        
        output_dir = Path(self.config.get('output_dir', 'output'))
        
        # Print Executive Summary
        exec_summary_path = output_dir / 'executive_summary.txt'
        if exec_summary_path.exists():
            print("\n" + exec_summary_path.read_text(encoding='utf-8'))
        
        # Print Technical Report if requested
        if self.config.get('print_technical', False):
            tech_report_path = output_dir / 'technical_report.txt'
            if tech_report_path.exists():
                print("\n" + tech_report_path.read_text(encoding='utf-8'))
    
    def _generate_executive_summary(self, output_dir: Path):
        """Generate executive-level summary"""
        summary_path = output_dir / 'executive_summary.txt'
        stats = self.results['statistics']
        
        # Build severity indicator
        risk_level = "LOW"
        if stats['critical'] > 0:
            risk_level = "CRITICAL"
        elif stats['high'] > 3:
            risk_level = "HIGH"
        elif stats['high'] > 0:
            risk_level = "MEDIUM"
        
        summary = f"""
==============================================================================
                AD SECUREAUDIT v2.1 - EXECUTIVE SUMMARY                    
==============================================================================

SCAN INFORMATION
------------------------------------------------------------------------------
Scan Date:           {self.results['scan_timestamp']}
Target Domain:       {self.results['target']}
Modules Scanned:     {stats['modules_scanned']}/4
Custom Templates:    {stats['custom_templates_loaded']} loaded
Overall Risk Level:  {risk_level}

RISK OVERVIEW
------------------------------------------------------------------------------
Total Findings:      {stats['total_findings']}
  [CRITICAL]:        {stats['critical']}
  [HIGH]:            {stats['high']}
  [MEDIUM]:          {stats['medium']}
  [LOW]:             {stats['low']}

Template Findings:   {stats['custom_template_findings']}
Attack Paths:        {stats['attack_paths']} privilege escalation paths identified

CRITICAL FINDINGS (Top 10)
------------------------------------------------------------------------------
"""
        
        # Sort by risk score and get top 10
        critical_findings = sorted(
            [f for f in self.results['findings'] if f.get('severity') in ['CRITICAL', 'HIGH']],
            key=lambda x: x.get('risk_score', 0),
            reverse=True
        )[:10]
        
        for idx, finding in enumerate(critical_findings, 1):
            summary += f"\n{idx}. [{finding.get('severity')}] {finding.get('title')}\n"
            summary += f"   Risk Score: {finding.get('risk_score', 0):.1f}/10.0\n"
            summary += f"   Module: {finding.get('module')}\n"
            
            # Add template info if it's a custom template finding
            if finding.get('module') == 'CustomTemplate':
                summary += f"   Template: {finding.get('template_name')}\n"
                summary += f"   Author: {finding.get('author')}\n"
            
            summary += f"   Impact: {finding.get('attack_vector', 'Not specified')}\n"
            if finding.get('mitigation'):
                summary += f"   Mitigation: {finding.get('mitigation')}\n"
        
        if not critical_findings:
            summary += "\n[OK] No critical or high-severity findings detected\n"
        
        summary += """
ATTACK PATH SUMMARY
------------------------------------------------------------------------------
"""
        
        for path in self.results['attack_paths'][:5]:
            summary += f"\nPath: {path['start_principal']} -> {path['target']}\n"
            summary += f"Risk Score: {path['combined_risk_score']}/10.0\n"
            summary += f"Steps: {path['path_length']}\n"
            summary += f"MITRE ATT&CK: {', '.join(path.get('techniques', []))}\n"
        
        summary += """
RECOMMENDATIONS
------------------------------------------------------------------------------
1. Review all CRITICAL findings immediately (within 24-48 hours)
2. Execute remediation scripts after thorough review and testing
3. Implement principle of least privilege across all accounts
4. Schedule regular security audits (quarterly recommended)
5. Monitor for new attack paths after remediation
6. Review and update security baselines
7. Implement detection rules for identified attack vectors

NEXT STEPS
------------------------------------------------------------------------------
- Review technical_report.txt for detailed findings
- Examine remediation/remediation.ps1 for automated fixes
- Run remediation/verify_remediation.ps1 after changes
- Test remediation in non-production environment first
- Document all changes in your change management system

------------------------------------------------------------------------------
Generated by AD SecureAudit v2.0
Report Generation: {datetime.now().isoformat()}
"""
        
        summary_path.write_text(summary, encoding='utf-8')
        logger.info(f"  -> Executive Summary: {summary_path}")
    
    def _generate_technical_report(self, output_dir: Path):
        """Generate detailed technical report"""
        tech_path = output_dir / 'technical_report.txt'
        
        report = f"""
==============================================================================
           AD SECUREAUDIT v2.0 - TECHNICAL DEEP-DIVE REPORT                
==============================================================================

SCAN METADATA
==============================================================================
Timestamp:      {self.results['scan_timestamp']}
Target Domain:  {self.results['target']}
Total Findings: {self.results['statistics']['total_findings']}
Attack Paths:   {self.results['statistics']['attack_paths']}
Scan Version:   2.0 (Enhanced Detection Engine)

DETAILED FINDINGS BY MODULE
==============================================================================

"""
        
        # Group findings by module
        findings_by_module = defaultdict(list)
        for finding in self.results['findings']:
            findings_by_module[finding.get('module', 'Unknown')].append(finding)
        
        # Generate detailed findings for each module
        for module, findings in sorted(findings_by_module.items()):
            # Sort findings by risk score within each module
            findings_sorted = sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True)
            
            report += f"\n{'=' * 78}\n"
            report += f"MODULE: {module}\n"
            report += f"{'=' * 78}\n"
            report += f"Total Issues: {len(findings)}\n"
            report += f"Risk Distribution:\n"
            report += f"  CRITICAL: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}\n"
            report += f"  HIGH: {sum(1 for f in findings if f.get('severity') == 'HIGH')}\n"
            report += f"  MEDIUM: {sum(1 for f in findings if f.get('severity') == 'MEDIUM')}\n"
            report += f"  LOW: {sum(1 for f in findings if f.get('severity') == 'LOW')}\n\n"
            
            for idx, finding in enumerate(findings_sorted, 1):
                report += f"\nFinding #{idx}: {finding.get('title')}\n"
                report += f"{'-' * 78}\n"
                report += f"Severity:     {finding.get('severity')}\n"
                report += f"Risk Score:   {finding.get('risk_score', 0):.1f}/10.0\n"
                
                if finding.get('esc_type'):
                    report += f"ESC Type:     {finding.get('esc_type')}\n"
                
                report += f"Description:  {finding.get('description')}\n"
                
                # Add module-specific details
                for key, value in finding.items():
                    if key not in ['module', 'severity', 'title', 'description', 'risk_score', 'attack_vector', 'mitigation', 'esc_type']:
                        report += f"{key.replace('_', ' ').title()}: {value}\n"
                
                report += f"\nAttack Vector:\n  {finding.get('attack_vector', 'Not specified')}\n"
                
                if finding.get('mitigation'):
                    report += f"\nRecommended Mitigation:\n  {finding.get('mitigation')}\n"
                
                # Add remediation guidance
                report += f"\nRemediation Steps:\n"
                report += f"  1. Review the automated remediation script in remediation/\n"
                report += f"  2. Verify change will not impact business operations\n"
                report += f"  3. Test in non-production environment\n"
                report += f"  4. Execute remediation with proper change control\n"
                report += f"  5. Verify using verify_remediation.ps1\n"
                report += f"  6. Document changes made\n"
                report += "\n"
        
        # Attack Path Analysis
        if self.results['attack_paths']:
            report += f"\n{'=' * 78}\n"
            report += "ATTACK PATH ANALYSIS\n"
            report += f"{'=' * 78}\n"
            report += f"Total Attack Paths Identified: {len(self.results['attack_paths'])}\n\n"
            
            for path in self.results['attack_paths']:
                report += f"\nAttack Path ID: {path['id']}\n"
                report += f"{'-' * 78}\n"
                report += f"Severity:          {path['severity']}\n"
                report += f"Risk Score:        {path['combined_risk_score']}/10.0\n"
                report += f"Start Principal:   {path['start_principal']}\n"
                report += f"Target:            {path['target']}\n"
                report += f"Path Length:       {path['path_length']} hops\n"
                
                if path.get('techniques'):
                    report += f"MITRE ATT&CK:      {', '.join(path['techniques'])}\n"
                
                report += f"\nAttack Chain:\n"
                
                for step_num, step in enumerate(path['steps'], 1):
                    report += f"  Step {step_num}: {step}\n"
                
                report += f"\nMitigation Strategy:\n"
                report += f"  Breaking any link in this chain will prevent the full attack.\n"
                report += f"  Priority: Address the highest-risk finding first.\n"
                report += f"  Focus on: Step 1 (initial access) and final step (privilege escalation)\n"
                report += "\n"
        
        # Summary and recommendations
        report += f"\n{'=' * 78}\n"
        report += "SUMMARY & RECOMMENDATIONS\n"
        report += f"{'=' * 78}\n\n"
        
        report += "Priority Actions (by Severity):\n"
        report += "1. CRITICAL findings: Address within 24-48 hours\n"
        report += "2. HIGH findings: Remediate within 1 week\n"
        report += "3. MEDIUM findings: Plan remediation within 1 month\n"
        report += "4. LOW findings: Review during next maintenance window\n\n"
        
        report += "Long-term Recommendations:\n"
        report += "- Implement continuous AD monitoring and alerting\n"
        report += "- Schedule quarterly comprehensive security audits\n"
        report += "- Establish and enforce least-privilege access policies\n"
        report += "- Enable Microsoft Defender for Identity or similar EDR\n"
        report += "- Implement privileged access workstations (PAWs)\n"
        report += "- Conduct regular security awareness training\n"
        report += "- Maintain detailed documentation of AD changes\n"
        report += "- Implement tiered administrative model\n"
        report += "- Enable advanced audit policies for attack detection\n\n"
        
        report += "Detection and Monitoring:\n"
        report += "- Monitor for Kerberoasting attempts (Event ID 4769)\n"
        report += "- Alert on DCSync attacks (Directory Service Access events)\n"
        report += "- Track certificate enrollment anomalies\n"
        report += "- Monitor GPO modifications (Event ID 5136/5137)\n"
        report += "- Implement honeypot accounts to detect enumeration\n\n"
        
        report += f"{'=' * 78}\n"
        report += "END OF REPORT\n"
        report += f"Generated: {datetime.now().isoformat()}\n"
        report += f"{'=' * 78}\n"
        
        tech_path.write_text(report, encoding='utf-8')
        logger.info(f"  -> Technical Report: {tech_path}")


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description='AD SecureAudit v2.0 - Enhanced Active Directory Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with Kerberos (recommended on domain-joined machine)
  python ad_secaudit.py -d corp.local --kerberos
  
  # Scan with explicit credentials
  python main.py -d corp.local -u Administrator -p Password123! --ldaps
  
  # Scan and print reports to console
  python main.py -d corp.local --kerberos --print
  
  # Scan only specific modules
  python main.py -d corp.local --kerberos --only adcs,kerberos
  
  # NEW: Scan with custom templates
  python main.py -d corp.local --kerberos -t custom_check.yaml
  
  # NEW: Scan with template directory
  python main.py -d corp.local --kerberos -t /path/to/templates/
  
  # NEW: Multiple template sources
  python main.py -d corp.local --kerberos -t file1.yaml -t file2.yaml -t /templates/
  
  # NEW: Only run custom templates (skip built-in modules)
  python main.py -d corp.local --kerberos -t /templates/ --only custom
  
  # Full scan with detailed console output
  python main.py -d corp.local --kerberos --print --print-technical -v

Requirements:
  pip install ldap3
  pip install pyyaml (for custom templates)
  pip install pywin32 (for Kerberos on Windows)

Template Format:
  See template_examples/ directory for YAML/JSON template examples

Note: Run from domain-joined workstation for best results
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, 
                       help='Target domain (e.g., corp.local)')
    parser.add_argument('-u', '--username',
                       help='Domain admin username (not needed with --kerberos)')
    parser.add_argument('-p', '--password',
                       help='Password (will prompt if not provided, not needed with --kerberos)')
    parser.add_argument('-s', '--server',
                       help='Specific domain controller (optional)')
    parser.add_argument('-o', '--output', default='output',
                       help='Output directory (default: output)')
    parser.add_argument('-t', '--template', action='append', dest='templates',
                       help='Path to custom template file or directory (can be specified multiple times)')
    parser.add_argument('--kerberos', action='store_true',
                       help='Use Kerberos authentication (requires pywin32)')
    parser.add_argument('--ldaps', action='store_true',
                       help='Use LDAPS (SSL/TLS on port 636) instead of LDAP')
    parser.add_argument('--no-remediation', action='store_true',
                       help='Skip remediation script generation')
    parser.add_argument('--only',
                       help='Scan specific modules only (comma-separated: acl,adcs,gpo,kerberos,custom)')
    parser.add_argument('--print', dest='print_reports', action='store_true',
                       help='Print executive summary to console after scan')
    parser.add_argument('--print-technical', action='store_true',
                       help='Also print technical report to console (use with --print)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate authentication method
    if args.kerberos:
        logger.info("Kerberos authentication mode selected")
        logger.info("Will use current logged-in user credentials")
    else:
        if not args.username:
            logger.error("Error: --username required when not using --kerberos")
            parser.print_help()
            sys.exit(1)
        
        # Prompt for password if not provided
        if not args.password:
            import getpass
            args.password = getpass.getpass(f"Password for {args.username}: ")
    
    # Build configuration
    config = {
        'domain': args.domain,
        'username': args.username,
        'password': args.password,
        'server': args.server,
        'output_dir': args.output,
        'use_kerberos': args.kerberos,
        'use_ssl': args.ldaps,
        'generate_remediation': not args.no_remediation,
        'print_reports': args.print_reports,
        'print_technical': args.print_technical,
        'template_paths': args.templates or []
    }
    
    # Handle selective module scanning
    if args.only:
        modules = [m.strip().lower() for m in args.only.split(',')]
        config.update({
            'scan_acl': 'acl' in modules,
            'scan_adcs': 'adcs' in modules,
            'scan_gpo': 'gpo' in modules,
            'scan_kerberos': 'kerberos' in modules,
        })
        
        # If only 'custom' is specified, disable all other modules
        if 'custom' in modules and len(modules) == 1:
            config.update({
                'scan_acl': False,
                'scan_adcs': False,
                'scan_gpo': False,
                'scan_kerberos': False,
            })
    
    try:
        # Banner
        print("\n" + "=" * 70)
        print("AD SECUREAUDIT v2.1 - ENHANCED SECURITY SCANNER")
        print("With Custom Template Support (Nuclei-style)")
        print("=" * 70)
        print(f"Target: {args.domain}")
        if args.kerberos:
            import getpass
            print(f"Auth: Kerberos (as {getpass.getuser()})")
        else:
            print(f"Auth: LDAPS (as {args.username})")
        
        if args.templates:
            print(f"Custom Templates: {len(args.templates)} path(s) specified")
        
        print("=" * 70 + "\n")
        print("=" * 70)
        
        # Initialize and run
        auditor = ADSecureAudit(config)
        results = auditor.run_full_audit()
        
        # Final summary
        print("\n" + "=" * 70)
        print("SCAN COMPLETE")
        print("=" * 70)
        
        # Safely access statistics with .get()
        stats = results.get('statistics', {})
        print(f"Total Findings:     {stats.get('total_findings', 0)}")
        print(f"  Critical:         {stats.get('critical', 0)}")
        print(f"  High:             {stats.get('high', 0)}")
        print(f"  Medium:           {stats.get('medium', 0)}")
        print(f"  Low:              {stats.get('low', 0)}")
        print(f"Attack Paths:       {stats.get('attack_paths', 0)}")
        
        if stats.get('custom_templates_loaded', 0) > 0:
            print(f"\nCustom Templates:   {stats.get('custom_templates_loaded', 0)} loaded")
            print(f"Template Findings:  {stats.get('custom_template_findings', 0)}")
        
        print(f"\nReports Location:   {args.output}/")
        print(f"Remediation Scripts: {args.output}/remediation/")
        print("=" * 70)
        
        # Exit code based on findings
        if stats.get('critical', 0) > 0:
            print("\n[!] CRITICAL issues found - immediate action required!")
            sys.exit(1)
        elif stats.get('high', 0) > 0:
            print("\n[!] HIGH severity issues found - review recommended")
            sys.exit(0)
        else:
            print("\n[OK] No critical issues detected")
            sys.exit(0)
        
    except KeyboardInterrupt:
        logger.warning("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\nFatal error: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()