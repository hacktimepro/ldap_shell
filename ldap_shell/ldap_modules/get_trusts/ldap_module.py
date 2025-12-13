import logging
from ldap3 import Connection, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for enumerating domain trusts and identifying trust misconfigurations"""
    
    help_text = "Enumerate all domain trusts and identify security misconfigurations"
    examples_text = """
    List all domain trusts:
    `get_trusts`
    ```
    [INFO] Found 3 trust(s):
    [INFO] 
    [INFO] Trust: child.domain.local
    [INFO]   Type: Forest Trust
    [INFO]   Direction: Bidirectional
    [INFO]   Transitive: Yes
    [INFO]   SID Filtering: Enabled
    [INFO]   TGT Delegation: Disabled
    [INFO]   NetBIOS: CHILD
    [INFO]   SID: S-1-5-21-1234567890-1234567890-1234567890
    [INFO]   Status: OK
    ```
    
    List only misconfigured trusts:
    `get_trusts -misconfig`
    ```
    [WARNING] Found 1 misconfigured trust(s):
    [WARNING] 
    [WARNING] Trust: external.domain.local
    [WARNING]   Type: External Trust
    [WARNING]   Direction: Outbound
    [WARNING]   SID Filtering: DISABLED (CRITICAL!)
    [WARNING]   TGT Delegation: Enabled (RISKY!)
    [WARNING]   Issues: SID filtering disabled, TGT delegation enabled
    ```
    """
    module_type = "Get Info"

    # Trust direction flags
    TRUST_DIRECTION = {
        0: 'Disabled',
        1: 'Inbound',
        2: 'Outbound',
        3: 'Bidirectional'
    }

    # Trust type flags
    TRUST_TYPE = {
        1: 'Downlevel (NT4)',
        2: 'Uplevel (AD)',
        3: 'MIT',
        4: 'DCE'
    }

    # Trust attributes flags (security settings)
    TRUST_ATTRIBUTES = {
        0x00000001: 'NON_TRANSITIVE',
        0x00000002: 'UPLEVEL_ONLY',
        0x00000004: 'QUARANTINED_DOMAIN (SID Filtering)',
        0x00000008: 'FOREST_TRANSITIVE',
        0x00000010: 'CROSS_ORGANIZATION',
        0x00000020: 'WITHIN_FOREST',
        0x00000040: 'TREAT_AS_EXTERNAL',
        0x00000080: 'USES_RC4_ENCRYPTION',
        0x00000100: 'CROSS_ORGANIZATION_NO_TGT_DELEGATION',
        0x00000200: 'PIM_TRUST'
    }

    class ModuleArgs(BaseModel):
        misconfig: Optional[bool] = Field(
            False,
            description="Show only misconfigured trusts",
            arg_type=ArgumentType.BOOLEAN
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def determine_trust_type_name(self, trust_type: int, trust_attributes: int) -> str:
        """Determine human-readable trust type name"""
        # Check if it's within forest
        if trust_attributes & 0x00000020:  # WITHIN_FOREST
            if trust_attributes & 0x00000008:  # FOREST_TRANSITIVE
                return 'Forest Trust (Parent-Child or Tree-Root)'
            else:
                return 'Parent-Child Trust'
        elif trust_attributes & 0x00000040:  # TREAT_AS_EXTERNAL
            return 'External Trust'
        elif trust_attributes & 0x00000010:  # CROSS_ORGANIZATION
            return 'Cross-Organization Trust'
        elif trust_type == 1:  # Downlevel
            return 'External Trust (NT4)'
        elif trust_type == 2:  # Uplevel
            return 'Forest Trust'
        else:
            return self.TRUST_TYPE.get(trust_type, f'Unknown ({trust_type})')

    def parse_trust_attributes(self, attributes: int) -> dict:
        """Parse trust attributes flags"""
        result = {
            'flags': [],
            'sid_filtering': False,
            'tgt_delegation': True,  # Default is enabled unless flag is set
            'transitive': False,
            'rc4_encryption': False,
            'within_forest': False,
            'treat_as_external': False
        }
        
        for flag_value, flag_name in self.TRUST_ATTRIBUTES.items():
            if attributes & flag_value:
                result['flags'].append(flag_name)
                
                if flag_value == 0x00000004:  # SID Filtering
                    result['sid_filtering'] = True
                if flag_value == 0x00000100:  # No TGT Delegation
                    result['tgt_delegation'] = False
                if flag_value == 0x00000008:  # Forest Transitive
                    result['transitive'] = True
                if flag_value == 0x00000080:  # RC4 Encryption
                    result['rc4_encryption'] = True
                if flag_value == 0x00000020:  # Within Forest
                    result['within_forest'] = True
                if flag_value == 0x00000040:  # Treat as External
                    result['treat_as_external'] = True
        
        return result

    def check_misconfigurations(self, trust_info: dict) -> list:
        """Check for security misconfigurations"""
        issues = []
        
        # Check SID filtering
        if not trust_info.get('sid_filtering', False):
            issues.append('SID filtering disabled (CRITICAL: allows SID History attacks)')
        
        # Check TGT delegation
        if trust_info.get('tgt_delegation', False):
            issues.append('TGT delegation enabled (RISKY: allows Kerberos delegation attacks)')
        
        # Check RC4 encryption
        if trust_info.get('rc4_encryption', False):
            issues.append('RC4 encryption enabled (WEAK: vulnerable to downgrade attacks)')
        
        # Check outbound trusts (can be risky)
        if trust_info.get('direction') == 'Outbound':
            issues.append('Outbound trust (allows external domain to authenticate to this domain)')
        
        # Check external trusts without SID filtering
        if 'External Trust' in trust_info.get('type', '') and not trust_info.get('sid_filtering', False):
            issues.append('External trust without SID filtering (HIGH RISK)')
        
        # Check transitive external trusts
        if 'External Trust' in trust_info.get('type', '') and trust_info.get('transitive', False):
            issues.append('Transitive external trust (unusual and potentially risky)')
        
        # Check forest trusts without SID filtering (less common but still risky)
        if 'Forest Trust' in trust_info.get('type', '') and not trust_info.get('sid_filtering', False):
            issues.append('Forest trust without SID filtering (RISKY)')
        
        return issues

    def format_sid(self, sid_data) -> str:
        """Format SID from bytes or string to string"""
        if not sid_data:
            return 'N/A'
        try:
            # If already a string (S-1-5-...), return as is
            if isinstance(sid_data, str):
                return sid_data
            
            # If bytes, parse binary SID
            if isinstance(sid_data, bytes):
                if len(sid_data) < 8:
                    return 'Invalid SID'
                revision = sid_data[0]
                sub_authority_count = sid_data[1]
                identifier_authority = int.from_bytes(sid_data[2:8], byteorder='big')
                
                sid_str = f'S-{revision}-{identifier_authority}'
                
                # Parse sub-authorities
                offset = 8
                for i in range(sub_authority_count):
                    if offset + 4 > len(sid_data):
                        break
                    sub_auth = int.from_bytes(sid_data[offset:offset+4], byteorder='little')
                    sid_str += f'-{sub_auth}'
                    offset += 4
                
                return sid_str
            
            # Try to convert to string
            return str(sid_data)
        except Exception as e:
            self.log.debug(f'Error formatting SID: {str(e)}')
            return str(sid_data) if sid_data else 'N/A'

    def __call__(self):
        self.log.info('Enumerating domain trusts...')
        
        try:
            # Search for trustedDomain objects
            # Trusts are stored in System container: CN=System,DC=domain,DC=local
            system_dn = f'CN=System,{self.domain_dumper.root}'
            
            self.client.search(
                system_dn,
                '(objectClass=trustedDomain)',
                attributes=[
                    'cn',  # Trust name
                    'trustPartner',  # FQDN of trusted domain
                    'trustDirection',  # Direction (0-3)
                    'trustType',  # Type (1-4)
                    'trustAttributes',  # Security flags
                    'flatName',  # NetBIOS name
                    'securityIdentifier',  # SID of trusted domain
                    'trustAuthIncoming',  # Incoming trust password
                    'trustAuthOutgoing'  # Outgoing trust password
                ],
                search_scope=SUBTREE,
                size_limit=100
            )
            
            if not self.client.entries:
                self.log.info('No trusts found')
                return
            
            trusts = []
            for entry in self.client.entries:
                # Get attributes safely
                trust_name = entry['cn'].value if 'cn' in entry else 'Unknown'
                trust_partner = entry['trustPartner'].value if 'trustPartner' in entry else 'N/A'
                trust_direction = entry['trustDirection'].value if 'trustDirection' in entry else 0
                trust_type = entry['trustType'].value if 'trustType' in entry else 0
                trust_attributes = entry['trustAttributes'].value if 'trustAttributes' in entry else 0
                flat_name = entry['flatName'].value if 'flatName' in entry else 'N/A'
                security_identifier = entry['securityIdentifier'].value if 'securityIdentifier' in entry else None
                
                # Parse trust information
                parsed_attrs = self.parse_trust_attributes(trust_attributes)
                
                # Determine trust type name
                trust_type_name = self.determine_trust_type_name(trust_type, trust_attributes)
                
                trust_info = {
                    'name': trust_name,
                    'partner': trust_partner,
                    'direction': self.TRUST_DIRECTION.get(trust_direction, f'Unknown ({trust_direction})'),
                    'type': trust_type_name,
                    'type_raw': self.TRUST_TYPE.get(trust_type, f'Unknown ({trust_type})'),
                    'netbios': flat_name,
                    'sid': self.format_sid(security_identifier),
                    'sid_filtering': parsed_attrs['sid_filtering'],
                    'tgt_delegation': parsed_attrs['tgt_delegation'],
                    'transitive': parsed_attrs['transitive'],
                    'rc4_encryption': parsed_attrs['rc4_encryption'],
                    'within_forest': parsed_attrs['within_forest'],
                    'treat_as_external': parsed_attrs['treat_as_external'],
                    'flags': parsed_attrs['flags'],
                    'raw_attributes': trust_attributes,
                    'raw_direction': trust_direction,
                    'raw_type': trust_type
                }
                
                # Check for misconfigurations
                issues = self.check_misconfigurations(trust_info)
                trust_info['issues'] = issues
                trust_info['has_issues'] = len(issues) > 0
                
                trusts.append(trust_info)
            
            # Filter by misconfig if requested
            if self.args.misconfig:
                trusts = [t for t in trusts if t['has_issues']]
                if not trusts:
                    self.log.info('No misconfigured trusts found')
                    return
                self.log.warning(f'Found {len(trusts)} misconfigured trust(s):')
            else:
                self.log.info(f'Found {len(trusts)} trust(s):')
            
            # Display trusts
            for trust in trusts:
                self.log.info('')
                if trust['has_issues']:
                    self.log.warning(f"Trust: {trust['name']}")
                else:
                    self.log.info(f"Trust: {trust['name']}")
                
                self.log.info(f"  Partner: {trust['partner']}")
                self.log.info(f"  Type: {trust['type']} ({trust['type_raw']})")
                self.log.info(f"  Direction: {trust['direction']} ({trust['raw_direction']})")
                
                if trust['transitive']:
                    self.log.info(f"  Transitive: Yes")
                else:
                    self.log.info(f"  Transitive: No")
                
                # Security settings
                if trust['sid_filtering']:
                    self.log.info(f"  SID Filtering: Enabled")
                else:
                    self.log.warning(f"  SID Filtering: DISABLED (CRITICAL!)")
                
                if trust['tgt_delegation']:
                    self.log.warning(f"  TGT Delegation: Enabled (RISKY!)")
                else:
                    self.log.info(f"  TGT Delegation: Disabled")
                
                if trust['rc4_encryption']:
                    self.log.warning(f"  RC4 Encryption: Enabled (WEAK!)")
                else:
                    self.log.info(f"  RC4 Encryption: Disabled")
                
                self.log.info(f"  NetBIOS: {trust['netbios']}")
                self.log.info(f"  SID: {trust['sid']}")
                
                if trust['flags']:
                    self.log.info(f"  Flags: {', '.join(trust['flags'])}")
                
                # Show issues
                if trust['issues']:
                    self.log.warning(f"  Issues:")
                    for issue in trust['issues']:
                        self.log.warning(f"    - {issue}")
                else:
                    self.log.info(f"  Status: OK")
        
        except Exception as e:
            self.log.error(f'Error enumerating trusts: {str(e)}')
            import traceback
            self.log.debug(f'Traceback: {traceback.format_exc()}')

