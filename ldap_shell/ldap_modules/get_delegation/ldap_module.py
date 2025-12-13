import logging
from ldap3 import Connection, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for finding accounts vulnerable to delegation attacks"""
    
    help_text = "Find accounts with delegation enabled (Unconstrained, Constrained, RBCD). Useful for reconnaissance even without privileges."
    examples_text = """
    Find all accounts with delegation enabled:
    `get_delegation`
    ```
    [INFO] Searching for delegation vulnerabilities...
    [INFO] 
    [INFO] === Unconstrained Delegation (TRUSTED_FOR_DELEGATION) ===
    [INFO] Found 2 account(s) with Unconstrained Delegation:
    [INFO]   - DC01$ (CN=DC01,OU=Domain Controllers,DC=domain,DC=local)
    [INFO]     UserAccountControl: 524288 (0x80000)
    [INFO]     WARNING: This account can impersonate ANY user to ANY service!
    [INFO] 
    [INFO] === Constrained Delegation (TRUSTED_TO_AUTH_FOR_DELEGATION) ===
    [INFO] Found 1 account(s) with Constrained Delegation:
    [INFO]   - WEB01$ (CN=WEB01,CN=Computers,DC=domain,DC=local)
    [INFO]     UserAccountControl: 16777216 (0x1000000)
    [INFO]     Allowed Services: cifs/DC01.domain.local, http/DC01.domain.local
    [INFO] 
    [INFO] === Resource-Based Constrained Delegation (RBCD) ===
    [INFO] Found 3 computer(s) with RBCD configured:
    [INFO]   - DC01$ (CN=DC01,OU=Domain Controllers,DC=domain,DC=local)
    [INFO]     Allowed to delegate: WEB01$, SQL01$
    [INFO]     WARNING: These accounts can impersonate users on DC01$!
    ```
    
    Find specific account:
    `get_delegation DC01$`
    ```
    [INFO] Checking delegation for: DC01$
    [INFO] Account: DC01$ (CN=DC01,OU=Domain Controllers,DC=domain,DC=local)
    [INFO] Unconstrained Delegation: ENABLED (0x80000)
    [INFO] Constrained Delegation: Disabled
    [INFO] RBCD: Not configured
    [INFO] WARNING: This account can impersonate ANY user to ANY service!
    ```
    
    Find only computers with RBCD:
    `get_delegation -rbcd-only`
    ```
    [INFO] Searching for computers with RBCD configured...
    [INFO] Found 3 computer(s) with RBCD:
    [INFO]   - DC01$ (CN=DC01,OU=Domain Controllers,DC=domain,DC=local)
    [INFO]     Allowed to delegate: WEB01$, SQL01$
    ```
    """
    module_type = "Get Info"
    
    # UAC flags for delegation
    TRUSTED_FOR_DELEGATION = 0x80000  # Unconstrained Delegation
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Constrained Delegation
    
    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Specific account to check (sAMAccountName). If not specified, searches for all accounts with delegation",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        rbcd_only: Optional[bool] = Field(
            False,
            description="Search only for computers with RBCD configured",
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
    
    def parse_rbcd_sd(self, sd_data):
        """Parse RBCD security descriptor to get allowed SIDs"""
        try:
            if not sd_data:
                return []
            
            if isinstance(sd_data, list):
                if len(sd_data) == 0:
                    return []
                sd_bytes = sd_data[0]
            elif isinstance(sd_data, bytes):
                sd_bytes = sd_data
            else:
                return []
            
            if not isinstance(sd_bytes, bytes):
                return []
            
            sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
            if 'Dacl' not in sd or not sd['Dacl']:
                return []
            
            dacl = sd['Dacl']
            if not hasattr(dacl, 'aces') or not dacl.aces:
                return []
            
            allowed_sids = []
            for ace in dacl.aces:
                try:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    # Try to get account name from SID
                    account_name = LdapUtils.sid_to_user(self.client, self.domain_dumper, sid)
                    if account_name:
                        allowed_sids.append(account_name)
                    else:
                        allowed_sids.append(sid)
                except (KeyError, IndexError, AttributeError):
                    continue
            
            return allowed_sids
        except Exception as e:
            self.log.debug(f'Error parsing RBCD SD: {str(e)}')
            return []
    
    def check_single_account(self, target: str):
        """Check delegation for specific account"""
        self.log.info(f'Checking delegation for: {target}')
        
        try:
            # Search for account
            self.client.search(
                self.domain_dumper.root,
                f'(sAMAccountName={escape_filter_chars(target)})',
                SUBTREE,
                attributes=['userAccountControl', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'distinguishedName', 'objectClass']
            )
            
            if len(self.client.entries) == 0:
                self.log.error(f'Account not found: {target}')
                return
            
            entry = self.client.entries[0]
            dn = entry.entry_dn
            
            # Check if computer
            object_classes = entry.get('objectClass', [])
            if isinstance(object_classes, list):
                obj_classes_lower = [oc.lower() if isinstance(oc, str) else str(oc).lower() for oc in object_classes]
            else:
                obj_classes_lower = [str(object_classes).lower()]
            is_computer = 'computer' in obj_classes_lower
            
            self.log.info(f'Account: {target} ({dn})')
            
            # Check UAC flags
            uac = 0
            if 'userAccountControl' in entry:
                uac_attr = entry['userAccountControl']
                if isinstance(uac_attr.value, list):
                    uac = uac_attr.value[0] if len(uac_attr.value) > 0 else 0
                else:
                    uac = uac_attr.value
            
            unconstrained = bool(uac & self.TRUSTED_FOR_DELEGATION)
            constrained = bool(uac & self.TRUSTED_TO_AUTH_FOR_DELEGATION)
            
            if unconstrained:
                self.log.warning(f'Unconstrained Delegation: ENABLED (0x{self.TRUSTED_FOR_DELEGATION:x})')
                self.log.warning('WARNING: This account can impersonate ANY user to ANY service!')
            else:
                self.log.info('Unconstrained Delegation: Disabled')
            
            if constrained:
                self.log.warning(f'Constrained Delegation: ENABLED (0x{self.TRUSTED_TO_AUTH_FOR_DELEGATION:x})')
                # Get allowed services
                if 'msDS-AllowedToDelegateTo' in entry:
                    allowed_services_attr = entry['msDS-AllowedToDelegateTo']
                    if isinstance(allowed_services_attr.value, list):
                        services = allowed_services_attr.value
                    else:
                        services = [allowed_services_attr.value] if allowed_services_attr.value else []
                    if services:
                        self.log.info(f'Allowed Services: {", ".join(services)}')
                    else:
                        self.log.warning('No services configured (may be misconfigured)')
                else:
                    self.log.warning('No services configured (may be misconfigured)')
            else:
                self.log.info('Constrained Delegation: Disabled')
            
            # Check RBCD (only for computers)
            if is_computer:
                if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in entry:
                    rbcd_attr = entry['msDS-AllowedToActOnBehalfOfOtherIdentity']
                    if rbcd_attr:
                        rbcd_data = rbcd_attr.raw_values if hasattr(rbcd_attr, 'raw_values') else [rbcd_attr.value] if hasattr(rbcd_attr, 'value') else []
                        allowed_sids = self.parse_rbcd_sd(rbcd_data)
                        if allowed_sids:
                            self.log.warning('RBCD: CONFIGURED')
                            self.log.warning(f'Allowed to delegate: {", ".join(allowed_sids)}')
                            self.log.warning('WARNING: These accounts can impersonate users on this computer!')
                        else:
                            self.log.info('RBCD: Not configured')
                    else:
                        self.log.info('RBCD: Not configured')
                else:
                    self.log.info('RBCD: Not configured')
            else:
                self.log.info('RBCD: Not applicable (not a computer account)')
                
        except Exception as e:
            self.log.error(f'Error checking account: {str(e)}')
    
    def find_all_delegation(self):
        """Find all accounts with delegation enabled"""
        self.log.info('Searching for delegation vulnerabilities...')
        self.log.info('')
        
        if self.args.rbcd_only:
            self.find_rbcd_only()
            return
        
        # Find Unconstrained Delegation
        self.log.info('=== Unconstrained Delegation (TRUSTED_FOR_DELEGATION) ===')
        unconstrained_accounts = []
        try:
            # Search for accounts with TRUSTED_FOR_DELEGATION flag
            self.client.search(
                self.domain_dumper.root,
                f'(&(userAccountControl:1.2.840.113556.1.4.803:={self.TRUSTED_FOR_DELEGATION}))',
                SUBTREE,
                attributes=['sAMAccountName', 'userAccountControl', 'distinguishedName']
            )
            
            for entry in self.client.entries:
                sam = entry['sAMAccountName'].value
                dn = entry.entry_dn
                uac = 0
                if 'userAccountControl' in entry:
                    uac_attr = entry['userAccountControl']
                    if isinstance(uac_attr.value, list):
                        uac = uac_attr.value[0] if len(uac_attr.value) > 0 else 0
                    else:
                        uac = uac_attr.value
                unconstrained_accounts.append({
                    'sam': sam,
                    'dn': dn,
                    'uac': uac
                })
            
            if unconstrained_accounts:
                self.log.info(f'Found {len(unconstrained_accounts)} account(s) with Unconstrained Delegation:')
                for acc in unconstrained_accounts:
                    self.log.info(f'  - {acc["sam"]} ({acc["dn"]})')
                    self.log.info(f'    UserAccountControl: {acc["uac"]} (0x{acc["uac"]:x})')
                    self.log.warning('    WARNING: This account can impersonate ANY user to ANY service!')
            else:
                self.log.info('No accounts found with Unconstrained Delegation')
        except Exception as e:
            self.log.error(f'Error searching for Unconstrained Delegation: {str(e)}')
        
        self.log.info('')
        
        # Find Constrained Delegation
        self.log.info('=== Constrained Delegation (TRUSTED_TO_AUTH_FOR_DELEGATION) ===')
        constrained_accounts = []
        try:
            # Search for accounts with TRUSTED_TO_AUTH_FOR_DELEGATION flag
            self.client.search(
                self.domain_dumper.root,
                f'(&(userAccountControl:1.2.840.113556.1.4.803:={self.TRUSTED_TO_AUTH_FOR_DELEGATION}))',
                SUBTREE,
                attributes=['sAMAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo', 'distinguishedName']
            )
            
            for entry in self.client.entries:
                sam = entry['sAMAccountName'].value
                dn = entry.entry_dn
                uac = 0
                if 'userAccountControl' in entry:
                    uac_attr = entry['userAccountControl']
                    if isinstance(uac_attr.value, list):
                        uac = uac_attr.value[0] if len(uac_attr.value) > 0 else 0
                    else:
                        uac = uac_attr.value
                
                services = []
                if 'msDS-AllowedToDelegateTo' in entry:
                    allowed_services_attr = entry['msDS-AllowedToDelegateTo']
                    if isinstance(allowed_services_attr.value, list):
                        services = allowed_services_attr.value
                    else:
                        services = [allowed_services_attr.value] if allowed_services_attr.value else []
                
                constrained_accounts.append({
                    'sam': sam,
                    'dn': dn,
                    'uac': uac,
                    'services': services
                })
            
            if constrained_accounts:
                self.log.info(f'Found {len(constrained_accounts)} account(s) with Constrained Delegation:')
                for acc in constrained_accounts:
                    self.log.info(f'  - {acc["sam"]} ({acc["dn"]})')
                    self.log.info(f'    UserAccountControl: {acc["uac"]} (0x{acc["uac"]:x})')
                    if acc['services']:
                        self.log.info(f'    Allowed Services: {", ".join(acc["services"])}')
                    else:
                        self.log.warning('    No services configured (may be misconfigured)')
            else:
                self.log.info('No accounts found with Constrained Delegation')
        except Exception as e:
            self.log.error(f'Error searching for Constrained Delegation: {str(e)}')
        
        self.log.info('')
        
        # Find RBCD
        self.find_rbcd_only()
    
    def find_rbcd_only(self):
        """Find computers with RBCD configured"""
        if not self.args.rbcd_only:
            self.log.info('=== Resource-Based Constrained Delegation (RBCD) ===')
        
        rbcd_computers = []
        try:
            # Search for all computers
            self.client.search(
                self.domain_dumper.root,
                '(objectClass=computer)',
                SUBTREE,
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'distinguishedName']
            )
            
            for entry in self.client.entries:
                if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in entry:
                    rbcd_attr = entry['msDS-AllowedToActOnBehalfOfOtherIdentity']
                    if rbcd_attr:
                        rbcd_data = rbcd_attr.raw_values if hasattr(rbcd_attr, 'raw_values') else [rbcd_attr.value] if hasattr(rbcd_attr, 'value') else []
                        allowed_sids = self.parse_rbcd_sd(rbcd_data)
                        if allowed_sids:
                            sam = entry['sAMAccountName'].value
                            dn = entry.entry_dn
                            rbcd_computers.append({
                                'sam': sam,
                                'dn': dn,
                                'allowed': allowed_sids
                            })
            
            if rbcd_computers:
                if self.args.rbcd_only:
                    self.log.info(f'Found {len(rbcd_computers)} computer(s) with RBCD:')
                else:
                    self.log.info(f'Found {len(rbcd_computers)} computer(s) with RBCD configured:')
                for comp in rbcd_computers:
                    self.log.info(f'  - {comp["sam"]} ({comp["dn"]})')
                    self.log.warning(f'    Allowed to delegate: {", ".join(comp["allowed"])}')
                    self.log.warning('    WARNING: These accounts can impersonate users on this computer!')
            else:
                if self.args.rbcd_only:
                    self.log.info('No computers found with RBCD configured')
                else:
                    self.log.info('No computers found with RBCD configured')
        except Exception as e:
            self.log.error(f'Error searching for RBCD: {str(e)}')
    
    def __call__(self):
        if self.args.target:
            self.check_single_account(self.args.target)
        else:
            self.find_all_delegation()

