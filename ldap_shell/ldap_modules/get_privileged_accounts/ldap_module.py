import logging
from ldap3 import Connection, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap3.utils.conv import escape_filter_chars
from datetime import datetime, timedelta

class LdapShellModule(BaseLdapModule):
    """Module for finding privileged accounts in Active Directory"""
    
    help_text = "Find all privileged accounts (Domain Admins, Enterprise Admins, Schema Admins, etc.) and their members. Useful for reconnaissance."
    examples_text = """
    Find all privileged accounts:
    `get_privileged_accounts`
    ```
    [INFO] Searching for privileged accounts...
    [INFO] 
    [INFO] === Domain Admins ===
    [INFO] Found 3 member(s):
    [INFO]   - Administrator (CN=Administrator,CN=Users,DC=domain,DC=local)
    [INFO]     Type: User
    [INFO]     Last logon: 2024-01-15 10:30:00
    [INFO]     Enabled: Yes
    [INFO]   - admin.user (CN=admin.user,CN=Users,DC=domain,DC=local)
    [INFO]     Type: User
    [INFO]     Last logon: 2024-01-14 15:20:00
    [INFO]     Enabled: Yes
    [INFO] 
    [INFO] === Enterprise Admins ===
    [INFO] Found 1 member(s):
    [INFO]   - Administrator (CN=Administrator,CN=Users,DC=domain,DC=local)
    [INFO]     Type: User
    [INFO]     Last logon: 2024-01-15 10:30:00
    [INFO]     Enabled: Yes
    ```
    
    Find members of specific privileged group:
    `get_privileged_accounts "Domain Admins"`
    ```
    [INFO] Searching for members of: Domain Admins
    [INFO] Found 3 member(s):
    [INFO]   - Administrator (CN=Administrator,CN=Users,DC=domain,DC=local)
    [INFO]     Type: User
    [INFO]     Last logon: 2024-01-15 10:30:00
    [INFO]     Enabled: Yes
    ```
    
    Find only enabled accounts:
    `get_privileged_accounts -enabled-only`
    ```
    [INFO] Searching for privileged accounts (enabled only)...
    [INFO] === Domain Admins ===
    [INFO] Found 2 enabled member(s):
    ```
    """
    module_type = "Get Info"
    
    # Privileged groups to search for
    PRIVILEGED_GROUPS = [
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'Replicator',
        'Administrators',  # Built-in Administrators
        'Domain Controllers',  # All DCs
        'DnsAdmins',  # DNS Admins
        'Group Policy Creator Owners',
        'Protected Users',
        'Remote Desktop Users',
        'Remote Management Users',
    ]
    
    # LDAP matching rule for recursive membership
    LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
    
    class ModuleArgs(BaseModel):
        group: Optional[str] = Field(
            None,
            description="Specific privileged group to search (e.g., 'Domain Admins'). If not specified, searches all privileged groups",
            arg_type=ArgumentType.GROUP
        )
        enabled_only: Optional[bool] = Field(
            False,
            description="Show only enabled accounts",
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
    
    def format_timestamp(self, timestamp):
        """Convert Windows timestamp to readable format"""
        if not timestamp or timestamp == 0:
            return "Never"
        try:
            # Windows epoch: January 1, 1601
            windows_epoch = datetime(1601, 1, 1)
            # Convert 100-nanosecond intervals to seconds
            if isinstance(timestamp, list):
                timestamp = timestamp[0] if timestamp else 0
            seconds = timestamp / 10000000
            dt = windows_epoch + timedelta(seconds=seconds)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError, OverflowError, ZeroDivisionError):
            return "Unknown"
    
    def get_group_members(self, group_name: str):
        """Get all members of a group (recursively)"""
        try:
            # First, find the group
            self.client.search(
                self.domain_dumper.root,
                f'(sAMAccountName={escape_filter_chars(group_name)})',
                SUBTREE,
                attributes=['distinguishedName', 'objectSid']
            )
            
            if len(self.client.entries) == 0:
                return None, []
            
            group_dn = self.client.entries[0].entry_dn
            
            # Find all members (recursively)
            self.client.search(
                self.domain_dumper.root,
                f'(memberOf:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)})',
                SUBTREE,
                attributes=['sAMAccountName', 'distinguishedName', 'objectClass', 'userAccountControl', 
                          'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'description']
            )
            
            members = []
            for entry in self.client.entries:
                # Determine account type
                object_classes = entry.get('objectClass', [])
                if isinstance(object_classes, list):
                    obj_classes_lower = [oc.lower() for oc in object_classes]
                else:
                    obj_classes_lower = [str(object_classes).lower()]
                
                if 'computer' in obj_classes_lower:
                    account_type = 'Computer'
                elif 'user' in obj_classes_lower:
                    account_type = 'User'
                elif 'group' in obj_classes_lower:
                    account_type = 'Group'
                else:
                    account_type = 'Unknown'
                
                # Check if enabled
                uac = entry.get('userAccountControl', [0])[0] if isinstance(entry.get('userAccountControl'), list) else entry.get('userAccountControl', 0)
                is_enabled = not bool(uac & 0x0002)  # ACCOUNTDISABLE flag
                
                # Get last logon
                last_logon = entry.get('lastLogon', [0])[0] if isinstance(entry.get('lastLogon'), list) else entry.get('lastLogon', 0)
                last_logon_ts = entry.get('lastLogonTimestamp', [0])[0] if isinstance(entry.get('lastLogonTimestamp'), list) else entry.get('lastLogonTimestamp', 0)
                
                # Use lastLogonTimestamp if lastLogon is 0
                if last_logon == 0:
                    last_logon = last_logon_ts
                
                # Get description
                description = entry.get('description', [''])[0] if isinstance(entry.get('description'), list) else entry.get('description', '')
                
                members.append({
                    'sam': entry['sAMAccountName'].value,
                    'dn': entry.entry_dn,
                    'type': account_type,
                    'enabled': is_enabled,
                    'last_logon': last_logon,
                    'description': description
                })
            
            return group_dn, members
            
        except Exception as e:
            self.log.debug(f'Error getting members of {group_name}: {str(e)}')
            return None, []
    
    def find_all_privileged_accounts(self):
        """Find all privileged accounts"""
        self.log.info('Searching for privileged accounts...')
        if self.args.enabled_only:
            self.log.info('(enabled only)')
        self.log.info('')
        
        groups_to_search = [self.args.group] if self.args.group else self.PRIVILEGED_GROUPS
        
        for group_name in groups_to_search:
            group_dn, members = self.get_group_members(group_name)
            
            if group_dn is None:
                continue
            
            # Filter by enabled if requested
            if self.args.enabled_only:
                members = [m for m in members if m['enabled']]
            
            if not members:
                continue
            
            self.log.info(f'=== {group_name} ===')
            self.log.info(f'Found {len(members)} member(s):')
            
            for member in members:
                self.log.info(f'  - {member["sam"]} ({member["dn"]})')
                self.log.info(f'    Type: {member["type"]}')
                
                if member['last_logon']:
                    last_logon_str = self.format_timestamp(member['last_logon'])
                    self.log.info(f'    Last logon: {last_logon_str}')
                
                self.log.info(f'    Enabled: {"Yes" if member["enabled"] else "No"}')
                
                if member['description']:
                    self.log.info(f'    Description: {member["description"]}')
            
            self.log.info('')
    
    def __call__(self):
        if self.args.group:
            # Search specific group
            self.log.info(f'Searching for members of: {self.args.group}')
            group_dn, members = self.get_group_members(self.args.group)
            
            if group_dn is None:
                self.log.error(f'Group not found: {self.args.group}')
                return
            
            # Filter by enabled if requested
            if self.args.enabled_only:
                members = [m for m in members if m['enabled']]
            
            if not members:
                self.log.info(f'No members found in {self.args.group}')
                return
            
            self.log.info(f'Found {len(members)} member(s):')
            for member in members:
                self.log.info(f'  - {member["sam"]} ({member["dn"]})')
                self.log.info(f'    Type: {member["type"]}')
                
                if member['last_logon']:
                    last_logon_str = self.format_timestamp(member['last_logon'])
                    self.log.info(f'    Last logon: {last_logon_str}')
                
                self.log.info(f'    Enabled: {"Yes" if member["enabled"] else "No"}')
                
                if member['description']:
                    self.log.info(f'    Description: {member["description"]}')
        else:
            # Search all privileged groups
            self.find_all_privileged_accounts()

