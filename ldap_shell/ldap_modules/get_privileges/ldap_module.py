import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for finding users/groups with specific Windows privileges or listing all privileges for a user/group"""
    
    help_text = "Find users/groups with specific Windows privileges or list all privileges for a user/group. Works with User Rights Assignment through AD group membership analysis. Note: Local privileges (NT AUTHORITY, local groups) are not visible through LDAP and require host access to check."
    examples_text = """
    List all known privileges:
    `get_privileges`
    ```
    [INFO] Known Windows Privileges:
    [INFO]   SeDebugPrivilege - Debug programs
    [INFO]   SeBackupPrivilege - Back up files and directories
    ...
    ```
    
    List all privileges for user 'john':
    `get_privileges john`
    ```
    [INFO] Privileges for john:
    [INFO]   - SeDebugPrivilege (Debug programs) via Domain Admins
    [INFO]   - SeBackupPrivilege (Back up files and directories) via Domain Admins
    [INFO]   - SeRestorePrivilege (Restore files and directories) via Domain Admins
    ```
    
    Find all users/groups with SeDebugPrivilege:
    `get_privileges SeDebugPrivilege`
    ```
    [INFO] Users/Groups with SeDebugPrivilege (Debug programs):
    [INFO]   - Domain Admins (Group, via Domain Admins)
    [INFO]   - Administrator (User, via Domain Admins)
    ```
    """
    module_type = "Get Info"

    # Windows Privileges mapping
    # Based on User Rights Assignment in Windows
    PRIVILEGES = {
        'SeDebugPrivilege': {
            'name': 'Debug programs',
            'description': 'Allows debugging of processes owned by other users',
            'common_groups': ['Domain Admins', 'Administrators', 'Enterprise Admins']
        },
        'SeBackupPrivilege': {
            'name': 'Back up files and directories',
            'description': 'Allows backing up files and directories',
            'common_groups': ['Domain Admins', 'Administrators', 'Backup Operators', 'Enterprise Admins']
        },
        'SeRestorePrivilege': {
            'name': 'Restore files and directories',
            'description': 'Allows restoring files and directories',
            'common_groups': ['Domain Admins', 'Administrators', 'Backup Operators', 'Enterprise Admins']
        },
        'SeTakeOwnershipPrivilege': {
            'name': 'Take ownership of files or other objects',
            'description': 'Allows taking ownership of objects',
            'common_groups': ['Domain Admins', 'Administrators', 'Enterprise Admins']
        },
        'SeLoadDriverPrivilege': {
            'name': 'Load and unload device drivers',
            'description': 'Allows loading and unloading device drivers',
            'common_groups': ['Administrators']
        },
        'SeSystemtimePrivilege': {
            'name': 'Change the system time',
            'description': 'Allows changing the system time',
            'common_groups': ['Administrators', 'Local Service']
        },
        'SeProfileSingleProcessPrivilege': {
            'name': 'Profile single process',
            'description': 'Allows profiling a single process',
            'common_groups': ['Administrators']
        },
        'SeIncreaseBasePriorityPrivilege': {
            'name': 'Increase scheduling priority',
            'description': 'Allows increasing process priority',
            'common_groups': ['Administrators']
        },
        'SeCreatePagefilePrivilege': {
            'name': 'Create a pagefile',
            'description': 'Allows creating pagefiles',
            'common_groups': ['Administrators']
        },
        'SeIncreaseQuotaPrivilege': {
            'name': 'Adjust memory quotas for a process',
            'description': 'Allows adjusting memory quotas',
            'common_groups': ['Administrators']
        },
        'SeSecurityPrivilege': {
            'name': 'Manage auditing and security log',
            'description': 'Allows managing security logs',
            'common_groups': ['Domain Admins', 'Administrators', 'Enterprise Admins']
        },
        'SeSystemEnvironmentPrivilege': {
            'name': 'Modify firmware environment values',
            'description': 'Allows modifying firmware environment',
            'common_groups': ['Administrators']
        },
        'SeChangeNotifyPrivilege': {
            'name': 'Bypass traverse checking',
            'description': 'Allows bypassing traverse checking',
            'common_groups': ['Everyone', 'Authenticated Users', 'Users']
        },
        'SeRemoteShutdownPrivilege': {
            'name': 'Force shutdown from a remote system',
            'description': 'Allows remote shutdown',
            'common_groups': ['Administrators']
        },
        'SeUndockPrivilege': {
            'name': 'Remove computer from docking station',
            'description': 'Allows undocking',
            'common_groups': ['Users', 'Administrators']
        },
        'SeSyncAgentPrivilege': {
            'name': 'Synchronize directory service data',
            'description': 'Allows synchronizing directory service data',
            'common_groups': ['Domain Admins', 'Enterprise Admins']
        },
        'SeEnableDelegationPrivilege': {
            'name': 'Enable computer and user accounts to be trusted for delegation',
            'description': 'Allows enabling delegation',
            'common_groups': ['Domain Admins', 'Enterprise Admins']
        },
        'SeManageVolumePrivilege': {
            'name': 'Perform volume maintenance tasks',
            'description': 'Allows volume maintenance',
            'common_groups': ['Administrators']
        },
        'SeImpersonatePrivilege': {
            'name': 'Impersonate a client after authentication',
            'description': 'Allows impersonation',
            'common_groups': ['Administrators', 'Service', 'Local Service', 'Network Service']
        },
        'SeCreateGlobalPrivilege': {
            'name': 'Create global objects',
            'description': 'Allows creating global objects',
            'common_groups': ['Administrators', 'Service', 'Local Service', 'Network Service']
        },
        'SeTrustedCredManAccessPrivilege': {
            'name': 'Access Credential Manager as a trusted caller',
            'description': 'Allows accessing credential manager',
            'common_groups': []
        },
        'SeRelabelPrivilege': {
            'name': 'Modify an object label',
            'description': 'Allows modifying object labels',
            'common_groups': []
        },
        'SeIncreaseWorkingSetPrivilege': {
            'name': 'Increase a process working set',
            'description': 'Allows increasing working set',
            'common_groups': []
        },
        'SeTimeZonePrivilege': {
            'name': 'Change the time zone',
            'description': 'Allows changing time zone',
            'common_groups': ['Users']
        },
        'SeCreateSymbolicLinkPrivilege': {
            'name': 'Create symbolic links',
            'description': 'Allows creating symbolic links',
            'common_groups': ['Administrators']
        },
        'SeDelegateSessionUserImpersonatePrivilege': {
            'name': 'Obtain an impersonation token for another user in the same session',
            'description': 'Allows session impersonation',
            'common_groups': []
        }
    }

    # Privilege to SID mapping for well-known groups
    PRIVILEGE_TO_GROUPS = {
        'SeDebugPrivilege': ['S-1-5-32-544', 'S-1-5-21-*-512', 'S-1-5-21-*-519'],  # Administrators, Domain Admins, Enterprise Admins
        'SeBackupPrivilege': ['S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-21-*-512', 'S-1-5-21-*-519'],  # Administrators, Backup Operators, Domain Admins, Enterprise Admins
        'SeRestorePrivilege': ['S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-21-*-512', 'S-1-5-21-*-519'],
        'SeTakeOwnershipPrivilege': ['S-1-5-32-544', 'S-1-5-21-*-512', 'S-1-5-21-*-519'],
        'SeSecurityPrivilege': ['S-1-5-32-544', 'S-1-5-21-*-512', 'S-1-5-21-*-519'],
        'SeSyncAgentPrivilege': ['S-1-5-21-*-512', 'S-1-5-21-*-519'],
        'SeEnableDelegationPrivilege': ['S-1-5-21-*-512', 'S-1-5-21-*-519'],
    }

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="User/group to check privileges for, or privilege name to search (e.g., SeDebugPrivilege). If not specified, lists all known privileges",
            arg_type=[ArgumentType.USER, ArgumentType.GROUP, ArgumentType.COMPUTER, ArgumentType.STRING]
        )
        fast: Optional[bool] = Field(
            False,
            description="Fast mode: check only direct group membership (no recursive search). Faster but may miss nested groups.",
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
        self.LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
        # Cache for group lookups to reduce LDAP queries
        self._group_cache = {}  # Cache for group name -> group info
        self._user_groups_cache = {}  # Cache for user DN -> list of groups

    def get_user_groups(self, user_dn: str, recursive: bool = True) -> list:
        """Get all groups for a user (recursively or direct only) - with caching"""
        # Check cache first
        cache_key = f"{user_dn}:{recursive}"
        if cache_key in self._user_groups_cache:
            cached_groups = self._user_groups_cache[cache_key]
            self.log.debug(f'Using cached groups for user (found {len(cached_groups)} groups)')
            return cached_groups
        
        groups = []
        if recursive:
            self.log.info('Searching for user groups recursively (this may take a moment on large domains)...')
            search_filter = f'(member:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(user_dn)})'
        else:
            self.log.info('Searching for direct group membership (fast mode)...')
            search_filter = f'(member={escape_filter_chars(user_dn)})'
        
        try:
            self.client.search(
                self.domain_dumper.root,
                search_filter,
                attributes=['sAMAccountName', 'objectSid', 'distinguishedName'],
                size_limit=500  # Reduced limit for faster response
            )
            
            if self.client.result['result'] == 0:
                entry_count = len(self.client.entries)
                if entry_count > 0:
                    self.log.info(f'Found {entry_count} groups')
                for entry in self.client.entries:
                    groups.append({
                        'name': entry['sAMAccountName'].value,
                        'sid': entry['objectSid'].value,
                        'dn': entry.entry_dn
                    })
            elif self.client.result['result'] == 4:  # Size limit exceeded
                self.log.warning(f'Group search returned too many results (limited to 500). Some groups may be missing.')
                for entry in self.client.entries:
                    groups.append({
                        'name': entry['sAMAccountName'].value,
                        'sid': entry['objectSid'].value,
                        'dn': entry.entry_dn
                    })
        except Exception as e:
            self.log.warning(f'Error getting groups for user: {str(e)}')
        
        # Cache the result
        self._user_groups_cache[cache_key] = groups
        self.log.debug(f'Cached groups for user (will reuse on next call)')
        
        return groups

    def check_privilege_via_groups(self, privilege: str, groups: list) -> list:
        """Check if privilege is granted via group membership"""
        granted_via = []
        
        # Check well-known groups
        for group in groups:
            group_sid = group['sid']
            group_name = group['name']
            
            # Check if this group typically has this privilege
            if privilege in self.PRIVILEGE_TO_GROUPS:
                for pattern_sid in self.PRIVILEGE_TO_GROUPS[privilege]:
                    # Handle wildcard patterns (e.g., S-1-5-21-*-512 for Domain Admins)
                    if '*' in pattern_sid:
                        prefix = pattern_sid.split('*')[0]
                        suffix = pattern_sid.split('*')[1]
                        if group_sid.startswith(prefix) and group_sid.endswith(suffix):
                            granted_via.append(group_name)
                            break
                    elif group_sid == pattern_sid:
                        granted_via.append(group_name)
                        break
            
            # Also check common groups from PRIVILEGES dict
            if privilege in self.PRIVILEGES:
                if group_name in self.PRIVILEGES[privilege]['common_groups']:
                    if group_name not in granted_via:
                        granted_via.append(group_name)
        
        return granted_via

    def get_privileges_for_user(self, target: str):
        """Get all privileges for a specific user/group/computer"""
        # Use LdapUtils to get DN - it handles computer accounts automatically
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, target)
        if not target_dn:
            self.log.error(f'Target not found: {target}')
            # Try with $ suffix for computer accounts if not already present
            if not target.endswith('$'):
                retry_target = f'{target}$'
                target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, retry_target)
                if target_dn:
                    self.log.info(f'Found computer account: {retry_target}')
                    target = retry_target
                else:
                    return
            else:
                return
        
        # Get object type
        try:
            self.client.search(
                self.domain_dumper.root,
                f'(distinguishedName={escape_filter_chars(target_dn)})',
                attributes=['objectClass', 'sAMAccountName'],
                size_limit=1
            )
            if not self.client.entries:
                self.log.error(f'Could not get object type for: {target}')
                return
            
            entry = self.client.entries[0]
            object_classes = [oc.lower() for oc in entry['objectClass']]
            
            if 'group' in object_classes:
                target_type = 'Group'
            elif 'computer' in object_classes:
                target_type = 'Computer'
            else:
                target_type = 'User'
        except Exception as e:
            self.log.warning(f'Error getting object type: {str(e)}, assuming User')
            target_type = 'User'
        
        self.log.info(f'Analyzing privileges for {target} ({target_type})...')
        # Get all groups (use fast mode if requested)
        # Note: fast mode is not exposed via args yet, but can be added
        groups = self.get_user_groups(target_dn, recursive=not getattr(self.args, 'fast', False))
        
        if not groups:
            self.log.info(f'No groups found for {target}. Checking default privileges...')
            # Still check for privileges that don't require group membership
            groups = []
        
        self.log.info(f'Checking privileges based on {len(groups)} group(s)...')
        
        # Optimize: only check privileges that could be granted via found groups
        # Build set of group names for quick lookup
        group_names = {g['name'] for g in groups}
        group_sids = {g['sid'] for g in groups}
        
        # Check each privilege (optimized - filter by relevant groups)
        found_privileges = []
        checked_count = 0
        
        for privilege in self.PRIVILEGES.keys():
            # Quick check: does this privilege have any common groups that match?
            privilege_groups = set(self.PRIVILEGES[privilege]['common_groups'])
            if not privilege_groups.intersection(group_names):
                # Also check SID patterns
                if privilege in self.PRIVILEGE_TO_GROUPS:
                    # Skip if no matching SID patterns
                    continue
            
            checked_count += 1
            granted_via = self.check_privilege_via_groups(privilege, groups)
            if granted_via:
                found_privileges.append({
                    'privilege': privilege,
                    'via': granted_via
                })
        
        # Output results
        if found_privileges:
            self.log.info(f'Privileges for {target} ({target_type}):')
            for priv_info in found_privileges:
                priv_name = self.PRIVILEGES[priv_info['privilege']]['name']
                via_str = ', '.join(priv_info['via'])
                self.log.info(f'  - {priv_info["privilege"]} ({priv_name}) via {via_str}')
        else:
            self.log.info(f'No special privileges found for {target} via AD groups (only default user privileges)')
            
            # Special note for computer accounts
            if target_type == 'Computer':
                self.log.warning('')
                self.log.warning('NOTE: Computer accounts may have LOCAL privileges on the host machine that are not visible through LDAP.')
                self.log.warning('Local privileges (NT AUTHORITY\\SYSTEM, NT AUTHORITY\\LOCAL SERVICE, etc.) are configured via:')
                self.log.warning('  - Local Security Policy (User Rights Assignment)')
                self.log.warning('  - Group Policy Objects (GPO) applied to the machine')
                self.log.warning('  - Local group membership on the host')
                self.log.warning('')
                self.log.warning('To check LOCAL privileges, you need:')
                self.log.warning('  - Access to the host machine (RDP, WinRM, etc.)')
                self.log.warning('  - Tools like Privileger, whoami /priv, or secedit.exe')
                self.log.warning('  - Or check GPO settings if you have access to SYSVOL')
        
        if checked_count < len(self.PRIVILEGES):
            self.log.debug(f'Optimized: checked {checked_count} relevant privileges out of {len(self.PRIVILEGES)} total')

    def get_group_info(self, group_name: str) -> Optional[dict]:
        """Get group info with caching to reduce LDAP queries"""
        if group_name in self._group_cache:
            return self._group_cache[group_name]
        
        try:
            self.client.search(
                self.domain_dumper.root,
                f'(&(objectClass=group)(sAMAccountName={escape_filter_chars(group_name)}))',
                attributes=['sAMAccountName', 'objectSid', 'distinguishedName'],
                size_limit=1
            )
            if self.client.entries:
                entry = self.client.entries[0]
                group_info = {
                    'name': entry['sAMAccountName'].value,
                    'sid': entry['objectSid'].value,
                    'dn': entry.entry_dn
                }
                self._group_cache[group_name] = group_info
                return group_info
        except Exception as e:
            self.log.debug(f'Error searching for group {group_name}: {str(e)}')
        
        return None

    def find_users_with_privilege(self, privilege: str):
        """Find all users/groups that have a specific privilege"""
        if privilege not in self.PRIVILEGES:
            self.log.error(f'Unknown privilege: {privilege}')
            self.log.info(f'Known privileges: {", ".join(sorted(self.PRIVILEGES.keys()))}')
            return
        
        # Get well-known groups that have this privilege (optimized with caching)
        target_groups = []
        unique_group_names = set()
        
        # Collect all unique group names first
        for group_name in self.PRIVILEGES[privilege]['common_groups']:
            # Skip built-in groups that don't exist in AD
            if group_name not in ['Everyone', 'Authenticated Users', 'Users', 'Local Service', 'Network Service', 'Service']:
                unique_group_names.add(group_name)
        
        # Also add well-known groups from SID patterns
        if privilege in self.PRIVILEGE_TO_GROUPS:
            for pattern_sid in self.PRIVILEGE_TO_GROUPS[privilege]:
                if '*' in pattern_sid:
                    if '512' in pattern_sid:
                        unique_group_names.add('Domain Admins')
                    elif '519' in pattern_sid:
                        unique_group_names.add('Enterprise Admins')
        
        # Single optimized search for all groups at once (if possible)
        if len(unique_group_names) > 1:
            # Build OR filter for multiple groups
            group_filters = [f'(sAMAccountName={escape_filter_chars(name)})' for name in unique_group_names]
            search_filter = f'(&(objectClass=group)(|{"".join(group_filters)}))'
            try:
                self.client.search(
                    self.domain_dumper.root,
                    search_filter,
                    attributes=['sAMAccountName', 'objectSid', 'distinguishedName'],
                    size_limit=len(unique_group_names) + 5
                )
                for entry in self.client.entries:
                    group_name = entry['sAMAccountName'].value
                    if group_name not in [g['name'] for g in target_groups]:
                        target_groups.append({
                            'name': group_name,
                            'sid': entry['objectSid'].value,
                            'dn': entry.entry_dn
                        })
                        # Cache it
                        self._group_cache[group_name] = {
                            'name': group_name,
                            'sid': entry['objectSid'].value,
                            'dn': entry.entry_dn
                        }
            except Exception as e:
                self.log.debug(f'Error in batch group search: {str(e)}')
                # Fallback to individual searches
                for group_name in unique_group_names:
                    group_info = self.get_group_info(group_name)
                    if group_info and group_info not in target_groups:
                        target_groups.append(group_info)
        else:
            # Single group - use cache
            for group_name in unique_group_names:
                group_info = self.get_group_info(group_name)
                if group_info:
                    target_groups.append(group_info)
        
        if not target_groups:
            self.log.info(f'No groups found with {privilege} in this domain')
            return
        
        # Find all members of these groups (recursively)
        # Optimize: limit to first few groups to reduce LDAP queries and noise
        found_objects = {}
        MAX_GROUPS_TO_CHECK = 3  # Limit to reduce LDAP queries
        
        for i, group in enumerate(target_groups[:MAX_GROUPS_TO_CHECK]):
            self.log.debug(f'Searching members of group: {group["name"]} ({i+1}/{min(len(target_groups), MAX_GROUPS_TO_CHECK)})')
            try:
                # Get direct and nested members
                self.client.search(
                    self.domain_dumper.root,
                    f'(member:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group["dn"])})',
                    attributes=['sAMAccountName', 'objectClass', 'distinguishedName'],
                    size_limit=1000  # Reduced from 5000 to be less noisy
                )
                
                if self.client.result['result'] != 0:
                    self.log.warning(f'Search failed for group {group["name"]}: {self.client.result["description"]}')
                    continue
                
                entry_count = len(self.client.entries)
                if entry_count > 0:
                    self.log.debug(f'Found {entry_count} members in group {group["name"]}')
                
                for entry in self.client.entries:
                    obj_name = entry['sAMAccountName'].value
                    obj_type = 'Group' if 'group' in [oc.lower() for oc in entry['objectClass']] else 'User'
                    
                    # Avoid duplicates
                    if obj_name not in found_objects:
                        found_objects[obj_name] = {
                            'name': obj_name,
                            'type': obj_type,
                            'via': [group['name']]
                        }
                    else:
                        # Add additional group if not already listed
                        if group['name'] not in found_objects[obj_name]['via']:
                            found_objects[obj_name]['via'].append(group['name'])
            except Exception as e:
                self.log.warning(f'Error searching members of group {group["name"]}: {str(e)}')
                continue
        
        # Output results
        if found_objects:
            self.log.info(f'Users/Groups with {privilege} ({self.PRIVILEGES[privilege]["name"]}):')
            if len(target_groups) > MAX_GROUPS_TO_CHECK:
                self.log.info(f'Note: Only checked first {MAX_GROUPS_TO_CHECK} groups to reduce LDAP queries. Total groups: {len(target_groups)}')
            for obj_name in sorted(found_objects.keys()):
                obj = found_objects[obj_name]
                via_str = ', '.join(obj['via'])
                self.log.info(f'  - {obj["name"]} ({obj["type"]}, via {via_str})')
        else:
            self.log.info(f'No users/groups found with {privilege} (groups exist but have no members)')

    def list_all_privileges(self):
        """List all known Windows privileges"""
        self.log.info('Known Windows Privileges:')
        for priv_name, priv_info in sorted(self.PRIVILEGES.items()):
            self.log.info(f'  {priv_name} - {priv_info["name"]}')
            if priv_info['description']:
                self.log.info(f'    Description: {priv_info["description"]}')
            if priv_info['common_groups']:
                self.log.info(f'    Common groups: {", ".join(priv_info["common_groups"])}')
            self.log.info('')  # Empty line for readability

    def __call__(self):
        # If no target specified, list all privileges
        if not self.args.target:
            self.list_all_privileges()
            return
        
        # Check if target is a known privilege name
        if self.args.target in self.PRIVILEGES:
            # Search for users/groups with this privilege
            self.find_users_with_privilege(self.args.target)
            return
        
        # Otherwise, treat as user/group name and get their privileges
        self.get_privileges_for_user(self.args.target)

