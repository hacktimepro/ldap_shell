import logging
from ldap3 import Connection, SUBTREE, MODIFY_ADD
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, Union
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for adding new groups to Active Directory"""

    help_text = "Add new group to Active Directory or find containers where you can create groups"
    examples_text = """
    Add a new group to default location (CN=Users)
    `add_group "Test Group"`

    Add a new group to specific OU
    `add_group "Test Group" "OU=testOU,DC=roasting,DC=lab"`
    
    Find all containers/OUs where you can create groups (OPSEC: very noisy!)
    `add_group -find-writable-containers`
    
    Find with limit to reduce noise:
    `add_group -find-writable-containers -limit 50`
    ```
    [INFO] OPSEC WARNING: This will query ALL containers/OUs in the domain (very noisy!)
    [INFO] Searching for containers where you can create groups...
    [INFO]   Found writable container: Users (CN=Users,DC=domain,DC=local)
    [INFO] Checked 50 container(s) total
    [INFO] Found 1 writable container(s) where you can create groups:
    [INFO]   - Users (CN=Users,DC=domain,DC=local)
    [INFO] 
    [INFO] Example usage:
    [INFO]   add_group "MyGroup" "CN=Users,DC=domain,DC=local"
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        group_name: Optional[str] = Field(
            None,
            description="Name of the group to create",
            arg_type=[ArgumentType.STRING]
        )
        target_dn: Optional[str] = Field(
            None,
            description="Target OU where to create the group (optional)",
            arg_type=[ArgumentType.DN]
        )
        find_writable_containers: Optional[bool] = Field(
            False,
            description="Find all containers/OUs where you can create groups",
            arg_type=ArgumentType.BOOLEAN
        )
        limit: Optional[Union[int, str]] = Field(
            None,
            description="Limit number of containers to check (OPSEC: reduces LDAP queries)",
            arg_type=ArgumentType.STRING
        )
    
    # LDAP matching rule for recursive group membership
    LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        self._user_groups_cache = None  # Cache for user groups

    def get_current_user_sid(self):
        """Get current user SID"""
        try:
            who_am_i = self.client.extend.standard.who_am_i()
            if not who_am_i:
                return None
            
            # Parse who_am_i output (format: u:DOMAIN\user or just DN)
            if who_am_i.startswith('u:'):
                user_str = who_am_i[2:]
                if '\\' in user_str:
                    domain, username = user_str.split('\\', 1)
                else:
                    username = user_str
            else:
                # It's a DN, extract username
                username = LdapUtils.get_name_from_dn(who_am_i)
            
            # Get SID
            return LdapUtils.get_sid(self.client, self.domain_dumper, username)
        except Exception as e:
            self.log.debug(f'Error getting current user SID: {str(e)}')
            return None
    
    def get_current_user_groups(self) -> list:
        """Get all groups for current user (recursively) with SIDs"""
        # Check cache
        if self._user_groups_cache is not None:
            return self._user_groups_cache
        
        # Get current user DN first
        try:
            current_user_info = self.client.extend.standard.who_am_i()
            if not current_user_info:
                return []
            
            # Parse who_am_i format
            if current_user_info.startswith('u:'):
                parts = current_user_info[2:].split('\\')
                if len(parts) == 2:
                    sam_account_name = parts[1]
                    target_entry = LdapUtils._search_with_retry(
                        self.client,
                        self.domain_dumper,
                        sam_account_name,
                        attributes=['distinguishedName', 'objectSid']
                    )
                    if not target_entry:
                        return []
                    user_dn = target_entry.entry_dn
                else:
                    return []
            else:
                user_dn = current_user_info
            
            # Get groups recursively
            self.log.debug('Getting user groups recursively...')
            search_filter = f'(member:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(user_dn)})'
            
            groups = []
            try:
                self.client.search(
                    self.domain_dumper.root,
                    search_filter,
                    attributes=['sAMAccountName', 'objectSid', 'distinguishedName'],
                    size_limit=1000
                )
                
                if self.client.result['result'] == 0:
                    for entry in self.client.entries:
                        if 'objectSid' in entry and 'sAMAccountName' in entry:
                            groups.append({
                                'name': entry['sAMAccountName'].value,
                                'sid': entry['objectSid'].value,
                                'dn': entry.entry_dn
                            })
            except Exception as e:
                self.log.debug(f'Error getting user groups: {str(e)}')
            
            # Cache result
            self._user_groups_cache = groups
            self.log.debug(f'Found {len(groups)} groups for current user')
            return groups
            
        except Exception as e:
            self.log.debug(f'Error getting current user groups: {str(e)}')
            return []
    
    def check_create_child_permission(self, container_dn: str, object_type: str = 'group') -> bool:
        """Check if current user can create child objects (groups) in container"""
        try:
            # Get security descriptor
            result = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, container_dn)
            if not result:
                return False
            
            sd_data, _ = result
            if not sd_data:
                return False
            
            # Parse security descriptor
            if isinstance(sd_data, list):
                if len(sd_data) == 0:
                    return False
                sd_bytes = sd_data[0]
            elif isinstance(sd_data, bytes):
                sd_bytes = sd_data
            else:
                return False
            
            if not isinstance(sd_bytes, bytes):
                return False
            
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
            except Exception:
                return False
            
            # Get current user SID
            current_user_sid = self.get_current_user_sid()
            if not current_user_sid:
                return False
            
            # Get user groups (for checking group-based permissions)
            user_groups = self.get_current_user_groups()
            user_group_sids = {g['sid'] for g in user_groups}
            
            # Check DACL
            if 'Dacl' not in sd or not sd['Dacl']:
                return False
            
            dacl = sd['Dacl']
            if not hasattr(dacl, 'aces') or not dacl.aces:
                return False
            
            # Object type GUID for groups: bf967a9c-0de6-11d0-a285-00aa003049e2
            # CreateChild right: 0x00000001
            CREATE_CHILD = 0x00000001
            GENERIC_ALL = 0xF01FF
            GENERIC_WRITE = 0x20034
            
            for ace in dacl.aces:
                try:
                    # Check if ACE applies to current user or their groups
                    ace_sid = ace['Ace']['Sid'].formatCanonical()
                    if ace_sid != current_user_sid and ace_sid not in user_group_sids:
                        continue
                    
                    # Check access mask
                    access_mask = ace['Ace']['Mask']['Mask']
                    
                    # Check for GenericAll, GenericWrite, or CreateChild
                    if (access_mask & GENERIC_ALL) or (access_mask & GENERIC_WRITE) or (access_mask & CREATE_CHILD):
                        return True
                except (KeyError, IndexError, AttributeError):
                    continue
            
            return False
        except Exception as e:
            self.log.debug(f'Error checking CreateChild permission: {str(e)}')
            return False
    
    def find_writable_containers(self):
        """Find containers/OUs where current user can create groups"""
        self.log.info('OPSEC WARNING: This will query ALL containers/OUs in the domain (very noisy!)')
        self.log.info('Searching for containers where you can create groups...')
        
        limit = None
        if self.args.limit:
            if isinstance(self.args.limit, str):
                try:
                    limit = int(self.args.limit)
                except ValueError:
                    self.log.error(f'Invalid limit value: {self.args.limit}')
                    return
            else:
                limit = self.args.limit
        
        # Search for containers and OUs
        # objectClass: container, organizationalUnit, builtinDomain, domainDNS
        filter_str = '(|(objectClass=container)(objectClass=organizationalUnit)(objectClass=builtinDomain)(objectClass=domainDNS))'
        
        writable_containers = []
        checked_count = 0
        
        try:
            search_generator = self.client.extend.standard.paged_search(
                self.domain_dumper.root,
                filter_str,
                SUBTREE,
                attributes=['distinguishedName', 'name', 'objectClass'],
                paged_size=100,
                generator=False
            )
            
            for entry_dict in search_generator:
                if entry_dict.get('type') != 'searchResEntry':
                    continue
                
                entry = entry_dict.get('attributes', {})
                if not entry:
                    continue
                
                # Get distinguishedName
                dn_attr = entry.get('distinguishedName')
                if not dn_attr:
                    continue
                
                if isinstance(dn_attr, list):
                    if len(dn_attr) == 0:
                        continue
                    container_dn = dn_attr[0]
                else:
                    container_dn = dn_attr
                
                if not container_dn:
                    continue
                
                checked_count += 1
                if limit and checked_count > limit:
                    break
                
                # Check CreateChild permission
                if self.check_create_child_permission(container_dn, 'group'):
                    # Get name
                    name_attr = entry.get('name')
                    if name_attr:
                        if isinstance(name_attr, list):
                            name = name_attr[0] if len(name_attr) > 0 else container_dn
                        else:
                            name = name_attr
                    else:
                        name = container_dn
                    
                    writable_containers.append({
                        'dn': container_dn,
                        'name': name
                    })
                    self.log.info(f'  Found writable container: {name} ({container_dn})')
            
            self.log.info(f'Checked {checked_count} container(s) total')
            
            if writable_containers:
                self.log.info(f'Found {len(writable_containers)} writable container(s) where you can create groups:')
                for container in writable_containers:
                    self.log.info(f'  - {container["name"]} ({container["dn"]})')
                self.log.info('')
                self.log.info('Example usage:')
                if writable_containers:
                    example_dn = writable_containers[0]['dn']
                    self.log.info(f'  add_group "MyGroup" "{example_dn}"')
            else:
                self.log.warning('No writable containers found. You cannot create groups with current credentials.')
                self.log.warning('Required: Create Group Objects (CreateChild) permission on container')
                self.log.warning('Default: Authenticated Users can create groups in CN=Users')
        except Exception as e:
            self.log.error(f'Error searching for containers: {str(e)}')
    
    def __call__(self):
        # If find_writable_containers is requested
        if self.args.find_writable_containers:
            self.find_writable_containers()
            return
        
        # Validate group_name is provided
        if not self.args.group_name:
            self.log.error('Group name is required (or use -find-writable-containers to search for writable containers)')
            return
        
        # Check if group already exists
        self.client.search(
            self.domain_dumper.root,
            f'(&(objectClass=group)(sAMAccountName={self.args.group_name}))',
            SUBTREE,
            attributes=['distinguishedName']
        )
        
        if len(self.client.entries) > 0:
            self.log.error(f"Group {self.args.group_name} already exists")
            return

        # Form DN for new group
        if self.args.target_dn:
            group_dn = f"CN={self.args.group_name},{self.args.target_dn}"
        else:
            group_dn = f"CN={self.args.group_name},CN=Users,{self.domain_dumper.root}"

        # Attributes for group creation
        group_attributes = {
            'objectClass': ['top', 'group'],
            'cn': self.args.group_name,
            'name': self.args.group_name,
            'sAMAccountName': self.args.group_name,
            'displayName': self.args.group_name,
            'description': f"Group created via ldap_shell"
        }

        # Create group
        try:
            result = self.client.add(group_dn, attributes=group_attributes)
            if result:
                self.log.info(f"Group {self.args.group_name} created successfully at {group_dn}")
            else:
                error_msg = self.client.result.get('description', 'Unknown error') if isinstance(self.client.result, dict) else str(self.client.result)
                error_code = self.client.result.get('result', 'N/A') if isinstance(self.client.result, dict) else 'N/A'
                self.log.error(f"Failed to create group {self.args.group_name}: {error_msg} (code: {error_code})")
                
                # Provide helpful suggestions
                if 'insufficient' in error_msg.lower() or 'access' in error_msg.lower() or error_code == 50:
                    self.log.warning('')
                    self.log.warning('Insufficient rights to create group.')
                    self.log.warning('Required permissions:')
                    self.log.warning('1. Create Group Objects (CreateChild) on target container')
                    self.log.warning('   - Default: Authenticated Users can create groups in CN=Users')
                    self.log.warning('   - Or: Domain Admins, Account Operators have full rights')
                    self.log.warning('2. Write properties on group object (for name, description, etc.)')
                    self.log.warning('')
                    self.log.warning('Possible solutions:')
                    self.log.warning(f'1. Check your permissions on target container:')
                    if self.args.target_dn:
                        self.log.warning(f'   check_permissions "{self.args.target_dn}"')
                    else:
                        self.log.warning(f'   check_permissions "CN=Users,{self.domain_dumper.root}"')
                    self.log.warning('2. Find writable containers:')
                    self.log.warning('   add_group -find-writable-containers')
                    self.log.warning('3. Use elevated credentials (Domain Admins, Account Operators)')
                    self.log.warning('')
        except Exception as e:
            error_msg = str(e)
            self.log.error(f'Error creating group: {error_msg}')
            if 'insufficient' in error_msg.lower() or 'access' in error_msg.lower():
                self.log.warning('')
                self.log.warning('Insufficient rights to create group.')
                self.log.warning('Required: Create Group Objects permission on target container')
                self.log.warning('Default: Authenticated Users can create groups in CN=Users')
                self.log.warning('Find writable containers: add_group -find-writable-containers')
                self.log.warning('')