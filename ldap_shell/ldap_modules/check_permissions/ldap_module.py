import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Union
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap3 import SUBTREE

class LdapShellModule(BaseLdapModule):
    """Module for checking permissions on AD objects"""
    
    help_text = "Check what permissions current user has on target AD object. Useful for finding writable groups before privilege escalation."
    examples_text = """
    Check permissions on group 'Backup Operators':
    `check_permissions "Backup Operators"`
    ```
    [INFO] Checking permissions on: Backup Operators
    [INFO] Current user: CN=john.doe,CN=Users,DC=domain,DC=local
    [INFO] Permissions found:
    [INFO]   - GenericAll (0xF01FF) - Full control
    [INFO]   - WriteDacl (0x60034) - Can modify permissions
    [INFO]   - WriteProperty (0x20034) - Can modify properties (including member)
    ```
    
    Check permissions on user:
    `check_permissions john.doe`
    ```
    [INFO] Checking permissions on: john.doe
    [INFO] Current user: CN=john.doe,CN=Users,DC=domain,DC=local
    [INFO] Permissions found:
    [INFO]   - GenericWrite (0x20034) - Can modify user properties
    ```
    
    Check what groups you can modify (OPSEC: queries ALL groups - very noisy!):
    `check_permissions -find-writable-groups`
    
    Check with limit to reduce noise (recommended):
    `check_permissions -find-writable-groups -limit 100`
    ```
    [INFO] OPSEC WARNING: This will query ALL groups in the domain (very noisy!)
    [INFO] Searching for groups you can modify...
    [INFO] Checked 100 groups total
    [INFO] Found 5 writable group(s):
    [INFO]   - Backup Operators (GenericAll)
    [INFO]   - Server Operators (WriteProperty)
    [INFO] Results cached - subsequent calls will use cache (no additional LDAP queries)
    ```
    
    Note: Results are cached per session. Second call uses cache (no LDAP queries).
    """
    module_type = "Get Info"

    # Common permission masks
    PERMISSION_MASKS = {
        0xF01FF: 'GenericAll',
        0x20034: 'GenericWrite',
        0x60034: 'WriteDacl',
        0xA0034: 'WriteOwner',
        0x30034: 'Delete',
        0x20134: 'AllExtendedRights',
    }

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Target object to check permissions on (sAMAccountName or DN). If not specified, searches for writable groups",
            arg_type=[ArgumentType.USER, ArgumentType.GROUP, ArgumentType.COMPUTER, ArgumentType.DN, ArgumentType.STRING]
        )
        find_writable_groups: Optional[bool] = Field(
            False,
            description="Find all groups that current user can modify",
            arg_type=ArgumentType.BOOLEAN
        )
        limit: Optional[Union[int, str]] = Field(
            None,
            description="Limit number of groups to check (OPSEC: reduces LDAP queries). Default: no limit",
            arg_type=ArgumentType.STRING
        )
        
        @field_validator('limit')
        @classmethod
        def validate_limit(cls, v):
            if v is None:
                return None
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                try:
                    return int(v)
                except ValueError:
                    raise ValueError(f'limit must be an integer, got: {v}')
            return v

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        # Cache for writable groups (per session)
        self._writable_groups_cache = None
        # Cache for user groups
        self._user_groups_cache = None
        self.LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'

    def get_current_user_sid(self) -> Optional[str]:
        """Get current user SID"""
        try:
            current_user_info = self.client.extend.standard.who_am_i()
            if not current_user_info:
                return None
            
            # who_am_i() может вернуть DN или формат u:DOMAIN\user
            # Парсим формат u:DOMAIN\user
            if current_user_info.startswith('u:'):
                # Формат: u:DOMAIN\username
                parts = current_user_info[2:].split('\\')
                if len(parts) == 2:
                    sam_account_name = parts[1]
                    # Ищем пользователя по sAMAccountName
                    target_entry = LdapUtils._search_with_retry(
                        self.client,
                        self.domain_dumper,
                        sam_account_name,
                        attributes=['objectSid', 'distinguishedName']
                    )
                    if target_entry and 'objectSid' in target_entry:
                        return target_entry['objectSid'].value
                return None
            else:
                # Это DN, ищем напрямую
                self.client.search(
                    self.domain_dumper.root,
                    f'(distinguishedName={escape_filter_chars(current_user_info)})',
                    attributes=['objectSid'],
                    size_limit=1
                )
                
                if self.client.entries and 'objectSid' in self.client.entries[0]:
                    return self.client.entries[0]['objectSid'].value
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

    def check_permissions_on_object(self, target: str):
        """Check permissions on specific object"""
        # Get target DN
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, target)
        if not target_dn:
            # Try as DN
            if LdapUtils.check_dn(self.client, self.domain_dumper, target):
                target_dn = target
            else:
                self.log.error(f'Target not found: {target}')
                return
        
        self.log.info(f'Checking permissions on: {target}')
        
        # Get current user info
        try:
            current_user_dn = self.client.extend.standard.who_am_i()
            if current_user_dn:
                self.log.info(f'Current user: {current_user_dn}')
        except:
            pass
        
        # Get current user SID
        current_user_sid = self.get_current_user_sid()
        if not current_user_sid:
            self.log.warning('Could not get current user SID, checking all ACEs')
        
        # Get security descriptor
        try:
            self.log.debug(f'Calling get_info_by_dn for: {target_dn}')
            result = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, target_dn)
            self.log.debug(f'get_info_by_dn returned: {result is not None}')
            
            if not result:
                self.log.error('Could not retrieve security descriptor (None returned)')
                self.log.info('This may indicate insufficient permissions to read security descriptor')
                self.log.info('Or the object does not exist at the specified DN')
                return
            
            sd_data, _ = result
            self.log.debug(f'sd_data type: {type(sd_data)}, value: {sd_data is not None}')
            if sd_data:
                self.log.debug(f'sd_data length: {len(sd_data) if hasattr(sd_data, "__len__") else "N/A"}')
            
            # Check if sd_data is valid
            if not sd_data:
                self.log.error('Could not retrieve security descriptor (None returned)')
                self.log.info('This may indicate insufficient permissions to read security descriptor')
                return
            
            # Handle different return types
            try:
                if isinstance(sd_data, list):
                    if len(sd_data) == 0:
                        self.log.error('Could not retrieve security descriptor (empty list)')
                        self.log.info('This may indicate insufficient permissions to read security descriptor')
                        return
                    sd_bytes = sd_data[0]
                elif isinstance(sd_data, bytes):
                    sd_bytes = sd_data
                elif sd_data is None:
                    self.log.error('Could not retrieve security descriptor (None)')
                    self.log.info('This may indicate insufficient permissions to read security descriptor')
                    return
                else:
                    self.log.error(f'Invalid security descriptor format: {type(sd_data)}, expected bytes or list')
                    self.log.debug(f'Actual value: {sd_data}')
                    return
            except (KeyError, IndexError) as idx_error:
                self.log.error(f'Error accessing security descriptor data: {str(idx_error)}')
                self.log.debug(f'Data type: {type(sd_data)}, length: {len(sd_data) if hasattr(sd_data, "__len__") else "N/A"}')
                self.log.info('This may indicate insufficient permissions to read security descriptor')
                return
            
            if not isinstance(sd_bytes, bytes):
                self.log.error(f'Invalid security descriptor format: {type(sd_bytes)}, expected bytes')
                return
            
            try:
                self.log.debug(f'Creating SR_SECURITY_DESCRIPTOR with {len(sd_bytes)} bytes')
                sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
                self.log.debug('SR_SECURITY_DESCRIPTOR created successfully')
            except (KeyError, IndexError) as sd_error:
                self.log.error(f'Error parsing security descriptor (KeyError/IndexError): {str(sd_error)}')
                self.log.debug(f'Security descriptor data length: {len(sd_bytes)} bytes')
                self.log.debug(f'Error type: {type(sd_error).__name__}, args: {sd_error.args}')
                self.log.info('This may indicate corrupted security descriptor or insufficient permissions')
                return
            except Exception as sd_error:
                self.log.error(f'Error parsing security descriptor: {str(sd_error)}')
                self.log.debug(f'Security descriptor data length: {len(sd_bytes)} bytes')
                self.log.debug(f'Error type: {type(sd_error).__name__}, args: {sd_error.args}')
                return
            
            # Check DACL
            found_permissions = []
            try:
                if 'Dacl' in sd and sd['Dacl']:
                    dacl = sd['Dacl']
                    if hasattr(dacl, 'aces') and dacl.aces:
                        # Process ACEs
                        for ace in dacl.aces:
                            try:
                                ace_sid = ace['Ace']['Sid'].formatCanonical()
                                
                                # Check if this ACE is for current user or groups they're in
                                if current_user_sid and ace_sid == current_user_sid:
                                    mask = ace['Ace']['Mask']['Mask']
                                    perm_name = self.PERMISSION_MASKS.get(mask, f'0x{mask:x}')
                                    found_permissions.append({
                                        'sid': ace_sid,
                                        'mask': mask,
                                        'name': perm_name,
                                        'type': 'Direct'
                                    })
                            except (KeyError, IndexError, AttributeError) as e:
                                self.log.debug(f'Error processing ACE: {str(e)}')
                                continue
            except (KeyError, AttributeError) as dacl_error:
                self.log.debug(f'Error accessing Dacl: {str(dacl_error)}')
            
            # Also check owner
            if 'OwnerSid' in sd and sd['OwnerSid']:
                try:
                    owner_sid = sd['OwnerSid'].formatCanonical()
                    if current_user_sid and owner_sid == current_user_sid:
                        found_permissions.append({
                            'sid': owner_sid,
                            'mask': 0xA0034,  # WriteOwner
                            'name': 'Owner',
                            'type': 'Owner'
                        })
                except Exception as e:
                    self.log.debug(f'Error checking owner: {str(e)}')
            
            # Output results
            if found_permissions:
                self.log.info('Permissions found:')
                for perm in found_permissions:
                    self.log.info(f'  - {perm["name"]} (0x{perm["mask"]:x}) - {perm["type"]} permission')
            else:
                self.log.info('No direct permissions found.')
                if current_user_sid:
                    self.log.info('Note: You may have permissions through group membership. Try to modify the object to test.')
                else:
                    self.log.info('Note: Could not determine your SID. Permissions may exist but cannot be verified.')
        
        except Exception as e:
            import traceback
            error_msg = str(e) if e else "Unknown error"
            error_type = type(e).__name__
            error_args = e.args if hasattr(e, 'args') else 'N/A'
            
            if not error_msg or error_msg == "0":
                error_msg = f"Exception type: {error_type}, args: {error_args}"
            
            self.log.error(f'Error checking permissions: {error_msg}')
            
            # For KeyError, provide more context
            if error_type == 'KeyError':
                self.log.error(f'KeyError details: trying to access key/index {error_args}')
                self.log.error('This usually means trying to access [0] on empty list or missing key in dict')
            
            self.log.debug(f'Full traceback: {traceback.format_exc()}')
            
            # Try to provide more context
            if 'sd_data' in locals():
                self.log.debug(f'Security descriptor data type: {type(sd_data) if sd_data else "None"}')
                if sd_data:
                    self.log.debug(f'Security descriptor data length: {len(sd_data) if hasattr(sd_data, "__len__") else "N/A"}')
            if 'target_dn' in locals():
                self.log.debug(f'Target DN: {target_dn}')
            if 'result' in locals():
                self.log.debug(f'get_info_by_dn result: {result}')

    def find_writable_groups(self):
        """Find groups that current user can modify"""
        # Check cache first
        if self._writable_groups_cache is not None:
            self.log.info('Using cached results from previous search...')
            writable_groups = self._writable_groups_cache
            if writable_groups:
                self.log.info(f'Found {len(writable_groups)} writable group(s) (cached):')
                for group in writable_groups[:20]:
                    self.log.info(f'  - {group["name"]} ({group["permission"]})')
                if len(writable_groups) > 20:
                    self.log.info(f'  ... and {len(writable_groups) - 20} more (limited output)')
            else:
                self.log.info('No writable groups found (cached)')
            return
        
        # Warn about noise
        if not self.args.limit:
            self.log.warning('OPSEC WARNING: This will query ALL groups in the domain (very noisy!)')
            self.log.warning('Consider using -limit N to restrict the search (e.g., -limit 100)')
        
        self.log.info('Searching for groups you can modify (this may take a while on large domains)...')
        
        # Get current user SID
        current_user_sid = self.get_current_user_sid()
        if not current_user_sid:
            self.log.error('Could not get current user SID')
            return
        
        self.log.debug(f'Current user SID: {current_user_sid}')
        
        # Get all user groups (for checking permissions via group membership)
        user_groups = self.get_current_user_groups()
        user_group_sids = {g['sid'] for g in user_groups}
        user_group_sids.add(current_user_sid)  # Include user SID too
        self.log.debug(f'Checking permissions for user and {len(user_groups)} groups')
        
        # Search for all groups using pagination
        writable_groups = []
        total_checked = 0
        # Convert limit to int if it's a string (from command line)
        limit = None
        if self.args.limit is not None:
            try:
                limit = int(self.args.limit) if isinstance(self.args.limit, str) else self.args.limit
            except (ValueError, TypeError):
                self.log.error(f'Invalid limit value: {self.args.limit}. Must be an integer.')
                return
        
        try:
            # Use paged search to get all groups (not limited to 1000)
            search_generator = self.client.extend.standard.paged_search(
                search_base=self.domain_dumper.root,
                search_filter='(objectClass=group)',
                attributes=['sAMAccountName', 'distinguishedName', 'nTSecurityDescriptor'],
                paged_size=500,
                generator=True,
                controls=security_descriptor_control(sdflags=0x04)
            )
            
            for entry_dict in search_generator:
                # Skip non-entry results
                if entry_dict.get('type') != 'searchResEntry':
                    continue
                
                # Check limit
                if limit and total_checked >= limit:
                    self.log.info(f'Reached limit of {limit} groups (OPSEC: stopping to reduce noise)')
                    break
                
                entry = entry_dict.get('attributes', {})
                entry_dn = entry_dict.get('dn', '')
                
                total_checked += 1
                if total_checked % 100 == 0:
                    self.log.debug(f'Checked {total_checked} groups, found {len(writable_groups)} writable...')
                
                group_name = entry.get('sAMAccountName', [None])[0] if isinstance(entry.get('sAMAccountName'), list) else entry.get('sAMAccountName')
                if not group_name:
                    continue
                
                # Check if we can modify this group
                # Try to read security descriptor
                try:
                    sd_attr = entry.get('nTSecurityDescriptor', None)
                    if not sd_attr:
                        continue
                    
                    # Get security descriptor data
                    sd_data = None
                    try:
                        if hasattr(sd_attr, 'raw_values') and sd_attr.raw_values:
                            if isinstance(sd_attr.raw_values, list) and len(sd_attr.raw_values) > 0:
                                sd_data = sd_attr.raw_values[0]
                            else:
                                sd_data = sd_attr.raw_values
                        elif hasattr(sd_attr, 'value') and sd_attr.value:
                            sd_data = sd_attr.value
                    except (KeyError, IndexError, AttributeError):
                        continue
                    
                    if not sd_data:
                        continue
                    
                    # Convert to bytes
                    if isinstance(sd_data, bytes):
                        sd_bytes = sd_data
                    elif isinstance(sd_data, list) and len(sd_data) > 0:
                        sd_bytes = sd_data[0] if isinstance(sd_data[0], bytes) else bytes(sd_data[0])
                    else:
                        sd_bytes = bytes(sd_data) if sd_data else None
                    
                    if not sd_bytes:
                        continue
                        
                        sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
                        
                        # Check DACL for permissions
                        has_permission = False
                        permission_type = None
                        granted_via = None
                        
                        if 'Dacl' in sd and sd['Dacl'] and sd['Dacl'].aces:
                            for ace in sd['Dacl'].aces:
                                ace_sid = ace['Ace']['Sid'].formatCanonical()
                                # Check if ACE is for current user or any of their groups
                                if ace_sid in user_group_sids:
                                    mask = ace['Ace']['Mask']['Mask']
                                    # Find which group/user granted this permission
                                    if ace_sid == current_user_sid:
                                        granted_via = 'direct'
                                    else:
                                        # Find group name
                                        group_name_for_ace = next((g['name'] for g in user_groups if g['sid'] == ace_sid), ace_sid)
                                        granted_via = f'group:{group_name_for_ace}'
                                    
                                    if mask & 0xF01FF:  # GenericAll
                                        has_permission = True
                                        permission_type = 'GenericAll'
                                        break  # Found highest permission, no need to check further
                                    elif mask & 0x20034:  # GenericWrite or WriteProperty
                                        has_permission = True
                                        permission_type = 'WriteProperty'
                                    elif mask & 0x60034:  # WriteDacl
                                        has_permission = True
                                        permission_type = 'WriteDacl'
                        
                        # Check owner
                        if not has_permission and 'OwnerSid' in sd and sd['OwnerSid']:
                            owner_sid = sd['OwnerSid'].formatCanonical()
                            if owner_sid in user_group_sids:
                                has_permission = True
                                permission_type = 'Owner'
                                if owner_sid == current_user_sid:
                                    granted_via = 'direct'
                                else:
                                    owning_group_name = next((g['name'] for g in user_groups if g['sid'] == owner_sid), owner_sid)
                                    granted_via = f'group:{owning_group_name}'
                        
                        if has_permission:
                            writable_groups.append({
                                'name': group_name,
                                'dn': entry_dn,
                                'permission': permission_type,
                                'via': granted_via if granted_via else 'direct'
                            })
                except Exception as e:
                    self.log.debug(f'Error checking group {group_name}: {str(e)}')
                    continue
            
            self.log.info(f'Checked {total_checked} groups total')
            
            # Cache results
            self._writable_groups_cache = writable_groups
            
            if writable_groups:
                self.log.info(f'Found {len(writable_groups)} writable group(s):')
                for group in writable_groups[:20]:  # Limit output
                    via_info = f" via {group['via']}" if group.get('via') and group['via'] != 'direct' else ""
                    self.log.info(f'  - {group["name"]} ({group["permission"]}{via_info})')
                if len(writable_groups) > 20:
                    self.log.info(f'  ... and {len(writable_groups) - 20} more (limited output)')
                self.log.info('Results cached - subsequent calls will use cache (no additional LDAP queries)')
            else:
                self.log.info('No writable groups found')
                self.log.info('Tip: Try checking specific groups or use dacl_modify to grant yourself permissions')
                self.log.info('Results cached - subsequent calls will use cache (no additional LDAP queries)')
        
        except Exception as e:
            self.log.error(f'Error searching for groups: {str(e)}')

    def __call__(self):
        if getattr(self.args, 'find_writable_groups', False):
            self.find_writable_groups()
        elif self.args.target:
            self.check_permissions_on_object(self.args.target)
        else:
            self.log.info('No target specified. Use -find-writable-groups to search for writable groups, or provide a target object.')
            self.find_writable_groups()

