import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap3.utils.conv import escape_filter_chars
from datetime import datetime, timedelta

class LdapShellModule(BaseLdapModule):
    """Module for finding users vulnerable to AS-REP Roasting attack (DONT_REQUIRE_PREAUTH)"""
    
    help_text = "Find users with DONT_REQUIRE_PREAUTH flag set (vulnerable to AS-REP Roasting attack)"
    examples_text = """
    Find all users vulnerable to AS-REP Roasting in current domain:
    `get_asreproast`
    ```
    [INFO] Found 3 users vulnerable to AS-REP Roasting:
    [INFO]   - john.doe (CN=john.doe,CN=Users,DC=domain,DC=local)
    [INFO]     Last password change: 2024-01-15 10:30:00
    [INFO]     UserAccountControl: 4194304 (0x400000)
    ```
    
    Find all users in trusted domain:
    `get_asreproast -domain trusted.domain.local`
    ```
    [INFO] Searching in domain: trusted.domain.local (DN: DC=trusted,DC=domain,DC=local)
    [INFO] Found 2 users vulnerable to AS-REP Roasting in domain trusted.domain.local:
    [INFO]   - admin (CN=admin,CN=Users,DC=trusted,DC=domain,DC=local)
    ```
    
    Find specific user in trusted domain:
    `get_asreproast admin -domain trusted.domain.local`
    ```
    [INFO] Searching in domain: trusted.domain.local (DN: DC=trusted,DC=domain,DC=local)
    [INFO] User admin is vulnerable to AS-REP Roasting
    [INFO]   DN: CN=admin,CN=Users,DC=trusted,DC=domain,DC=local
    ```
    
    Note: Searching in trusted domains requires bidirectional or inbound trust.
    Use `get_trusts` to check available trusted domains.
    """
    module_type = "Get Info"

    # DONT_REQUIRE_PREAUTH flag value
    DONT_REQUIRE_PREAUTH = 0x400000  # 4194304

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Specific user to check (sAMAccountName). If not specified, searches for all vulnerable users",
            arg_type=ArgumentType.USER
        )
        domain: Optional[str] = Field(
            None,
            description="Domain to search in (FQDN, e.g., 'trusted.domain.local'). If not specified, searches in current domain",
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
    
    def get_domain_dn(self, domain_fqdn: str) -> str:
        """Convert domain FQDN to DN format"""
        # Convert domain.com to DC=domain,DC=com
        parts = domain_fqdn.split('.')
        dn_parts = [f'DC={part}' for part in parts]
        return ','.join(dn_parts)

    def format_timestamp(self, timestamp):
        """Convert Windows timestamp to readable format"""
        if not timestamp or timestamp == 0:
            return "Never"
        try:
            # Windows epoch: January 1, 1601
            windows_epoch = datetime(1601, 1, 1)
            # Convert 100-nanosecond intervals to seconds
            seconds = timestamp / 10000000
            dt = windows_epoch + timedelta(seconds=seconds)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError, OverflowError):
            return str(timestamp)

    def check_user(self, target: str):
        """Check if specific user is vulnerable"""
        try:
            # Determine search base
            search_base = self.domain_dumper.root
            if self.args.domain:
                search_base = self.get_domain_dn(self.args.domain)
                self.log.info(f'Searching in domain: {self.args.domain} (DN: {search_base})')
            
            self.client.search(
                search_base,
                f'(&(objectClass=user)(sAMAccountName={escape_filter_chars(target)}))',
                attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'distinguishedName']
            )
            
            if not self.client.entries or len(self.client.entries) != 1:
                self.log.error(f'User not found: {target}')
                return
            
            entry = self.client.entries[0]
            uac = entry.get('userAccountControl', 0)
            uac_value = uac.value if uac else 0
            
            if uac_value & self.DONT_REQUIRE_PREAUTH:
                self.log.info(f'User {target} is vulnerable to AS-REP Roasting')
                self.log.info(f'  DN: {entry.entry_dn}')
                
                pwd_last_set = entry.get('pwdLastSet', 0)
                if pwd_last_set:
                    pwd_date = self.format_timestamp(pwd_last_set.value)
                    self.log.info(f'  Last password change: {pwd_date}')
                
                self.log.info(f'  UserAccountControl: {uac_value} (0x{uac_value:x})')
                self.log.info(f'  Flag: DONT_REQUIRE_PREAUTH (0x{self.DONT_REQUIRE_PREAUTH:x})')
            else:
                self.log.info(f'User {target} is NOT vulnerable to AS-REP Roasting')
                self.log.info(f'  UserAccountControl: {uac_value} (0x{uac_value:x})')
        except Exception as e:
            self.log.error(f'Error checking user: {str(e)}')

    def find_all_vulnerable(self):
        """Find all users vulnerable to AS-REP Roasting"""
        try:
            # Determine search base
            search_base = self.domain_dumper.root
            domain_info = ""
            if self.args.domain:
                search_base = self.get_domain_dn(self.args.domain)
                domain_info = f" in domain {self.args.domain}"
                self.log.info(f'Searching in domain: {self.args.domain} (DN: {search_base})')
            
            # Search for users with DONT_REQUIRE_PREAUTH flag
            # Using bitwise filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304)
            # This is LDAP matching rule for bitwise AND
            search_filter = f'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={self.DONT_REQUIRE_PREAUTH}))'
            
            self.log.info(f'Searching for users with DONT_REQUIRE_PREAUTH flag{domain_info}...')
            
            try:
                self.client.search(
                    search_base,
                    search_filter,
                    attributes=['sAMAccountName', 'userAccountControl', 'pwdLastSet', 'distinguishedName'],
                    size_limit=1000
                )
            except Exception as search_error:
                error_msg = str(search_error)
                self.log.error(f'Search failed: {error_msg}')
                
                if 'invalid server address' in error_msg.lower() or 'server' in error_msg.lower():
                    self.log.warning('')
                    self.log.warning('Cannot search in trusted domain through current connection.')
                    self.log.warning('Possible reasons:')
                    self.log.warning('1. Trust is not bidirectional or inbound (check with: get_trusts)')
                    self.log.warning('2. No access through trust relationship')
                    self.log.warning('3. Trusted domain DC is not accessible from current DC')
                    self.log.warning('')
                    self.log.warning('Solutions:')
                    self.log.warning('- Search in current domain only (without -domain parameter)')
                    self.log.warning('- Connect directly to trusted domain DC')
                    self.log.warning('- Check trust direction: get_trusts')
                    self.log.warning('')
                return
            
            if self.client.result['result'] != 0:
                error_desc = self.client.result.get('description', 'Unknown error')
                self.log.error(f'Search failed: {error_desc} (result: {self.client.result["result"]})')
                
                if self.args.domain:
                    self.log.warning('')
                    self.log.warning('Cannot search in trusted domain. Check:')
                    self.log.warning('1. Trust direction (must be bidirectional or inbound): get_trusts')
                    self.log.warning('2. Access rights through trust')
                    self.log.warning('')
                return
            
            vulnerable_users = []
            for entry in self.client.entries:
                sam_account = entry.get('sAMAccountName', '')
                if sam_account:
                    uac = entry.get('userAccountControl', 0)
                    uac_value = uac.value if uac else 0
                    pwd_last_set = entry.get('pwdLastSet', 0)
                    
                    vulnerable_users.append({
                        'name': sam_account.value,
                        'dn': entry.entry_dn,
                        'uac': uac_value,
                        'pwd_last_set': pwd_last_set.value if pwd_last_set else 0
                    })
            
            if vulnerable_users:
                self.log.info(f'Found {len(vulnerable_users)} user(s) vulnerable to AS-REP Roasting:')
                for user in vulnerable_users:
                    self.log.info(f'  - {user["name"]} ({user["dn"]})')
                    if user['pwd_last_set']:
                        pwd_date = self.format_timestamp(user['pwd_last_set'])
                        self.log.info(f'    Last password change: {pwd_date}')
                    self.log.info(f'    UserAccountControl: {user["uac"]} (0x{user["uac"]:x})')
            else:
                self.log.info('No users found with DONT_REQUIRE_PREAUTH flag')
                
        except Exception as e:
            self.log.error(f'Error searching for vulnerable users: {str(e)}')

    def __call__(self):
        if self.args.target:
            self.check_user(self.args.target)
        else:
            self.find_all_vulnerable()

