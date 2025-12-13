Предложения новых модулей
Get Info (разведка)
get_delegation — найти объекты с делегированием
Unconstrained Delegation (userAccountControl: TRUSTED_FOR_DELEGATION)
Constrained Delegation (msDS-AllowedToDelegateTo)
Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
Вывод: тип делегирования, целевые сервисы, кто может делегировать
get_asreproast — найти пользователей для AS-REP Roasting
Фильтр: DONT_REQUIRE_PREAUTH
Вывод: sAMAccountName, DN, когда последний раз меняли пароль
get_kerberoast — найти пользователей для Kerberoasting
Фильтр: servicePrincipalName=*
Вывод: SPN, sAMAccountName, когда последний раз меняли пароль
get_trusts — получить информацию о доверительных отношениях
Атрибуты: trustDirection, trustType, trustAttributes
Вывод: список доверий, направление, тип, атрибуты
get_privileged_accounts — найти привилегированные аккаунты
Фильтр: adminCount=1 или членство в DA/EA/BA
Вывод: список, группы, когда последний вход
get_unconstrained_delegation — компьютеры с Unconstrained Delegation
Фильтр: userAccountControl содержит TRUSTED_FOR_DELEGATION
Вывод: список компьютеров, последний вход, IP
get_constrained_delegation — объекты с Constrained Delegation
Фильтр: msDS-AllowedToDelegateTo не пусто
Вывод: объект, целевые сервисы, тип (user/computer)
get_password_policy — политика паролей домена
Атрибуты: minPwdLength, pwdHistoryLength, lockoutThreshold, maxPwdAge, minPwdAge
Вывод: параметры политики
get_sid_history — объекты с SID History
Фильтр: sIDHistory не пусто
Вывод: объект, старые SID
get_sensitive_accounts — чувствительные аккаунты
Фильтр: adminCount=1, servicePrincipalName, trustedForDelegation
Вывод: список с категориями
get_never_expire — аккаунты с never expire password
Фильтр: userAccountControl содержит DONT_EXPIRE_PASSWORD
Вывод: список пользователей/компьютеров
get_inactive_accounts — неактивные аккаунты
Фильтр: lastLogonTimestamp старше N дней
Параметр: days (по умолчанию 90)
Вывод: список, дата последнего входа
get_service_accounts — сервисные аккаунты
Фильтр: servicePrincipalName=* или description содержит "service"
Вывод: список, SPN, описание
get_computer_os — информация об ОС компьютеров
Атрибуты: operatingSystem, operatingSystemVersion, operatingSystemServicePack
Вывод: список компьютеров с версиями ОС
get_last_logon — последний вход пользователей/компьютеров
Атрибуты: lastLogon, lastLogonTimestamp
Вывод: список с датами
get_primary_group — primary group для пользователя
Атрибут: primaryGroupID
Вывод: группа, SID, DN
get_ou_permissions — права на OU
Атрибут: nTSecurityDescriptor
Вывод: ACE, кто имеет права, какие права
get_gpo — информация о GPO
Поиск: CN=Policies,CN=System
Вывод: список GPO, имя, DN, когда изменяли
get_dns_zones — DNS зоны (если доступны)
Поиск: CN=MicrosoftDNS,CN=System
Вывод: список зон, записи
get_schema_extensions — расширения схемы
Поиск: CN=Schema,CN=Configuration
Вывод: кастомные классы/атрибуты
Abuse ACL (эксплуатация)
set_unconstrained_delegation — включить Unconstrained Delegation
Параметры: target (computer), action (add/del)
Логика: добавить/удалить TRUSTED_FOR_DELEGATION в userAccountControl
set_constrained_delegation — настроить Constrained Delegation
Параметры: target, grantee, services (список SPN)
Логика: добавить в msDS-AllowedToDelegateTo
set_sid_history — добавить SID History (требует права)
Параметры: target, sid_to_add
Логика: добавить SID в sIDHistory
set_primary_group — изменить primary group
Параметры: target, group
Логика: изменить primaryGroupID
set_description — изменить описание объекта
Параметры: target, description
Логика: изменить description
set_script_path — изменить script path (logon script)
Параметры: target, script_path
Логика: изменить scriptPath
set_home_directory — изменить home directory
Параметры: target, home_dir
Логика: изменить homeDirectory, homeDrive
set_profile_path — изменить profile path
Параметры: target, profile_path
Логика: изменить profilePath
set_trusted_for_delegation — включить TrustedForDelegation (legacy)
Параметры: target, action (add/del)
Логика: модификация userAccountControl
set_sensitive_never_expire — установить флаги sensitive + never expire
Параметры: target
Логика: установить adminCount=1 и DONT_EXPIRE_PASSWORD
Misc (утилиты)
move_object — переместить объект в другую OU
Параметры: target, target_ou
Логика: изменить DN через move операцию
rename_object — переименовать объект
Параметры: target, new_name
Логика: изменить CN через modifyDN
set_expiration — установить срок действия аккаунта
Параметры: target, expiration_date
Логика: изменить accountExpires
unlock_account — разблокировать аккаунт
Параметры: target
Логика: удалить LOCKOUT из userAccountControl
reset_bad_pwd_count — сбросить счетчик неудачных попыток
Параметры: target
Логика: установить badPwdCount=0
set_password_never_expires — установить never expire для пароля
Параметры: target, action (add/del)
Логика: модификация userAccountControl через uac_modify логику
get_object_permissions — получить права на объект (детально)
Параметры: target
Вывод: полный разбор nTSecurityDescriptor, все ACE с расшифровкой
find_interesting_permissions — найти интересные права
Параметры: target (опционально)
Логика: поиск GenericAll, WriteDacl, WriteOwner, DCSync, RBCD на всех объектах
Вывод: список объектов с интересными правами
get_group_membership_recursive — рекурсивное членство в группах
Параметры: user
Логика: рекурсивный обход всех групп (включая вложенные)
Вывод: дерево групп
export_object — экспорт объекта в LDIF
Параметры: target, output_file (опционально)
Логика: экспорт всех атрибутов в LDIF формат
Приоритетные модули для реализации
Топ-10 по полезности:
get_delegation — критично для тестирования делегирования
get_asreproast — классический вектор атаки
get_kerberoast — классический вектор атаки
get_privileged_accounts — быстрая разведка
get_unconstrained_delegation — важный вектор
find_interesting_permissions — поиск векторов эскалации
get_trusts — разведка междоменных отношений
set_unconstrained_delegation — эксплуатация
get_inactive_accounts — поиск заброшенных аккаунтов
get_object_permissions — детальный анализ прав
Хвост от старика
Начни с get_delegation — объединяет несколько типов делегирования в один модуль
get_asreproast и get_kerberoast — стандартные векторы, часто нужны
find_interesting_permissions — полезен для поиска векторов эскалации
get_trusts — важен для междоменной разведки
Для эксплуатации: set_unconstrained_delegation и set_constrained_delegation
get_privileged_accounts — быстрый способ найти DA/EA/BA
get_inactive_accounts — поиск заброшенных аккаунтов для переиспользования
get_object_permissions — детальный разбор прав на объект
get_password_policy — полезно для понимания политик
move_object и rename_object — базовые операции, которых не хватает

get_asreproast +
check_permissions +
get_privileges +
set_privilege +