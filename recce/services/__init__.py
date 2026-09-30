"""Per-service deep enumeration.

Each service module (smb, ldap, ftp, snmp, ...) knows one wire protocol
and one enumeration playbook. Database engines are grouped under
services.db/ because they share dispatch (services.db.__init__ owns the
port/service→module mapping) and a common finding-builder pattern.

Currently only services.db/ has moved in from the flat top level; the
other services (smb/ldap/ftp/...) will follow in later restructure
commits. Backward-compat shims at recce/mysql.py etc. re-export the
new locations via sys.modules aliasing so no callsite has to move.
"""
