"""Static lookup tables for path/param/CMS/cloud wordlists.

Extracted from web.py. Every entry is re-exported through
web/__init__.py's wildcard import so `from recce.services.web import X`
keeps working for the split names too."""
from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlparse

from ...core.models import Host, Port, Vuln
from .. import probes
from ...core import proxy


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403

__all__ = ['_WORDLIST_ADMIN', '_WORDLIST_CONFIG', '_WORDLIST_INFO_DISCLOSURE', '_WORDLIST_SOURCE_CODE', '_WORDLIST_AUTH_ENDPOINTS', '_WORDLIST_API', '_WORDLIST_DATA_EXPOSURE', '_WORDLIST_TRAVERSAL', '_WORDLIST_UPLOAD', '_WORDLIST_FRAMEWORK_PATHS', '_WORDLIST_VCS', '_WORDLIST_DEBUG', '_WORDLIST_SUBDOMAINS', '_WORDLIST_PARAMETERS', '_WORDLIST_HEADERS', '_WORDLIST_CMS_PATHS', '_WORDLIST_CLOUD_PATHS', '_WORDLIST_EXTENSIONS', '_WORDLIST_BYPASS_ENCODING', '_WORDLIST_USER_ENUM', '_WORDLIST_PRIV_ESC', '_WORDLIST_MOBILE_API', '_WORDLIST_EXPORT_DOWNLOAD', '_WORDLIST_SQL_INJECTION_PATTERNS', '_WORDLIST_XSS_VECTORS', 'wordlist_for_gobuster', 'wordlist_for_domain_enum', 'wordlist_for_vcs_disclosure', 'wordlist_get_framework_paths', 'wordlist_get_parameters', 'wordlist_get_headers', 'wordlist_get_cms_paths', 'wordlist_get_cloud_paths', 'wordlist_get_extensions', 'wordlist_get_bypasses', 'wordlist_get_payloads']



_WORDLIST_ADMIN = [
    "admin", "administrator", "admin-login", "admin_login", "admin/login",
    "adminpanel", "admin-panel", "admin_panel", "adm", "admins", "admin.php",
    "wp-admin", "wp-login", "wp-login.php", "wp-admin/", "wp-json",
    "administrator/", "admin.asp", "admin.html", "admin.aspx",
    "manager", "management", "console", "control", "dashboard",
    "master", "operator", "supervisor", "root", "superuser",
]



_WORDLIST_CONFIG = [
    ".env", ".env.local", ".env.example", "config.php", "config.json",
    "settings.php", "settings.xml", "settings.py", "settings.ini",
    "app.config", "web.config", "web.xml", ".htaccess", ".htpasswd",
    "config/", "conf/", ".git", ".git/config", ".gitignore",
    "dockerfile", "docker-compose.yml", ".dockerignore",
    ".github/", ".gitlab-ci.yml", ".travis.yml", "jenkinsfile",
    "package.json", "package-lock.json", "yarn.lock", "composer.json",
    "requirements.txt", "Pipfile", "Gemfile", "pom.xml", "build.gradle",
    ".env.production", ".env.staging", ".env.development",
    "credentials.json", "secrets.json", "apikeys.json",
]



_WORDLIST_INFO_DISCLOSURE = [
    "robots.txt", "sitemap.xml", "humans.txt", ".well-known/",
    "readme.md", "readme.txt", "readme.html", "changelog", "changelog.txt",
    "license", "license.txt", "AUTHORS", "CONTRIBUTORS", "HISTORY",
    ".DS_Store", "thumbs.db", ".swp", ".swo", "*.bak", "*.tmp",
    "test", "staging", "dev", "development", "demo", "debug",
    "backup", "backups", "old", "archive", "previous", "legacy",
    "temp", "tmp", "cache", ".cache", "logs", "log", ".log",
    "version", "VERSION", "version.txt", "build", "build.txt",
]



_WORDLIST_SOURCE_CODE = [
    "src/", "source/", "sources/", "code/", "codes/",
    "lib/", "libs/", "library/", "libraries/", "modules/",
    "views/", "models/", "controllers/", "components/",
    "assets/", "static/", "public/", "resources/",
    "app/", "application/", "main/", "core/",
    "utils/", "helpers/", "includes/", "functions/",
    "js/", "css/", "images/", "fonts/", "media/",
]



_WORDLIST_AUTH_ENDPOINTS = [
    "login", "signin", "auth", "authenticate", "auth/login",
    "user/login", "account/login", "session/new",
    "logout", "signout", "logoff", "exit",
    "register", "signup", "join", "register.php",
    "forgot", "forgot-password", "reset-password", "password-reset",
    "profile", "user/profile", "account/profile", "settings",
    "change-password", "update-password", "security",
]



_WORDLIST_API = [
    "api", "api/", "api/v1", "api/v2", "api/v3",
    "v1/", "v2/", "v3/", "v4/", "v5/",
    "graphql", "api/graphql", "graph",
    "rest", "soap", "rpc",
    "webhook", "webhooks",
    "client", "clients", "customers", "users", "accounts",
    "products", "items", "posts", "articles", "data",
    "endpoint", "endpoints", "action", "method",
]



_WORDLIST_DATA_EXPOSURE = [
    "database", "databases", "db/", "data/", "dataset/",
    "export", "download", "backup", "dump",
    "credentials", "secrets", "keys", "tokens",
    "user", "users", "profile", "profiles",
    "admin", "superuser", "root",
    "email", "password", "hash", "salt",
    "config", "setting", "option",
    "sql", "db", "postgres", "mysql", "mongodb",
]



_WORDLIST_TRAVERSAL = [
    "../", "../../", "../../../",
    "..%2f", "..%252f", "..%5c",
    "....//", "..%5c%5c", "..%c0%af",
    "%2e%2e%2f", "%252e%252e%252f",
    "etc/passwd", "etc/shadow", "etc/hosts",
    "proc/self/environ", "proc/self/cwd",
    "windows/win.ini", "windows/system32/drivers/etc/hosts",
    "bootini", "boot.ini",
]



_WORDLIST_UPLOAD = [
    "upload", "uploads", "upload/", "upload.php",
    "file", "files", "file/", "file_upload",
    "media", "image", "images", "photo", "photos",
    "document", "documents", "attachment", "attachments",
    "archive", "archives", "zip", "archive.php",
    "form", "forms", "form_upload", "form.php",
]



_WORDLIST_FRAMEWORK_PATHS = {
    "wordpress": ["wp-content", "wp-includes", "wp-json", "wp-admin", "wp-login.php"],
    "drupal": ["sites/", "modules/", "themes/", "admin/", "node/", "user/"],
    "joomla": ["administrator", "components", "modules", "plugins", "templates", "media"],
    "laravel": ["app/", "bootstrap/", "config/", "storage/", "routes/", "artisan"],
    "django": ["admin/", "api/", "static/", "media/", "templates/", "migrations/"],
    "rails": ["app/", "config/", "db/", "public/", "vendor/", "assets/"],
    "asp.net": ["App_Data/", "App_Code/", "Bin/", "Content/", "Scripts/", "Views/"],
    "php": ["index.php", "admin.php", "config.php", "includes/", "classes/"],
    "nodejs": ["node_modules/", "public/", "routes/", "views/", "server.js", "app.js"],
}



_WORDLIST_VCS = [
    ".git", ".git/", ".git/config", ".git/HEAD", ".git/objects",
    ".gitignore", ".github/", ".gitlab-ci.yml",
    ".svn", ".svn/", ".hg", ".hg/", ".bzr", ".bzr/",
    "CVS", "CVS/",
]



_WORDLIST_DEBUG = [
    "debug", "debug.php", "debug.asp", "test.php", "test.asp",
    "phpinfo.php", "info.php", "test.html", "trace.php",
    "status", "status.php", "health", "health.php", "ping", "ping.php",
    "metrics", "stats", "statistics",
]


_WORDLIST_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "api", "v1", "v2", "v3", "v4",
    "admin", "test", "dev", "staging", "production", "prod", "uat",
    "app", "apps", "console", "control", "cpanel", "webmin", "cPanel",
    "blog", "news", "shop", "store", "cart", "checkout", "ecommerce",
    "cdn", "static", "assets", "download", "download-server", "files",
    "cache", "proxy", "vpn", "gateway", "tunnel", "bastion",
    "db", "database", "mysql", "postgres", "mongodb", "redis", "elastic",
    "smtp", "mail", "mail2", "pop3", "imap", "exchange", "outlook",
    "ldap", "ad", "active-directory", "directory", "iam",
    "vpn", "wireguard", "openvpn", "ssh", "telnet", "rds",
    "jenkins", "ci", "cd", "build", "deploy", "deployment",
    "git", "gitlab", "github", "bitbucket", "svn", "scm", "repo",
    "sonarqube", "artifactory", "nexus", "jira", "confluence", "wiki",
    "grafana", "prometheus", "kibana", "elasticsearch", "logstash", "logs",
    "vault", "consul", "etcd", "zookeeper", "keycloak",
    "kubernetes", "k8s", "docker", "swarm", "nomad",
    "rabbitmq", "kafka", "redis", "memcached", "queue",
    "influxdb", "timeseries", "metrics", "monitoring",
    "analytics", "tracking", "telemetry", "mixpanel", "amplitude",
    "internal", "private", "local", "intranet", "extranet",
    "backup", "backups", "staging-backup", "dev-backup",
    "old", "legacy", "archive", "sandbox", "test-env",
    "s3", "s3-backup", "bucket", "gcs", "azure-blob",
    "health", "healthcheck", "status", "ping", "heartbeat",
]



_WORDLIST_PARAMETERS = [
    "id", "uid", "user_id", "userid", "pid", "product_id", "order_id",
    "email", "username", "user", "pass", "password", "pwd", "secret",
    "key", "apikey", "api_key", "token", "auth", "authtoken",
    "search", "q", "query", "filter", "sort", "order", "by",
    "page", "offset", "limit", "size", "per_page", "count",
    "redirect", "return", "callback", "url", "uri", "goto", "dest",
    "action", "method", "command", "cmd", "exec", "execute",
    "file", "filename", "path", "dir", "directory", "folder",
    "download", "upload", "submit", "send", "type", "format",
    "admin", "is_admin", "role", "permission", "group", "level",
    "debug", "verbose", "log", "trace", "error", "test",
    "version", "v", "api_version", "proto", "protocol",
    "name", "title", "description", "content", "text", "body",
    "code", "status", "state", "mode", "type", "category",
    "sort", "order", "reverse", "asc", "desc",
    "from", "to", "start", "end", "date", "time", "since",
    "lat", "lon", "latitude", "longitude", "geo", "location",
    "include", "exclude", "expand", "fields", "projection",
    "callback", "jsonp", "format", "output", "pretty",
    "hash", "checksum", "signature", "verify", "sign",
]



_WORDLIST_HEADERS = [
    "X-API-Key", "X-API-Secret", "X-Auth-Token", "X-Auth", "X-Token",
    "Authorization", "Bearer", "WWW-Authenticate",
    "X-Forwarded-For", "X-Real-IP", "X-Remote-Addr", "X-Client-IP",
    "X-Forwarded-Proto", "X-Forwarded-Host", "X-Original-URL",
    "X-Original-Host", "X-Rewrite-URL", "X-Proxy-Authorization",
    "X-CSRF-Token", "X-XSRF-Token", "CSRF-Token",
    "X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
    "X-Requested-With", "XMLHttpRequest",
    "X-User-ID", "X-User", "X-Username", "X-UID",
    "X-Admin", "X-Is-Admin", "X-Permission", "X-Role",
    "X-Debug", "X-Debug-Mode", "X-Trace", "X-Log",
    "X-Version", "X-API-Version", "X-Protocol-Version",
    "X-Request-ID", "X-Correlation-ID", "X-Transaction-ID",
    "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
    "Content-Security-Policy", "Strict-Transport-Security",
    "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
    "User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
]



_WORDLIST_CMS_PATHS = {
    "wordpress": ["wp-admin", "wp-login.php", "wp-content", "wp-includes",
                  "wp-json", "wp-api", "wordpress/", "blog/", "index.php",
                  "themes/", "plugins/", "uploads/", "wp-cron.php",
                  "xmlrpc.php", "wp-trackback.php"],
    "drupal": ["admin", "admin/login", "admin/user", "admin/structure",
               "sites/", "modules/", "themes/", "profiles/", "libraries/",
               "rest/", "jsonapi/", "core/", "user/", "node/"],
    "joomla": ["administrator", "administrator/index.php", "components/",
               "modules/", "plugins/", "templates/", "images/", "media/",
               "index.php", "router.php"],
    "magento": ["admin", "admin/", "var/", "media/", "skin/", "js/",
                "app/", "lib/", "shell/", "downloader/", "contacts/"],
    "shopify": ["admin/", "api/", "cdn/", "cdn/shop/", "s/files/"],
    "wix": ["_api/", "_api/v1/", "api/", "api/v1/"],
    "squarespace": ["api/", "api/v1/", "checkout/", "cart/"],
    "prestashop": ["admin/", "modules/", "themes/", "controllers/",
                   "classes/", "translations/", "uploads/"],
}



_WORDLIST_CLOUD_PATHS = {
    "aws": ["api.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com",
            "rds.amazonaws.com", "lambda.amazonaws.com", "iam.amazonaws.com",
            "cloudfront.amazonaws.com", "elasticache.amazonaws.com",
            "169.254.169.254/latest/meta-data/"],
    "azure": ["management.azure.com", "vault.azure.net", "blob.core.windows.net",
              "file.core.windows.net", "queue.core.windows.net", "table.core.windows.net",
              "169.254.169.254/metadata/instance/"],
    "gcp": ["cloudresourcemanager.googleapis.com", "storage.googleapis.com",
            "compute.googleapis.com", "bigquery.googleapis.com",
            "metadata.google.internal/computeMetadata/"],
    "alibaba": ["100.100.100.200/latest/meta-data/"],
}



_WORDLIST_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht",
    ".asp", ".aspx", ".asp.net", ".cer", ".asa",
    ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
    ".cgi", ".pl", ".py", ".pyc", ".rb", ".rbx",
    ".sh", ".bash", ".bat", ".cmd", ".exe",
    ".html", ".htm", ".shtml", ".stm",
    ".xml", ".json", ".yaml", ".yml", ".conf", ".config",
    ".txt", ".csv", ".log", ".sql", ".db",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz",
    ".bak", ".backup", ".old", ".tmp", ".temp",
    ".swp", ".swo", ".~", ".bkp",
]



_WORDLIST_BYPASS_ENCODING = [
    "%00", "%0d%0a", "%2e%2e/", "..%2f", "..%5c",
    "%252e%252e%252f", "..%c0%af", "..%c1%9c",
    "%3f", "%23", "%26", "%25",
    "test%09.php", "test%20.php", "test%00.php",
    "test.php%00", "test.php%20", "test.php%09",
    "test.php.bak", "test.php~", "test.php.tmp",
    "test(1).php", "test[1].php", "test{1}.php",
]



_WORDLIST_USER_ENUM = [
    "user_id=1", "user=admin", "email=admin@example.com",
    "username=admin", "uid=1", "id=admin",
    "author=1", "author_id=1", "user_login=admin",
    "get_user=admin", "profile=admin",
]



_WORDLIST_PRIV_ESC = [
    "role=admin", "is_admin=1", "admin=true", "level=9",
    "permission=admin", "group=admin", "privilege=admin",
    "access_level=9", "user_level=admin",
]



_WORDLIST_MOBILE_API = [
    "api/", "api/v1/", "api/v2/", "mobile/", "app/",
    "ios/", "android/", "client/", "app-api/",
    "token", "oauth", "oauth2", "login", "auth",
    "user", "profile", "settings", "notifications",
    "feed", "timeline", "posts", "messages", "comments",
    "like", "share", "follow", "unfollow",
]



_WORDLIST_EXPORT_DOWNLOAD = [
    "export", "download", "generate", "report", "pdf",
    "csv", "excel", "json", "xml", "yaml",
    "backup", "dump", "archive", "package",
    "email_report", "send_report", "schedule",
]



_WORDLIST_SQL_INJECTION_PATTERNS = [
    "' OR '1'='1", "' OR 1=1 --", "' OR 1=1 /*",
    "admin' --", "admin' #", "admin'/*",
    "' UNION SELECT NULL--", "' UNION ALL SELECT NULL--",
    "'; DROP TABLE users--",
]



_WORDLIST_XSS_VECTORS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
]




def wordlist_for_gobuster(category: str = "all") -> list[str]:
    """Export wordlist(s) for gobuster/dirbuster dir enumeration.
    Categories: admin, config, api, auth, upload, source, debug, traversal, all."""
    if category == "all":
        return (_WORDLIST_ADMIN + _WORDLIST_CONFIG + _WORDLIST_AUTH_ENDPOINTS +
                _WORDLIST_API + _WORDLIST_DATA_EXPOSURE + _WORDLIST_SOURCE_CODE +
                _WORDLIST_UPLOAD + _WORDLIST_DEBUG + _WORDLIST_INFO_DISCLOSURE)
    elif category == "admin":
        return _WORDLIST_ADMIN
    elif category == "config":
        return _WORDLIST_CONFIG
    elif category == "api":
        return _WORDLIST_API
    elif category == "auth":
        return _WORDLIST_AUTH_ENDPOINTS
    elif category == "upload":
        return _WORDLIST_UPLOAD
    elif category == "source":
        return _WORDLIST_SOURCE_CODE
    elif category == "debug":
        return _WORDLIST_DEBUG
    elif category == "traversal":
        return _WORDLIST_TRAVERSAL
    else:
        return _WORDLIST_ADMIN




def wordlist_for_domain_enum() -> list[str]:
    """Export subdomain wordlist for DNS enumeration (ffuf, massdns, etc)."""
    return _WORDLIST_SUBDOMAINS




def wordlist_for_vcs_disclosure() -> list[str]:
    """Export VCS/source control paths."""
    return _WORDLIST_VCS




def wordlist_get_framework_paths(framework: str = None) -> dict[str, list[str]] | list[str]:
    """Get framework-specific paths. If framework is None, return all; else return specific."""
    if framework:
        return _WORDLIST_FRAMEWORK_PATHS.get(framework.lower(), [])
    return _WORDLIST_FRAMEWORK_PATHS




def wordlist_get_parameters() -> list[str]:
    """Get common parameter names for fuzzing (id, email, api_key, etc)."""
    return _WORDLIST_PARAMETERS




def wordlist_get_headers() -> list[str]:
    """Get HTTP headers for header injection / bypass testing."""
    return _WORDLIST_HEADERS




def wordlist_get_cms_paths(cms: str = None) -> dict[str, list[str]] | list[str]:
    """Get CMS-specific paths."""
    if cms:
        return _WORDLIST_CMS_PATHS.get(cms.lower(), [])
    return _WORDLIST_CMS_PATHS




def wordlist_get_cloud_paths(provider: str = None) -> dict[str, list[str]] | list[str]:
    """Get cloud provider paths (AWS, Azure, GCP, Alibaba)."""
    if provider:
        return _WORDLIST_CLOUD_PATHS.get(provider.lower(), [])
    return _WORDLIST_CLOUD_PATHS




def wordlist_get_extensions() -> list[str]:
    """Get common file extensions for brute-forcing."""
    return _WORDLIST_EXTENSIONS




def wordlist_get_bypasses() -> list[str]:
    """Get encoding/bypass techniques for path traversal, etc."""
    return _WORDLIST_BYPASS_ENCODING




def wordlist_get_payloads(attack_type: str) -> list[str]:
    """Get payload templates: sql_injection, xss, user_enum, priv_esc, mobile_api, export."""
    payloads_map = {
        "sql_injection": _WORDLIST_SQL_INJECTION_PATTERNS,
        "xss": _WORDLIST_XSS_VECTORS,
        "user_enum": _WORDLIST_USER_ENUM,
        "priv_esc": _WORDLIST_PRIV_ESC,
        "mobile_api": _WORDLIST_MOBILE_API,
        "export": _WORDLIST_EXPORT_DOWNLOAD,
    }
    return payloads_map.get(attack_type, [])
