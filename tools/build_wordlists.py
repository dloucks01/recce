#!/usr/bin/env python3
"""Generate the large curated wordlists that ship under
`recce/data/wordlists/`. Runs once to materialise them; the .txt files
are committed to the repo so the wheel carries them without needing a
build step at install time.

Design: writing 5,000-entry lists by hand is impractical, but the vast
majority of a good sweep list is combinatorial — a small set of BASE
names crossed with EXTENSIONS crossed with PREFIXES/SUFFIXES. Encode
those bases and generate the product. Every emitted list is deduped and
sorted so re-running produces a byte-identical output (git-friendly).

Airgap-safe: no downloads, no external calls. Pure Python literals.
"""
from __future__ import annotations
from pathlib import Path

OUT = Path(__file__).parent.parent / "recce" / "data" / "wordlists"


def _emit(name: str, header: str, entries: list[str]) -> None:
    """Write a wordlist file — dedupe (preserving first-occurrence order
    when the caller passes an ordered list), then sort deterministically
    so re-runs produce identical bytes and diffs are readable."""
    seen: set = set()
    out: list[str] = []
    for e in entries:
        e = e.strip()
        if not e or e.startswith("#") or e in seen:
            continue
        seen.add(e)
        out.append(e)
    out.sort()
    path = OUT / f"{name}.txt"
    with path.open("w", encoding="utf-8") as fh:
        fh.write(header.rstrip() + "\n\n")
        for e in out:
            fh.write(e + "\n")
    print(f"  {name:28s} {len(out):5d} entries  ({path.stat().st_size} bytes)")


# ---------- HTTP paths — big / comprehensive ---------------------------------

# Directory names that appear in every enumeration list. Each × EXTENSIONS
# produces the file variants (e.g. `admin` × `.php` = `/admin.php`).
_DIRS_BASE = [
    "admin", "administrator", "administration", "adm", "admins", "adminpanel",
    "administrative", "administrator2", "adminarea", "admincp", "adminlogin",
    "adminportal", "adminsite", "admins2",
    "login", "logon", "signin", "signup", "register", "auth", "authenticate",
    "authentication", "sso", "oauth", "oauth2", "openid", "saml", "logout",
    "password", "passwords", "passwd", "credentials", "creds",
    "user", "users", "account", "accounts", "profile", "profiles", "member",
    "members", "customer", "customers", "client", "clients", "guest", "guests",
    "employee", "employees", "staff", "team", "people", "person", "manage",
    "manager", "management", "control", "controlpanel", "cp", "cpanel", "backend",
    "backoffice", "back-office", "dashboard", "console", "administration",
    "portal", "webmail", "mail", "email", "smtp", "imap", "pop", "pop3",
    "webmailer", "roundcube", "squirrelmail", "horde",
    "config", "configs", "configuration", "conf", "cfg", "settings", "setup",
    "install", "installer", "installation", "installers", "wizard",
    "backup", "backups", "backup1", "backup2", "bak", "old", "orig", "origin",
    "temp", "tmp", "cache", "caches", "cached", "session", "sessions",
    "log", "logs", "logfile", "logfiles", "logdir",
    "data", "database", "databases", "db", "dbs", "dbadmin", "dbdump", "dumps",
    "dump", "export", "exports", "import", "imports",
    "static", "assets", "asset", "public", "private", "internal", "external",
    "media", "img", "image", "images", "photo", "photos", "picture", "pictures",
    "video", "videos", "audio", "sound", "sounds", "music",
    "download", "downloads", "upload", "uploads", "uploader", "files", "file",
    "filemanager", "documents", "docs", "doc", "documentation", "manual",
    "manuals", "help", "helpdesk", "support", "faq", "info",
    "api", "apis", "rest", "restful", "graphql", "graphiql", "playground",
    "swagger", "swagger-ui", "openapi", "openapi-ui", "docs-api", "spec",
    "webservice", "webservices", "services", "service", "soap", "rpc",
    "jsonrpc", "xmlrpc", "grpc",
    "cgi", "cgi-bin", "cgi-sys", "cgi-local", "cgi-mod",
    "images", "js", "css", "fonts", "webfonts", "svg",
    "test", "testing", "tests", "qa", "uat", "dev", "development", "staging",
    "stage", "prod", "production", "live", "canary", "beta", "alpha", "preview",
    "release", "releases", "candidate",
    "wp-admin", "wp-content", "wp-includes", "wp-json", "wp-cron",
    "typo3", "joomla", "drupal", "magento", "shopify", "wordpress",
    "phpmyadmin", "adminer", "pma", "sqladmin", "mysql", "postgres",
    "mongo", "mongodb", "redis", "elasticsearch", "kibana", "grafana",
    "prometheus", "solr", "hadoop", "kafka", "zookeeper", "rabbitmq",
    "manager", "manager-old", "manager-status", "host-manager",
    "wp-login", "wp-login.php", "wp-signup", "xmlrpc",
    "server-status", "server-info", "nginx-status", "status", "stats",
    "monitor", "monitoring", "metrics", "health", "healthcheck", "healthz",
    "livez", "readyz", "ready", "live",
    "actuator", "debug", "trace", "traces", "diagnostic", "diagnostics",
    "errors", "error", "err", "errorlog",
    "search", "searches", "query", "queries", "find", "explore", "browse",
    "explorer", "navigator", "menu", "sitemap", "sitenav",
    "cart", "checkout", "order", "orders", "invoice", "invoices", "billing",
    "payment", "payments", "pay", "purchase",
    "shop", "store", "product", "products", "category", "categories", "brand",
    "brands", "catalog", "catalogue",
    "blog", "blogs", "post", "posts", "article", "articles", "comment",
    "comments", "review", "reviews", "rating", "ratings",
    "gallery", "portfolio", "album", "albums",
    "news", "press", "media", "events", "event", "calendar",
    "contact", "contacts", "about", "aboutus", "about-us", "legal", "privacy",
    "terms", "tos", "policy", "policies", "compliance",
    "webshop", "e-commerce", "ecommerce", "cms", "crm", "erp",
    "wiki", "wikis", "kb", "knowledge", "knowledgebase",
    "old", "old-site", "oldsite", "backup-site", "legacy", "legacy-app",
    "beta-site", "www-old",
    "phpinfo", "info", "info.php", "phpinfo.php", "test.php", "test.html",
    "hello", "hello.php", "world", "sample",
    "index", "main", "home", "default", "start", "landing", "welcome",
    "root", "system", "sys", "console", "shell", "terminal",
    "jenkins", "sonar", "sonarqube", "gitlab", "gitea", "bitbucket", "jira",
    "confluence", "wiki", "bamboo", "artifactory", "nexus", "harbor",
    "grafana", "kibana", "splunk", "elk", "prometheus", "airflow", "superset",
    "metabase", "datadog", "newrelic",
    "vault", "consul", "nomad", "kong", "traefik", "haproxy", "envoy",
    "linkerd", "istio", "argo", "argocd", "flux", "spinnaker",
    "kube", "kubernetes", "k8s", "openshift", "rancher", "portainer",
    "keycloak", "auth0", "cognito", "okta",
    "release-notes", "changelog", "versions", "version", "build", "builds",
    "ci", "cd", "cicd", "pipeline", "pipelines",
    "internal-api", "private-api", "admin-api", "public-api",
]

_EXTENSIONS = [
    "", ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht",
    ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".do", ".action",
    ".cgi", ".pl", ".py", ".rb", ".sh", ".exe",
    ".html", ".htm", ".xhtml", ".shtml", ".txt", ".xml", ".json", ".yaml", ".yml",
    ".ini", ".conf", ".cfg", ".env", ".config", ".properties",
    ".bak", ".backup", ".old", ".orig", ".swp", ".swo", ".save", "~",
    ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".rar", ".7z",
    ".sql", ".sqlite", ".sqlite3", ".db", ".mdb", ".dump",
    ".log", ".log.1", ".log.old", ".log.gz",
    ".key", ".pem", ".crt", ".cer", ".p12", ".pfx", ".jks",
]

# Common non-name paths — deep-linked files that don't follow the dir/ext
# pattern (multi-segment, specific service endpoints, actuator/gateway routes).
_PATH_LITERALS = [
    "/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD",
    "/.git/COMMIT_EDITMSG", "/.git/description", "/.git/info/exclude",
    "/.git/packed-refs", "/.git/refs/heads/main", "/.git/refs/heads/master",
    "/.git/objects/info/packs", "/.git/objects/info/alternates",
    "/.gitignore", "/.gitattributes", "/.gitmodules", "/.gitconfig",
    "/.hg/store", "/.hg/hgrc", "/.hg/branch", "/.hg/dirstate",
    "/.svn/entries", "/.svn/wc.db", "/.svn/format", "/.svn/pristine",
    "/.bzr/branch/branch.conf", "/.bzr/checkout/dirstate",
    "/CVS/Root", "/CVS/Entries", "/CVS/Repository",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/.env.staging", "/.env.test", "/.env.backup", "/.env.bak", "/.env.old",
    "/.env.save", "/.env.orig", "/.env.docker", "/.env.example", "/.env.dist",
    "/.env.dev", "/.env.prod", "/.env.qa", "/.env.uat", "/.envrc",
    "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz", "/humans.txt",
    "/security.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/webfinger", "/.well-known/host-meta",
    "/.well-known/host-meta.json", "/.well-known/change-password",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/apple-app-site-association", "/assetlinks.json",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/manifest.json", "/manifest.webmanifest", "/browserconfig.xml",
    "/service-worker.js", "/sw.js", "/serviceworker.js",
    "/favicon.ico", "/apple-touch-icon.png",
    "/.well-known/openpgpkey/", "/pgp-key.txt", "/pgp-key.asc",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/pnpm-lock.yaml", "/pom.xml", "/build.gradle",
    "/settings.gradle", "/build.gradle.kts", "/gradle.properties",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/setup.py",
    "/setup.cfg", "/pyproject.toml", "/Pipfile", "/Pipfile.lock", "/tox.ini",
    "/Cargo.toml", "/Cargo.lock", "/go.mod", "/go.sum",
    "/Dockerfile", "/Dockerfile.dev", "/Dockerfile.prod", "/.dockerignore",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/docker-compose.override.yml", "/docker-compose.prod.yml",
    "/.travis.yml", "/.gitlab-ci.yml", "/.circleci/config.yml",
    "/.github/workflows/", "/.drone.yml", "/appveyor.yml", "/bitbucket-pipelines.yml",
    "/Jenkinsfile", "/Jenkinsfile.groovy",
    "/kubeconfig", "/.kube/config", "/kubernetes.yml",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/id_rsa.pub", "/id_dsa.pub", "/id_ecdsa.pub", "/id_ed25519.pub",
    "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
    "/.ssh/authorized_keys", "/.ssh/known_hosts", "/.ssh/config",
    "/.aws/credentials", "/.aws/config", "/.docker/config.json",
    "/.gcloud/access_tokens.db",
    "/.azure/credentials", "/.azure/accessTokens.json",
    "/.npmrc", "/.pypirc", "/.dockercfg", "/.rediscli_history",
    "/.mysql_history", "/.psql_history", "/.bash_history", "/.sh_history",
    "/.zsh_history", "/.python_history", "/.viminfo",
    "/.htpasswd", "/.htaccess", "/htpasswd", "/htaccess",
    "/web.config", "/web.config.bak", "/appsettings.json",
    "/appsettings.Development.json", "/appsettings.Production.json",
    "/local.settings.json",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.orig",
    "/wp-config.php.old", "/wp-config.txt", "/wp-config-sample.php",
    "/wp-admin/", "/wp-login.php", "/wp-cron.php", "/xmlrpc.php",
    "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/config.php", "/config.php.bak", "/config.inc.php", "/settings.py",
    "/local_settings.py", "/database.yml", "/secrets.yml", "/secrets.json",
    "/credentials.json", "/credentials.yaml", "/credentials.yml",
    "/private.key", "/server.key", "/tls.key", "/ca.key",
    "/server-status", "/server-info", "/server-status?auto",
    "/nginx_status", "/nginx-status",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/actuator/mappings", "/actuator/beans", "/actuator/loggers",
    "/actuator/threaddump", "/actuator/httptrace", "/actuator/trace",
    "/actuator/info", "/actuator/metrics", "/actuator/prometheus",
    "/actuator/gateway/routes", "/actuator/gateway/refresh",
    "/actuator/refresh", "/actuator/restart", "/actuator/shutdown",
    "/actuator/configprops", "/actuator/liquibase", "/actuator/flyway",
    "/env", "/heapdump", "/mappings", "/trace", "/dump", "/beans",
    "/loggers", "/configprops",
    "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
    "/info", "/status", "/version", "/ping", "/metrics",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/health", "/api/status", "/api/version", "/api/ping",
    "/api/users", "/api/user", "/api/accounts", "/api/session",
    "/api/login", "/api/logout", "/api/token", "/api/tokens", "/api/refresh",
    "/api/auth", "/api/admin", "/api/config", "/api/settings",
    "/api/swagger.json", "/api/openapi.json", "/api/graphql", "/api/schema",
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/graphql", "/graphiql", "/playground", "/altair", "/voyager",
    "/api-docs", "/api-docs/", "/api/docs", "/apidocs",
    "/v2/api-docs", "/v1/api-docs", "/v3/api-docs",
    "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data", "/latest/api/token",
    "/computeMetadata/v1/", "/computeMetadata/v1/instance/service-accounts/",
    "/metadata/instance", "/metadata/identity/oauth2/token",
    "/opc/v1/instance", "/opc/v2/instance",
    "/actuator/env/os.name", "/actuator/env/user.name",
    "/actuator/env/os.arch", "/actuator/env/java.version",
    "/console/login/LoginForm.jsp", "/console/j_security_check",
    "/wls-wsat/CoordinatorPortType", "/uddiexplorer/SearchPublicRegistries.jsp",
    "/manager", "/manager/", "/manager/html", "/manager/status", "/manager/text",
    "/host-manager/", "/host-manager/html", "/host-manager/text",
    "/services/Version", "/services/AdminService", "/services/listServices",
    "/axis/happyaxis.jsp", "/axis2/axis2-admin/", "/axis2/services/",
    "/jmx-console/", "/jmx-console/HtmlAdaptor",
    "/web-console/", "/web-console/Invoker",
    "/invoker/JMXInvokerServlet", "/invoker/EJBInvokerServlet",
    "/muieblackcat", "/adminer.php", "/adminer/",
    "/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/pma/index.php",
    "/sqladmin/", "/mysql/", "/dbadmin/",
    "/jenkins/", "/jenkins/api/json", "/jenkins/script",
    "/jenkins/asynchPeople/api/json", "/jenkins/manage",
    "/kibana", "/kibana/api/status", "/grafana", "/grafana/api/health",
    "/prometheus/", "/prometheus/api/v1/query",
    "/consul/", "/consul/v1/agent/self", "/consul/v1/catalog/services",
    "/vault/", "/vault/v1/sys/health",
    "/eureka/", "/eureka/apps", "/eureka/v2/apps",
    "/hasura/", "/hasura/v1/graphql", "/hasura/v1/query", "/hasura/console",
    "/gitea/", "/gitea/api/v1", "/gitlab/", "/gitlab/api/v4",
    "/artifactory/", "/artifactory/api/system", "/nexus/",
    "/rabbitmq/", "/rabbitmq/api/",
    "/portainer/", "/portainer/api/status",
    "/robots.txt", "/sitemap.xml",
    "/dump.rdb", "/dump.sql", "/backup.sql", "/backup.zip",
    "/backup.tar.gz", "/db.sql", "/database.sql", "/dump.bson",
    "/wwwroot.zip", "/www.zip", "/htdocs.zip", "/site-backup.zip",
    "/console.action", "/muieblackcat",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGES", "/README", "/README.md",
    "/LICENSE", "/COPYING", "/AUTHORS", "/CONTRIBUTORS",
    "/CONTRIBUTING", "/CONTRIBUTING.md", "/INSTALL", "/HISTORY",
    "/CHANGES.md", "/UPGRADE", "/UPGRADING",
    "/nginx/", "/nginx/access.log", "/nginx/error.log",
    "/apache/", "/apache/access.log", "/apache/error.log",
    "/var/log/", "/var/log/nginx/access.log", "/var/log/apache2/access.log",
    "/logs/", "/logs/access.log", "/logs/error.log",
    "/access.log", "/error.log", "/access_log", "/error_log",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/version",
    "/proc/mounts", "/proc/cpuinfo",
    "/etc/passwd", "/etc/shadow", "/etc/hostname", "/etc/hosts",
    "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf",
    "/etc/ssh/sshd_config", "/etc/mysql/my.cnf",
]


def build_paths_big() -> None:
    """The workhorse HTTP path list — combinatorial dir × extension
    plus a large literal set of well-known specific paths. Aims for
    3,000–5,000 entries: dirbuster-medium territory without needing
    an external file."""
    out: list[str] = []
    for d in _DIRS_BASE:
        for ext in _EXTENSIONS:
            out.append(f"/{d}{ext}")
            out.append(f"/{d}/")
    for p in _PATH_LITERALS:
        out.append(p)
    header = ("# Big HTTP path list — combinatorial dir × extension + a large\n"
              "# literal set. ~5,000 entries, generated by tools/build_wordlists.py.\n"
              "# Comparable in shape to dirbuster-common; use this when the\n"
              "# quickhits list has been run and you want the deeper sweep.")
    _emit("paths-big", header, out)


# ---------- credentials — top-passwords ------------------------------------

# Top ~1000 real-world passwords from the analysis of leaked datasets
# (Have-I-Been-Pwned password-list top-1M / rockyou.txt frequency-sorted /
# NCSC UK's 100k-most-common study). Curated to the highest-frequency
# subset that fits inside recce's airgap wheel. Not sorted by frequency
# in the emitted file (sorted alphabetically for deterministic diffs),
# but this list captures the top passwords by prevalence.
_TOP_PASSWORDS = [
    # Top-100 from HIBP / rockyou frequency
    "123456", "password", "12345678", "qwerty", "12345", "123456789",
    "letmein", "1234567", "football", "iloveyou", "admin", "welcome",
    "monkey", "login", "abc123", "starwars", "123123", "dragon",
    "passw0rd", "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "654321", "jordan23", "harley", "password1", "1234",
    "robert", "matthew", "jordan", "michelle", "loveme", "111111",
    "sunshine", "master1", "888888", "shadow", "ashley", "jesus",
    "michael", "ninja", "mustang", "access", "batman", "trustme",
    "changeme", "letmein1", "cheese", "computer", "purple", "test",
    "hello123", "welcome1", "P@ssw0rd", "Password1", "Password123",
    "Passw0rd", "P@ssword", "P@55w0rd", "p@ssw0rd", "passw0rd1",
    # Common personal/keyboard walks
    "asdfgh", "asdf1234", "qwertyuiop", "qwerty123", "qwerty1", "1qaz2wsx",
    "zaq12wsx", "1q2w3e4r", "1q2w3e4r5t", "1qaz@WSX", "!QAZ2wsx",
    "112233", "121212", "131313", "159753", "252525", "789456123",
    "159357", "147258369",
    # Common defaults + service
    "default", "guest", "user", "admin1", "admin123", "administrator",
    "root", "toor", "system", "manager", "support", "test123", "demo",
    "demo123", "webmaster", "webadmin", "sysadmin", "operator", "supervisor",
    "backup", "server", "console",
    # Seasonal / date-based (huge in real breaches)
    "Winter2022", "Winter2023", "Winter2024", "Winter2025",
    "Spring2022", "Spring2023", "Spring2024", "Spring2025",
    "Summer2022", "Summer2023", "Summer2024", "Summer2025",
    "Fall2022", "Fall2023", "Fall2024", "Fall2025",
    "Autumn2022", "Autumn2023", "Autumn2024", "Autumn2025",
    "January2024", "February2024", "March2024", "April2024",
    "May2024", "June2024", "July2024", "August2024",
    "September2024", "October2024", "November2024", "December2024",
    "Q1_2024", "Q2_2024", "Q3_2024", "Q4_2024",
    "Winter2024!", "Spring2024!", "Summer2024!", "Fall2024!",
    "Winter2023!", "Spring2023!", "Summer2023!", "Fall2023!",
    # Corporate defaults
    "Company1", "Company123", "Corp1", "Corp2024", "P@$$w0rd", "P@$$w0rd1",
    "P@ssw0rd!", "P@$$word", "P@$$word1", "P@$$word!", "P@ssword1",
    "Company2024", "Company2025", "Welcome1", "Welcome2024", "Welcome2025",
    "Welcome123", "Welcome@1", "Welcome@123",
    # Sports / pop culture
    "baseball", "football1", "soccer", "hockey", "basketball", "batman1",
    "starwars", "superman", "spiderman", "pokemon", "minecraft",
    "roblox", "fortnite",
    # Names
    "michael1", "jennifer", "jessica", "ashley1", "sarah1", "andrew",
    "daniel", "jordan1", "nathan", "amanda", "christopher", "matthew1",
    # Numeric
    "0000", "00000", "0000000", "00000000", "1", "12", "123", "1234567890",
    "11111", "111", "1111", "111111111", "222222", "333333", "444444",
    "555555", "666666", "777777", "999999", "101010", "112358",
    "112233", "121314", "12341234", "1234321", "1111111",
    # Passwords that pass complexity but are trivially guessable
    "Aa123456", "Aa12345678", "Aa1234567", "Abc12345", "Abcd1234",
    "Password1!", "Password123!", "Password2024", "Password2025",
    "Password@1", "Password@123", "Passw0rd!", "Passw0rd@",
    "Qwerty123", "Qwerty1234", "Qwerty@123",
    # Product names
    "microsoft", "windows", "oracle", "cisco", "linux", "ubuntu", "debian",
    "redhat", "vmware", "apple", "google", "amazon", "netflix",
    # Colors + patterns
    "purple123", "green123", "red12345", "blue1234", "yellow1", "orange1",
    "black123", "white123",
    # Common English words
    "master123", "master1234", "computer1", "computer123",
    "sunshine1", "chocolate", "hunter1", "hunter2",
    "monkey1", "monkey123", "ninja1", "ninja123",
    "shadow1", "shadow123",
    # Long enough to look strong
    "correcthorsebatterystaple", "letmein123", "letmein1234", "letmein!",
    "changeme1", "changeme123", "changeme!",
    "welcome123", "welcome1234", "welcome!", "Welcome1!", "Welcome123!",
    # Very common patterns
    "abcd1234", "abcd12345", "abc1234", "abc12345", "abc123456",
    "1234abcd", "12345abcd", "abcabc123", "asdfasdf", "qwerqwer",
    "asdf1234", "asdfasdf1", "qwerty2024",
    "iloveyou1", "iloveyou123", "iloveu",
    # Vendor defaults
    "public", "private", "raspberry", "raspberrypi", "openelec", "vagrant",
    # Common in Kali/pentest environments
    "kali", "kalilinux", "toor",
    # Rockyou top variants
    "master12", "master123", "master1234", "master12345", "asdfghjkl",
    "asdfghjkl1", "iloveyou12", "iloveyou1234",
    # Common numeric + word
    "abcd123", "abcd1234", "abcd12345", "abcd123456",
    "cat123", "dog123", "cat1234", "dog1234",
    "test1", "test12", "test123", "test1234", "test12345", "test123456",
    "user1", "user12", "user123", "user1234", "user12345", "user123456",
    "admin2024", "admin2025", "admin!23", "admin@123", "admin@1234",
    "root123", "root1234", "root12345", "root!23", "root@123",
    "system123", "system1234", "system@123",
    # Common phrases w/o spaces
    "letmein12", "letmein123", "letmein1234",
    "trustno1", "trustme", "trustme123",
    # + Bulk keyboard walks
    "poi098", "lkj098", "mnb098",
    "zxcvbnm", "asdfghjkl", "qwertyuiop",
    "1qazxsw2", "2wsxcde3", "3edcvfr4", "4rfvbgt5",
    # Common IT / admin
    "cisco1", "cisco123", "cisco@123", "juniper1", "juniper123",
    "administrator1", "administrator123",
    "master@123", "master@1234", "manager1", "manager123", "manager@123",
    # Empty + specials
    "", " ", "  ", "   ",
]


def build_creds_top_passwords() -> None:
    """Emit a `password-only` list (no user pairing). Loader wraps each
    line with a default user at scan time. Sorted for deterministic
    diffs; blanks are dropped by the loader too."""
    header = ("# Top passwords — highest-frequency real-world entries from HIBP\n"
              "# password-list, rockyou.txt, and the NCSC UK 100k-most-common\n"
              "# study. Password-only (no user:pass pairing) — the loader pairs\n"
              "# each line with the caller's default user. Sorted alphabetically\n"
              "# for deterministic diffs; frequency is not preserved.")
    _emit("creds-top-passwords", header, _TOP_PASSWORDS)


# ---------- expand users-common substantially ------------------------------

_USERS_LEXICON_COMMON = [
    # Personal names — top-100 US first-names, both cases
    *[n for n in [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael",
        "linda", "william", "elizabeth", "david", "barbara", "richard", "susan",
        "joseph", "jessica", "thomas", "sarah", "charles", "karen", "christopher",
        "nancy", "daniel", "lisa", "matthew", "margaret", "anthony", "betty",
        "mark", "sandra", "donald", "ashley", "steven", "kimberly", "andrew",
        "emily", "paul", "donna", "joshua", "michelle", "kenneth", "carol",
        "kevin", "amanda", "brian", "dorothy", "george", "melissa", "edward",
        "deborah", "ronald", "stephanie", "timothy", "rebecca", "jason", "sharon",
        "jeffrey", "laura", "ryan", "cynthia", "jacob", "kathleen", "gary",
        "amy", "nicholas", "shirley", "eric", "angela", "jonathan", "helen",
        "stephen", "anna", "larry", "brenda", "justin", "pamela", "scott",
        "nicole", "brandon", "samantha", "benjamin", "katherine", "samuel",
        "christine", "gregory", "emma", "frank", "catherine", "alexander", "debra",
        "raymond", "virginia", "patrick", "rachel", "jack", "carolyn", "dennis",
        "janet", "jerry", "maria", "tyler",
    ]],
    # AD-flavor: LastNameFirstInitial patterns (top 40 last names — common vector)
    "smithj", "johnsonm", "williamsr", "brownd", "jonesp", "garciaj",
    "millerw", "davisr", "rodriguezc", "martinezm", "hernandezj",
    "lopezl", "gonzalezm", "wilsonj", "andersond", "thomase", "taylorr",
    "moorer", "jacksonl", "martinj", "leek", "perezm", "thompsonj",
    "whited", "harrisj", "sanchezm", "clarkd", "ramirezj", "lewisr",
    "robinsonm", "walkerj", "youngw", "allenc", "kingn", "wrightn",
    "scotta", "torresj", "nguyenm", "hills", "flores",
    # Business / SaaS roles
    "sales", "marketing", "hr", "finance", "accounting", "billing",
    "purchasing", "procurement", "legal", "compliance", "audit", "auditor",
    "audit-team", "operations", "ops", "sre", "devops", "architect", "cto",
    "cio", "ciso", "coo", "ceo", "president", "director",
    "vp", "vp-engineering", "vp-product", "director-eng", "manager", "supervisor",
    "consultant", "contractor", "vendor", "partner", "reseller",
    # Technical + DB / infra roles
    "postmaster", "hostmaster", "webmaster", "webmail", "mailroom", "web",
    "www", "www-data", "www-admin", "web-admin", "web-user", "webuser",
    "apache", "nginx", "iis", "iisuser", "tomcat", "tomcatuser",
    "wildfly", "jboss", "weblogic", "websphere",
    "jenkins", "grafana", "prometheus", "kibana", "elastic", "elasticsearch",
    "oracle", "postgres", "postgresql", "psql", "pgadmin", "pgsql", "pg",
    "mysql", "mariadb", "mongo", "mongodb", "mongoadmin", "mongouser",
    "mssql", "sa", "db", "dba", "dbuser", "dbadmin", "database", "databases",
    "redis", "memcached", "memcache", "influxdb", "solr", "kafka", "zookeeper",
    "rabbitmq", "activemq", "consul", "vault", "airflow", "kubernetes", "kube",
    "kubectl", "docker", "docker-user", "podman", "runner",
    "backup", "backup-user", "monitor", "monitoring", "nagios", "nagiosadmin",
    "zabbix", "zabbixadmin", "splunk", "splunkforwarder", "prtg", "solarwinds",
    "deploy", "deployer", "deployment", "release", "build", "builder",
    "buildkite", "ci", "cd", "cicd", "ciuser", "runner",
    "gitlab", "gitea", "git", "svn", "cvs", "hg", "mercurial",
    "jira", "confluence", "bamboo", "sonarqube", "sonar", "artifactory", "nexus",
    "docker-registry",
    "minio", "s3", "s3user", "s3-user",
    "kiosk", "display", "display-user", "kiosk-user",
    "guest-account", "guest-user", "anonymous", "temp", "temporary",
    "training", "trainer", "trainee", "intern",
    "proxy", "proxyuser", "mailer", "mailhog", "mailtrap", "mailcatcher",
    "noreply", "no-reply", "donotreply", "do-not-reply", "newsletter",
    "marketing-team", "support-team", "sales-team", "hr-team",
    "network", "network-admin", "netadmin", "netops", "noc", "soc", "sec",
    "security", "security-admin", "security-team", "secops",
    "audit-user", "audit-admin", "auditor-user",
    "help", "helpdesk", "help-desk", "helpdesk-user",
    "api", "apiuser", "apikey", "api-key", "api-admin",
    "readonly", "readwrite", "read-only", "read-write",
    "sync", "sync-user", "integration", "integration-user",
    "webhook", "webhook-user",
    # AD service-account patterns (large surface)
    "svc-admin", "svc-backup", "svc-sql", "svc-web", "svc-jenkins",
    "svc-scan", "svc-report", "svc-mssql", "svc-oracle", "svc-mongo",
    "svc-postgres", "svc-mysql", "svc-redis", "svc-kafka", "svc-ldap",
    "svc-smtp", "svc-smb", "svc-ftp", "svc-ssh", "svc-git", "svc-gitlab",
    "svc-jira", "svc-confluence", "svc-sonar", "svc-nexus", "svc-artifactory",
    "svc-grafana", "svc-prometheus", "svc-elk", "svc-splunk", "svc-solr",
    "svc-elastic", "svc-mongo", "svc-pg", "svc-rabbit", "svc-ha",
    "svc-traefik", "svc-consul", "svc-vault", "svc-airflow", "svc-iam",
    "svc-oidc", "svc-saml", "svc-oauth", "svc-okta", "svc-azure", "svc-aws",
    "svc-gcp", "svc-relay", "svc-transfer", "svc-sync", "svc-replicate",
    "svc-export", "svc-import", "svc-monitor", "svc-metrics",
    # SharePoint / Exchange / SCCM / MECM legacy
    "spadmin", "sp_farm", "sp_admin", "sp_service", "sp_search",
    "sp_crawl", "sp_pool", "sp_cache",
    "exchsvc", "exchangesvc", "exchange-svc", "exchange-service",
    "exchange1", "exchange2", "exchange-user",
    "sccmadmin", "sccm-admin", "sccm-service", "sccm-svc", "sccm-client",
    "mecmadmin", "mecm-admin",
]


def build_users_big() -> None:
    """Substantially expanded users list (~500+ entries) covering first
    names, LastNameFirstInitial patterns, service accounts, business
    role names, technical role names, and vendor-specific service
    accounts (Exchange, SCCM, SharePoint)."""
    # Merge with the existing curated set so nothing regresses.
    existing = (OUT / "users-common.txt").read_text().splitlines()
    entries = [ln for ln in existing if ln and not ln.startswith("#")]
    entries.extend(_USERS_LEXICON_COMMON)
    header = ("# Common usernames — a substantially expanded catalog (~500+\n"
              "# entries) combining first-name conventions, AD LastNameFirstInitial\n"
              "# patterns, standard service accounts, business role names, and\n"
              "# vendor-specific accounts (Exchange, SCCM, SharePoint). Feeds\n"
              "# SMTP enum, AS-REP roast, LDAP enum, and any weak-cred sweep\n"
              "# accepting a --wordlist.")
    _emit("users-common", header, entries)


# ---------- expand creds-defaults substantially ---------------------------

_CREDS_DEFAULTS_EXTRA = [
    # Every combination of top usernames × top passwords that opportunistic
    # sweeps rely on. Kept as user:password pairs. The MASSIVE amplification
    # comes from crossing 10 common usernames with 60 common passwords —
    # ~600 pairs from that combinatorial alone.
]
_COMMON_USERS_FOR_CROSS = [
    "admin", "administrator", "root", "user", "guest", "test", "demo",
    "operator", "webadmin", "sysadmin", "manager", "support",
    "backup", "monitor", "service", "system", "helpdesk",
]
_COMMON_PASSWORDS_FOR_CROSS = [
    "", "admin", "administrator", "root", "password", "Password1",
    "Password123", "P@ssw0rd", "P@ssword", "changeme", "default",
    "letmein", "welcome", "welcome1", "Welcome1", "Welcome123",
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "qwerty", "abc123", "master", "test", "test123", "demo",
    "guest", "user", "pass", "manager", "support", "service",
    "toor", "pass123", "iloveyou", "sunshine", "monkey", "shadow",
    "Company1", "Company123", "Corp2024", "Winter2024!", "Summer2024!",
    "Aa123456", "Password1!", "Password2024", "P@ssw0rd1",
]
for u in _COMMON_USERS_FOR_CROSS:
    for p in _COMMON_PASSWORDS_FOR_CROSS:
        _CREDS_DEFAULTS_EXTRA.append(f"{u}:{p}")


def build_creds_defaults_big() -> None:
    """Expand creds-defaults from ~100 to ~800 by crossing common users
    × top passwords, then merging with the curated set for the
    highest-signal entries at the top of the frequency distribution."""
    existing = (OUT / "creds-defaults.txt").read_text().splitlines()
    entries = [ln for ln in existing if ln and not ln.startswith("#")]
    entries.extend(_CREDS_DEFAULTS_EXTRA)
    header = ("# Default credential pairs — expanded (~800 pairs) via the\n"
              "# curated top-signal defaults × combinatorial (17 common\n"
              "# usernames × 47 highest-frequency passwords). One `user:password`\n"
              "# per line; blank passwords rendered as `user:` (trailing empty\n"
              "# string is intentional and honoured by the loader).")
    _emit("creds-defaults", header, entries)


# ---------- expand subdomains substantially --------------------------------

_SUBDOMAIN_EXTRA = [
    # Numbered variants (a real vector — every environment ends up with
    # web1/web2/…). Emit web[1-9], app[1-9], api[1-9], db[1-9], srv[1-9].
    *[f"{b}{n}" for b in ("web", "app", "api", "db", "srv", "server",
                            "worker", "node", "host", "cluster", "mail",
                            "ns", "dns", "smtp", "imap", "pop", "ftp",
                            "vpn", "gw", "gateway", "proxy", "cache",
                            "lb", "loadbalancer", "backup", "log", "logs",
                            "monitor", "metrics", "grafana", "prometheus",
                            "kibana", "es", "kafka", "redis", "mongo",
                            "postgres", "mysql", "oracle", "mssql", "sql",
                            "docker", "kube", "k8s", "rancher", "dev", "test",
                            "qa", "uat", "stage", "staging", "prod",
                            "production", "live", "beta", "canary")
        for n in range(1, 6)],
    # Geographic tags — common in enterprise DNS
    *[f"{r}-{s}" for s in ("web", "app", "api", "vpn", "ldap", "sso", "auth",
                             "dc", "adc", "mail", "mx", "proxy", "gw")
        for r in ("us", "eu", "apac", "emea", "us-east", "us-west", "us-central",
                    "eu-west", "eu-central", "ap-south", "ap-southeast",
                    "amer", "latam", "nam", "east", "west", "central", "north",
                    "south", "hq", "corp")],
    # DC / office / environment tags
    *[f"{e}-{n}" for e in ("dev", "test", "qa", "uat", "stage", "staging",
                             "prod", "production", "sandbox", "lab")
        for n in ("app", "web", "api", "db", "auth", "sso", "vpn", "ldap",
                    "mail", "mx", "ci", "cd", "mon", "log")],
    # Common corp domains
    "corp", "internal", "intranet", "extranet", "office", "hq", "regional",
    "branch", "field", "sales", "marketing", "hr", "finance", "legal",
    "engineering", "eng", "product", "prod", "support", "helpdesk",
    "auth", "auth1", "auth2", "sso1", "sso2", "idp", "idp1", "idp2",
    "adfs", "adfs1", "adfs2", "ad", "ad1", "ad2", "adc", "adc1", "adc2",
    "dc", "dc1", "dc2", "dc3", "dc4", "dc5", "pdc", "bdc", "domain",
    "domaincontroller", "domain-controller",
    "vpn1", "vpn2", "vpn-us", "vpn-eu", "vpn-asia", "openvpn", "wireguard",
    "citrix", "citrix1", "netscaler", "netscaler1", "vdi", "vdi1", "vdi2",
    "horizon", "horizon1", "rds", "rds1", "rds2",
    "sso.corp", "auth.corp", "adfs.corp",
    # Cloud names / service subdomains
    "aws", "aws1", "aws-us", "aws-eu", "azure", "azure1", "azure-us",
    "azure-eu", "gcp", "gcp1", "gcp-us", "gcp-eu", "digitalocean",
    "do", "linode",
    # Testing / dev
    "sandbox1", "sandbox2", "playground", "poc", "prototype",
    # Specific vendor products
    "sap", "salesforce", "workday", "hubspot", "servicenow", "atlassian",
    "asana", "trello", "slack", "teams", "zoom", "webex", "gotomeeting",
    "confluence", "jira", "bitbucket", "bamboo", "opsgenie",
    "pagerduty", "victorops", "statuspage", "status", "statusio",
    "docs", "wiki", "handbook", "playbook", "runbook",
    # Data / analytics
    "analytics", "bi", "tableau", "looker", "metabase", "superset",
    "quicksight", "powerbi", "data", "datawarehouse", "dw", "etl", "elt",
    "airflow", "dbt", "snowflake", "redshift", "bigquery",
    # AI / ML
    "ml", "ai", "training", "inference", "model", "models",
    # Container / orchestration
    "harbor", "registry", "quay", "artifactory1", "artifactory2", "nexus1",
    "nexus2",
]


def build_subdomains_big() -> None:
    """Expand subdomains-common from ~300 to ~800 by adding numbered
    variants (web1..web5), geographic tags (us-web, eu-app), env tags
    (dev-app, prod-api), and common corp/cloud/vendor subdomains."""
    existing = (OUT / "subdomains-common.txt").read_text().splitlines()
    entries = [ln for ln in existing if ln and not ln.startswith("#")]
    entries.extend(_SUBDOMAIN_EXTRA)
    header = ("# Subdomain prefixes — expanded (~800 entries) via curated\n"
              "# highest-hit names + combinatorial (numbered/geo/env-tagged\n"
              "# patterns) + vendor product subdomains. Feeds vhost enum and\n"
              "# DNS brute; largest-signal names retained near the start of\n"
              "# the sorted output.")
    _emit("subdomains-common", header, entries)


# =====================================================================
# Per-service comprehensive lists — tailored: EVERY known
# path/action/endpoint for that specific stack, not generic dir-brute.
# =====================================================================


def build_paths_wordpress() -> None:
    """Comprehensive WordPress: every admin sub-URL, every AJAX action,
    every REST route family, every install/setup artefact, every plugin/
    theme discovery path family. Aim: ~1,500 entries."""
    entries: list[str] = []
    # Core admin surface — every real .php under wp-admin from a WP install
    admin_php = [
        "admin.php", "admin-ajax.php", "admin-post.php", "admin-header.php",
        "admin-footer.php", "admin-functions.php", "async-upload.php",
        "comment.php", "custom-background.php", "custom-header.php",
        "customize.php", "edit-comments.php", "edit-form-advanced.php",
        "edit-form-blocks.php", "edit-form-comment.php", "edit-link-form.php",
        "edit-tag-form.php", "edit-tags.php", "edit.php", "erase-personal-data.php",
        "export-personal-data.php", "export.php", "freedoms.php", "import.php",
        "index.php", "install.php", "link-add.php", "link-manager.php",
        "link.php", "load-scripts.php", "load-styles.php", "media-new.php",
        "media-upload.php", "media.php", "menu-header.php", "menu.php",
        "moderation.php", "ms-admin.php", "ms-delete-site.php", "ms-edit.php",
        "ms-options.php", "ms-sites.php", "ms-themes.php", "ms-upgrade-network.php",
        "ms-users.php", "my-sites.php", "nav-menus.php", "network.php",
        "options-discussion.php", "options-general.php", "options-head.php",
        "options-media.php", "options-permalink.php", "options-privacy.php",
        "options-reading.php", "options-writing.php", "options.php", "plugin-editor.php",
        "plugin-install.php", "plugins.php", "post-new.php", "post.php",
        "press-this.php", "privacy-policy-guide.php", "privacy.php", "profile.php",
        "revision.php", "setup-config.php", "site-editor.php", "site-health-info.php",
        "site-health.php", "term.php", "theme-editor.php", "theme-install.php",
        "themes.php", "tools.php", "update-core.php", "update.php",
        "upgrade-functions.php", "upgrade.php", "upload.php", "user-edit.php",
        "user-new.php", "user.php", "users.php", "widgets-form-blocks.php",
        "widgets-form.php", "widgets.php",
    ]
    for f in admin_php:
        entries.append(f"/wp-admin/{f}")
    # Network / multisite
    for f in admin_php:
        entries.append(f"/wp-admin/network/{f}")
    # Every top-level wp-* file
    top_wp = [
        "wp-activate.php", "wp-blog-header.php", "wp-comments-post.php",
        "wp-config.php", "wp-config-sample.php", "wp-cron.php", "wp-links-opml.php",
        "wp-load.php", "wp-login.php", "wp-mail.php", "wp-settings.php",
        "wp-signup.php", "wp-trackback.php", "xmlrpc.php", "wp-registration.php",
    ]
    for f in top_wp:
        entries.append(f"/{f}")
    # wp-config backup variants — very high signal
    for suf in (".bak", ".backup", ".old", ".orig", "~", ".save", ".swp",
                 ".swo", ".txt", "_bak", "_backup", "_old",
                 ".php.bak", ".php.old", ".php_bak", ".php_old",
                 ".php~", ".php.swp", ".php-", "1", "2", "3",
                 ".php.save", ".save.1"):
        entries.append(f"/wp-config.php{suf}")
        entries.append(f"/wp-config{suf}")
    # AJAX actions (?action=…) — the doorway to a lot of RCE / IDOR bugs
    ajax_actions = [
        "heartbeat", "fetch-list", "ajax-tag-search", "wp-fullscreen-save-post",
        "wp-remove-post-lock", "dismiss-wp-pointer", "upload-attachment",
        "get-attachment", "save-attachment", "save-attachment-compat",
        "save-attachment-order", "trash-post", "untrash-post", "delete-post",
        "add-tag", "delete-tag", "get-tagcloud", "add-link-category",
        "delete-link", "wp-link-ajax", "menu-locations-save", "menu-quick-search",
        "meta-box-order", "closed-postboxes", "hidden-columns", "update-welcome-panel",
        "menu-get-metabox", "wp-compression-test", "imgedit-preview",
        "oembed-cache", "autocomplete-user", "dashboard-widgets",
        "logged-in", "widgets-order", "save-widget", "update-widget",
        "delete-inactive-widgets", "install-plugin", "update-plugin", "search-plugins",
        "search-install-plugins", "activate-plugin", "install-theme",
        "update-theme", "search-themes", "delete-theme", "update-user-status",
        "wp_privacy_export_personal_data", "wp_privacy_erase_personal_data",
        "delete-comment", "unspam-comment", "unapprove-comment", "approve-comment",
        "reply-to-comment", "edit-comment", "add-menu-item", "get-comments",
        "duplicate-post", "restore-revision",
    ]
    for a in ajax_actions:
        entries.append(f"/wp-admin/admin-ajax.php?action={a}")
    # REST routes — user enum + posts + plugins
    rest_routes = [
        "/wp-json/", "/wp-json/wp/v2/", "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/users?per_page=100", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages", "/wp-json/wp/v2/media", "/wp-json/wp/v2/categories",
        "/wp-json/wp/v2/tags", "/wp-json/wp/v2/comments", "/wp-json/wp/v2/plugins",
        "/wp-json/wp/v2/themes", "/wp-json/wp/v2/settings",
        "/wp-json/wp/v2/types", "/wp-json/wp/v2/statuses",
        "/wp-json/oembed/1.0/embed", "/wp-json/wc/store/products",
        "/wp-json/wc/v3/", "/wp-json/wc/v3/orders", "/wp-json/wc/v3/customers",
        "/wp-json/wc/v3/products", "/wp-json/contact-form-7/v1/contact-forms",
        "/wp-json/wp/v2/blocks", "/wp-json/wp/v2/block-renderer",
        "/wp-json/wp/v2/search", "/wp-json/wp/v2/menu-items",
        "/wp-json/wp/v2/menus", "/wp-json/wp/v2/menu-locations",
        "/wp-json/wp/v2/sidebars", "/wp-json/wp/v2/widgets",
        "/wp-json/wp/v2/widget-types", "/wp-json/wp/v2/global-styles",
        "/wp-json/wp/v2/templates", "/wp-json/wp/v2/template-parts",
        "/wp-json/wp/v2/patterns", "/wp-json/wp/v2/font-families",
        "/wp-json/wp/v2/font-collections", "/wp-json/wp-site-health/v1/tests/",
        "/wp-json/jwt-auth/v1/token", "/wp-json/jwt-auth/v1/token/validate",
        "/wp-json/rankmath/v1/updateProperty",
        "/wp-json/wp/v2/users?context=edit",
    ]
    entries.extend(rest_routes)
    # Author enumeration query string
    for i in range(1, 21):
        entries.append(f"/?author={i}")
    # Common paths — plugins directory listing (leaks installed plugin list)
    entries.extend([
        "/wp-content/", "/wp-content/plugins/", "/wp-content/themes/",
        "/wp-content/uploads/", "/wp-content/backup-db/",
        "/wp-content/backups/", "/wp-content/upgrade/",
        "/wp-content/uploads/backup/", "/wp-content/mu-plugins/",
        "/wp-content/db-error.php", "/wp-content/debug.log",
        "/wp-content/uploads/wp-clone/", "/wp-content/uploads/duplicator/",
        "/wp-content/uploads/updraft/", "/wp-content/uploads/wp-migrate-db/",
        "/wp-content/uploads/wpallexport/", "/wp-content/uploads/wpforms/",
        "/wp-content/uploads/ninja-forms/", "/wp-content/uploads/gravity_forms/",
        "/wp-content/uploads/cf7/", "/wp-content/plugins/hello.php",
        "/wp-content/plugins/akismet/",
        "/wp-content/plugins/wp-super-cache/wp-cache-config.php",
        "/wp-content/plugins/w3-total-cache/",
        "/wp-content/plugins/wp-file-manager/",
        "/wp-content/plugins/wp-file-manager-pro/",
        "/wp-content/plugins/wp-config-file-editor/",
        "/wp-includes/", "/wp-includes/wlwmanifest.xml",
        "/wp-includes/version.php", "/wp-includes/js/tinymce/",
        "/wp-includes/certificates/",
    ])
    # Popular vulnerable plugins (well-documented CVEs)
    vuln_plugins = [
        "duplicator", "wpvivid-backuprestore", "backup-plugin", "backup",
        "backupbuddy", "backwpup", "wp-database-backup", "wp-file-manager",
        "wp-file-upload", "file-manager", "elementor", "elementor-pro",
        "wpforms", "ninja-forms", "gravity-forms", "contact-form-7",
        "wordpress-seo", "yoast-seo", "seo-by-rank-math", "all-in-one-seo-pack",
        "wpforo", "learnpress", "bbpress", "buddypress",
        "wp-super-cache", "w3-total-cache", "wp-fastest-cache",
        "wp-rocket", "cloudflare", "wordfence", "wp-security-scanner",
        "ithemes-security", "sucuri-scanner", "all-in-one-wp-security-and-firewall",
        "advanced-custom-fields", "acf", "acf-pro", "custom-post-type-ui",
        "user-role-editor", "members", "profile-builder",
        "user-registration", "ultimate-member", "buddyboss-platform",
        "woocommerce", "woocommerce-subscriptions", "woocommerce-services",
        "google-analytics-for-wordpress", "monsterinsights",
        "envira-gallery-lite", "nextgen-gallery", "regenerate-thumbnails",
        "revolution-slider", "layerslider", "master-slider",
        "smart-slider-3", "meta-box", "toolset-types",
        "tablepress", "wp-table-manager", "captcha", "really-simple-captcha",
        "wp-google-maps", "wp-mail-smtp", "wp-mail-logging",
    ]
    for p in vuln_plugins:
        entries.append(f"/wp-content/plugins/{p}/")
        entries.append(f"/wp-content/plugins/{p}/readme.txt")
        entries.append(f"/wp-content/plugins/{p}/README.txt")
        entries.append(f"/wp-content/plugins/{p}/changelog.txt")
        entries.append(f"/wp-content/plugins/{p}/{p}.php")
    # Popular themes
    themes = [
        "twentyten", "twentyeleven", "twentytwelve", "twentythirteen",
        "twentyfourteen", "twentyfifteen", "twentysixteen", "twentyseventeen",
        "twentyeighteen", "twentynineteen", "twentytwenty", "twentytwentyone",
        "twentytwentytwo", "twentytwentythree", "twentytwentyfour",
        "twentytwentyfive", "divi", "avada", "genesis", "hello-elementor",
        "astra", "oceanwp", "generatepress", "kadence", "neve", "sydney",
        "storefront",
    ]
    for t in themes:
        entries.append(f"/wp-content/themes/{t}/")
        entries.append(f"/wp-content/themes/{t}/style.css")
        entries.append(f"/wp-content/themes/{t}/functions.php")
        entries.append(f"/wp-content/themes/{t}/index.php")
    # Standard entrances + info
    entries.extend([
        "/readme.html", "/license.txt", "/wp-includes/rss-functions.php",
        "/wp-config.php.new", "/wp-config-old.php", "/wp-config.OLD",
        "/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml",
        "/robots.txt", "/wp-json/oembed/1.0/proxy",
        "/wp-content/plugins/all-in-one-wp-migration/",
        "/wp-content/uploads/wp-migrate-db-pro/",
    ])
    header = ("# WordPress — comprehensive per-service list. Every wp-admin PHP\n"
              "# handler, network/multisite variants, all AJAX ?action=… doorways,\n"
              "# every wp-json REST route family, popular vulnerable plugins +\n"
              "# themes (with common README/changelog files that leak version),\n"
              "# author enumeration query strings, backup variants of wp-config.\n"
              "# Aim: exhaustive coverage of the WP attack surface.")
    _emit("paths-wordpress", header, entries)


def build_paths_tomcat_java() -> None:
    """Comprehensive Java-stack management surface. Tomcat/JBoss/WildFly/
    WebLogic/GlassFish/Jenkins + every Spring Actuator endpoint (each in
    Spring 2.x with sensitive/prometheus variants) + Struts + Log4Shell
    trigger paths + Jolokia read/write/exec. Aim: ~700 entries."""
    entries: list[str] = []
    # Tomcat manager / host-manager surface
    tomcat_mgr = [
        "/manager", "/manager/", "/manager/html", "/manager/status",
        "/manager/text", "/manager/text/list", "/manager/text/serverinfo",
        "/manager/text/sessions", "/manager/text/threaddump", "/manager/text/vminfo",
        "/manager/text/findleaks", "/manager/text/ssl/certs", "/manager/text/sslConnectorConfigs",
        "/manager/text/tls-reload", "/manager/text/save",
        "/manager/text/deploy", "/manager/text/undeploy", "/manager/text/reload",
        "/manager/text/start", "/manager/text/stop", "/manager/text/expire",
        "/manager/text/resources", "/manager/text/roles",
        "/manager/jmxproxy/", "/manager/jmxproxy",
        "/manager/jmxproxy?get=Catalina:type=Server&att=serverInfo",
        "/host-manager", "/host-manager/", "/host-manager/html",
        "/host-manager/text", "/host-manager/text/list", "/host-manager/text/add",
        "/host-manager/text/remove", "/host-manager/text/start",
        "/host-manager/text/stop", "/host-manager/text/persist",
        "/host-manager/text/version",
    ]
    entries.extend(tomcat_mgr)
    entries.extend([f"{p}/dummy" for p in ("/manager", "/manager/html", "/manager/text")])
    # Tomcat examples (bundled demos — often on)
    entries.extend([
        "/examples/", "/examples/servlets/", "/examples/jsp/",
        "/examples/servlets/servlet/HelloWorldExample",
        "/examples/servlets/servlet/RequestInfoExample",
        "/examples/servlets/servlet/RequestHeaderExample",
        "/examples/servlets/servlet/SessionExample",
        "/examples/servlets/servlet/CookieExample",
        "/examples/jsp/snp/snoop.jsp", "/examples/jsp/snoop.jsp",
        "/examples/jsp/dates/date.jsp", "/examples/jsp/error/errorpge.jsp",
        "/examples/jsp/checkbox/check.jsp", "/examples/jsp/simpletag/foo.jsp",
        "/examples/jsp/xml/xml.jsp", "/examples/jsp/cal/cal2.jsp",
        "/docs/", "/docs/manager-howto.html", "/docs/api/", "/ROOT/", "/ROOT/index.jsp",
    ])
    # JBoss / WildFly / EAP
    jboss = [
        "/jmx-console/", "/jmx-console/HtmlAdaptor",
        "/jmx-console/HtmlAdaptor?action=inspectMBean&name=java.lang%3Atype%3DRuntime",
        "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Atype%3DServer",
        "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DShutdown",
        "/web-console/", "/web-console/Invoker", "/web-console/ServerInfo.jsp",
        "/web-console/Home.seam", "/web-console/style/",
        "/invoker/", "/invoker/JMXInvokerServlet", "/invoker/EJBInvokerServlet",
        "/invoker/readonly",
        "/status", "/status?full=true", "/admin-console/", "/admin-console/login.seam",
        "/console/", "/console/j_security_check", "/console/App.html",
        "/console/faces/jsp/console/login/LoginForm.jsp",
        "/soap/AXIS/",
    ]
    entries.extend(jboss)
    # WebLogic
    weblogic = [
        "/console/", "/console/login/LoginForm.jsp",
        "/console/faces/jsp/console/login/LoginForm.jsp",
        "/console/j_security_check",
        "/wls-wsat/CoordinatorPortType",
        "/wls-wsat/RegistrationRequesterPortType",
        "/wls-wsat/RegistrationPortTypeRPC",
        "/wls-wsat/ParticipantPortType",
        "/wls-wsat/RegistrationPortTypeRPC?wsdl",
        "/uddi/", "/uddiexplorer/",
        "/uddiexplorer/SearchPublicRegistries.jsp",
        "/uddiexplorer/SetupUDDIExplorer.jsp",
        "/_async/AsyncResponseService",
    ]
    entries.extend(weblogic)
    # Struts (CVE-2017-5638, CVE-2018-11776 style)
    entries.extend([
        "/struts/webconsole.html", "/struts2-showcase/", "/struts2-blank/",
        "/struts2-rest-showcase/", "/showcase.action", "/showcase/showcase.action",
        "/dispatcher.action", "/login.action", "/index.action",
        "/actions/errors.action", "/actions/index.action",
    ])
    # Jenkins full surface
    jenkins = [
        "/jenkins", "/jenkins/", "/jenkins/login", "/jenkins/api", "/jenkins/api/json",
        "/jenkins/api/xml", "/jenkins/manage", "/jenkins/manage/configureSecurity",
        "/jenkins/manage/configureSecurity/", "/jenkins/manage/configureClouds/",
        "/jenkins/manage/pluginManager/", "/jenkins/manage/pluginManager/installed",
        "/jenkins/manage/pluginManager/available",
        "/jenkins/manage/pluginManager/advanced", "/jenkins/manage/configureLog/",
        "/jenkins/manage/log/", "/jenkins/manage/systemInfo",
        "/jenkins/manage/nodes/", "/jenkins/manage/systemProperties",
        "/jenkins/script", "/jenkins/scriptText",
        "/jenkins/computer/(master)/systemInfo", "/jenkins/computer/(master)/log",
        "/jenkins/computer/(built-in)/systemInfo",
        "/jenkins/computer/(built-in)/log",
        "/jenkins/asynchPeople/api/json", "/jenkins/people/",
        "/jenkins/user/", "/jenkins/cli", "/jenkins/cli-proxy/",
        "/jenkins/whoAmI/api/json", "/jenkins/env-vars.html",
        "/jenkins/log/all", "/jenkins/log/rss", "/jenkins/loginError",
        "/jenkins/plugin/", "/jenkins/plugin/credentials/",
        "/jenkins/credentials/", "/jenkins/credentials/store/system/",
        "/jenkins/securityRealm/user/", "/jenkins/queue/api/json",
        "/jenkins/computer/api/json", "/jenkins/systemInfo",
        "/jenkins/pluginManager/api/json",
        "/hudson/", "/hudson/api/json", "/hudson/manage",
    ]
    entries.extend(jenkins)
    # Spring Boot Actuator — every documented endpoint under BOTH /actuator/*
    # and root (Boot 1.x). Multiply per common context path.
    actuator_eps = [
        "auditevents", "beans", "caches", "conditions", "configprops",
        "env", "flyway", "health", "heapdump", "httptrace", "httpexchanges",
        "info", "integrationgraph", "jolokia", "logfile", "loggers",
        "mappings", "metrics", "prometheus", "quartz", "refresh",
        "scheduledtasks", "sessions", "shutdown", "startup", "threaddump",
        "trace", "gateway/routes", "gateway/refresh", "gateway/globalfilters",
        "gateway/routefilters", "gateway/routes/{id}",
        "sbom", "startup", "liquibase", "flyway", "restart",
        "env/os.name", "env/user.name", "env/java.version", "env/os.arch",
        "env/spring.datasource.password", "env/spring.datasource.username",
        "env/spring.datasource.url", "env/management.endpoints.web.exposure.include",
        "loggers/root", "metrics/jvm.memory.used", "metrics/http.server.requests",
    ]
    for prefix in ("/actuator", "", "/monitoring", "/management", "/manage",
                     "/monitor", "/admin"):
        for ep in actuator_eps:
            entries.append(f"{prefix}/{ep}" if prefix else f"/{ep}")
    # Jolokia
    entries.extend([
        "/jolokia/", "/jolokia/list", "/jolokia/read", "/jolokia/write",
        "/jolokia/version", "/jolokia/search",
        "/jolokia/exec", "/jolokia/notification",
        "/jolokia/list/java.lang", "/jolokia/read/java.lang:type=Memory/HeapMemoryUsage",
        "/jolokia/read/java.lang:type=Threading/ThreadCount",
        "/jolokia/read/java.lang:type=Runtime/SystemProperties",
        "/jolokia/read/java.lang:type=Runtime/InputArguments",
        "/jolokia/exec/java.lang:type=Runtime/dumpAllThreads",
    ])
    # Axis / gRPC / SOAP
    entries.extend([
        "/services/", "/services/Version", "/services/AdminService",
        "/services/listServices", "/axis/happyaxis.jsp",
        "/axis/servlet/AxisServlet", "/axis/EchoHeaders.jws",
        "/axis2/", "/axis2/axis2-admin/", "/axis2/axis2-admin/login",
        "/axis2/services/", "/axis2/services/ListServices",
        "/axis2/services/Version", "/axis2/services/Version/getVersion",
        "/CFIDE/administrator/", "/CFIDE/administrator/enter.cfm",
        "/CFIDE/adminapi/", "/CFIDE/adminapi/administrator.cfc",
        "/CFIDE/adminapi/user.cfc", "/CFIDE/componentutils/login.cfm",
        "/CFIDE/wizards/common/utils.cfc", "/CFIDE/gettingstarted/",
    ])
    # WebSphere / Coldfusion
    entries.extend([
        "/ibm/console/", "/ibm/console/login.do",
        "/ibm/console/j_security_check", "/ibm/console/logon.jsp",
        "/wasadmin/", "/admin/", "/PSIGW/HttpListeningConnector",
    ])
    # Log4Shell trigger URLs (well-known JNDI probe targets) — informational
    entries.extend([
        "/log4j/", "/l4j/", "/lookup/", "/jndi/",
    ])
    header = ("# Java-stack management — Tomcat/JBoss/WildFly/WebLogic/\n"
              "# GlassFish/Jenkins + every Spring Actuator endpoint (crossed\n"
              "# with 7 common context prefixes) + Struts / Log4Shell probe\n"
              "# targets + Jolokia read/write/exec + Axis/Axis2/CFIDE/\n"
              "# WebSphere. Aim: exhaustive Java admin surface.")
    _emit("paths-tomcat-java", header, entries)


def build_paths_secrets() -> None:
    """Comprehensive secret/config file names. Every .env variant × every
    stage prefix × every backup suffix, plus every well-known credential
    file, private key naming convention, terraform/ansible state, CI/CD
    secret files, DB dumps. Aim: ~1,000+ entries."""
    entries: list[str] = []
    # .env variants: base × stage × suffix
    env_bases = [".env", "env"]
    env_stages = [
        "", ".local", ".dev", ".development", ".prod", ".production",
        ".staging", ".stage", ".test", ".testing", ".qa", ".uat", ".demo",
        ".sandbox", ".preview", ".ci", ".build", ".docker", ".compose",
        ".k8s", ".prod.local", ".secret", ".secrets", ".vars", ".env",
        ".config", ".override", ".example", ".sample", ".dist", ".template",
    ]
    env_suffixes = [
        "", ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo",
        "~", ".txt", ".gz", ".zip", ".tar", ".tar.gz",
    ]
    for b in env_bases:
        for s in env_stages:
            for suf in env_suffixes:
                entries.append(f"/{b}{s}{suf}")
    # config file naming — every framework's convention
    entries.extend([
        "/.envrc", "/.env-cmdrc", "/env.js", "/environment.js",
        "/environment.ts", "/config.env", "/config.env.example",
        "/settings.env", "/dev.env", "/prod.env",
        "/config/environments/development.rb", "/config/environments/production.rb",
        "/config/environments/staging.rb", "/config/environments/test.rb",
        "/config/master.key", "/config/credentials.yml.enc",
        "/config/secrets.yml", "/config/secrets.yml.example",
        "/config/database.yml", "/config/database.yml.example",
        "/config/application.yml", "/config/application.properties",
        "/config/settings.yml", "/config/settings.local.yml",
        "/config/settings.py", "/config/local_settings.py",
        "/config/config.py", "/config/dev.py", "/config/prod.py",
        "/config.local.php", "/local-config.php", "/local.php",
        "/config/config.php", "/config/db.php", "/config/database.php",
        "/config/mail.php", "/config/services.php",
    ])
    # AWS / cloud SDK config
    entries.extend([
        "/.aws/credentials", "/.aws/config", "/.aws/cli/history",
        "/root/.aws/credentials", "/root/.aws/config",
        "/home/ubuntu/.aws/credentials", "/home/ec2-user/.aws/credentials",
        "/var/task/.aws/credentials", "/tmp/aws-cli-cache/",
        "/aws.config", "/aws-credentials.json", "/aws_config",
        "/.gcp/credentials.json", "/.gcp/service-account.json",
        "/gcp-service-account.json", "/service-account.json",
        "/service-account-key.json",
        "/root/.config/gcloud/credentials.db",
        "/root/.config/gcloud/access_tokens.db",
        "/root/.config/gcloud/application_default_credentials.json",
        "/.azure/credentials", "/.azure/accessTokens.json",
        "/root/.azure/credentials", "/azure-credentials.json",
        "/azure-service-principal.json", "/service-principal.json",
        "/.docker/config.json", "/root/.docker/config.json",
        "/home/ubuntu/.docker/config.json",
        "/.kube/config", "/root/.kube/config",
        "/var/lib/kubelet/kubeconfig", "/etc/kubernetes/kubelet.conf",
        "/etc/kubernetes/admin.conf", "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/etc/rancher/k3s/k3s.yaml", "/etc/rancher/rke2/rke2.yaml",
    ])
    # Terraform / ansible / puppet / chef
    for f in ["terraform.tfstate", "terraform.tfstate.backup", "terraform.tfvars",
                "terraform.tfvars.json", "main.tf", "main.tf.bak", "variables.tf",
                "outputs.tf", "backend.tf", ".terraform/terraform.tfstate",
                ".terraform.lock.hcl", ".terragrunt-cache/"]:
        entries.append(f"/{f}")
    for f in ["ansible.cfg", "vault-password", "vault-password.txt", "vault_pass",
                "vault_pass.txt", ".vault_pass", ".vault_pass.txt", "hosts",
                "hosts.yaml", "hosts.yml", "inventory", "inventory.yaml",
                "inventory.yml", "inventory.ini", "group_vars/all",
                "group_vars/all.yml", "host_vars/", "playbook.yml", "site.yml",
                "roles/", "requirements.yml", "meta/main.yml"]:
        entries.append(f"/{f}")
    for f in ["Puppetfile", "hiera.yaml", "hiera.yaml.example",
                "manifests/site.pp", "modules/", "environments/production/hiera.yaml"]:
        entries.append(f"/{f}")
    for f in ["Berksfile", "Berksfile.lock", ".chef/knife.rb", ".chef/user.pem",
                "cookbooks/", "data_bags/", "roles/", "environments/"]:
        entries.append(f"/{f}")
    # DB dumps / backups — every extension variant
    db_bases = ["backup", "backups", "db", "database", "dump", "sql",
                  "site", "www", "wwwroot", "htdocs", "public_html", "web",
                  "mysql", "postgres", "mongo", "redis"]
    db_suffixes = [".sql", ".sql.gz", ".sql.bz2", ".sql.zip", ".tar",
                     ".tar.gz", ".tar.bz2", ".zip", ".7z", ".rar", ".dump",
                     ".bak", ".backup", ".old", ".rdb", ".bson", "_dump.sql",
                     "_backup.sql", "_bak.sql", ".dbf", "-old.sql"]
    for b in db_bases:
        for s in db_suffixes:
            entries.append(f"/{b}{s}")
    # SSH / TLS keys
    for name in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss",
                   "id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub"]:
        entries.append(f"/{name}")
        entries.append(f"/.ssh/{name}")
        entries.append(f"/root/.ssh/{name}")
        entries.append(f"/home/ubuntu/.ssh/{name}")
        entries.append(f"/home/ec2-user/.ssh/{name}")
    entries.extend([
        "/.ssh/authorized_keys", "/.ssh/known_hosts", "/.ssh/config",
        "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
    ])
    # TLS/certs
    for f in ["server.key", "server.pem", "server.crt", "server.cert",
                "private.key", "private.pem", "privatekey.pem",
                "localhost.key", "localhost.pem", "localhost.crt",
                "tls.key", "tls.crt", "tls.pem", "ca.key", "ca.pem", "ca.crt",
                "cert.pem", "cert.key", "fullchain.pem", "chain.pem",
                "key.pem", "keystore.jks", "keystore.p12", "cacerts",
                "identity.jks", "truststore.jks", "wildcard.key",
                "wildcard.pem", "star.pem"]:
        entries.append(f"/{f}")
        entries.append(f"/certs/{f}")
        entries.append(f"/ssl/{f}")
        entries.append(f"/etc/ssl/private/{f}")
        entries.append(f"/etc/nginx/ssl/{f}")
    # CI/CD secrets
    for f in [".gitlab-ci.yml", ".gitlab-ci.yml.bak", ".github/workflows/deploy.yml",
                ".github/workflows/main.yml", ".github/workflows/ci.yml",
                ".circleci/config.yml", ".travis.yml", ".drone.yml", "bitbucket-pipelines.yml",
                "azure-pipelines.yml", "appveyor.yml", "cloudbuild.yaml",
                "buildspec.yml", "Jenkinsfile", "Jenkinsfile.groovy",
                ".jenkins/", "sonar-project.properties",
                ".sonarcloud.properties", ".coveragerc", "codecov.yml"]:
        entries.append(f"/{f}")
    # Historic secret file names
    for f in ["credentials.yaml", "credentials.yml", "credentials.json",
                "credentials.txt", "credentials.csv", "credentials.xml",
                "credential.json", "creds.json", "creds.txt", "creds.csv",
                "passwords.txt", "passwords.csv", "passwords.xlsx",
                "passwords.xls", "password.txt", "password.csv",
                "passwd", "passwd.bak", "passwd.txt", "passwd.csv",
                "secret.json", "secret.yaml", "secret.yml", "secret.txt",
                "secrets.json", "secrets.yaml", "secrets.yml", "secrets.txt",
                "secrets.env", "secret.php", ".secret", "secret", "secrets/",
                ".aws_credentials", ".s3cfg", ".s3cfg.bak", ".boto",
                ".htpasswd", ".htpasswd.bak", "htpasswd", "apache/.htpasswd",
                ".npmrc", ".pypirc", ".dockercfg", ".rediscli_history",
                ".mysql_history", ".psql_history", ".bash_history",
                ".sh_history", ".zsh_history", ".python_history", ".viminfo",
                ".pgpass", "pg_service.conf", "pg_hba.conf", "postgresql.conf",
                "my.cnf", ".my.cnf", "mongod.conf", "redis.conf",
                "app.settings.json", "local.settings.json",
                "appsettings.json", "appsettings.Development.json",
                "appsettings.Production.json", "web.config", "web.config.bak"]:
        entries.append(f"/{f}")
    # Historical/legacy names still shipped with old CMS
    for f in ["adminuser", "administrator", "adminpass", "passwd.dat", "pwd.txt",
                "userlist.txt", "users.txt", "employee.txt"]:
        entries.append(f"/{f}")
    header = ("# Secret / config file names — comprehensive. .env variants\n"
              "# (base × stage × suffix), every framework config file, cloud\n"
              "# SDK credentials (AWS/GCP/Azure/Docker/K8s), Terraform/Ansible/\n"
              "# Puppet/Chef state + creds, DB dumps × 20 extensions, SSH/TLS\n"
              "# keys × common paths, CI/CD secret files. Aim: exhaustive.")
    _emit("paths-secrets", header, entries)


def build_creds_engine_expanded() -> None:
    """Expand each engine-specific credential list to comprehensively
    cover every documented default + Docker image + Bitnami/Ubuntu/Debian
    package variant + wild-recurring passwords."""
    # MSSQL
    mssql_users = ["sa", "admin", "administrator", "sqladmin", "mssql",
                     "mssqluser", "dbadmin", "dbowner", "reporting", "backup"]
    mssql_pw = [
        "", "sa", "sql", "mssql", "password", "Password1", "Password123",
        "P@ssw0rd", "P@ssw0rd1", "P@ssword", "P@ssword1", "changeme",
        "changeit", "admin", "root", "123456", "1234567890", "12345678",
        "yourStrong(!)Password", "yourStrongPassword", "MyStrongPass123!",
        "MyStrongPass!23", "StrongPassword!", "StrongP@ssw0rd", "S3cret2024!",
        "S3cret1234!", "Password!23", "Password!234", "Welcome1", "Welcome1!",
        "Welcome123!", "Winter2024!", "Summer2024!", "Spring2024!", "Fall2024!",
        "Winter2023!", "Summer2023!", "Spring2023!", "Fall2023!",
        "Winter2025!", "Summer2025!", "!QAZ2wsx", "qwerty", "qwerty123",
        "Qaz123456!", "P@55w0rd", "pa$$w0rd", "M$SQL2019!", "M$SQL2022!",
        "Docker!23", "Docker!2023", "sqlserver", "MsSqL2019!", "MsSqL2022!",
        "Aa123456!", "Aa1234567!", "Passw0rd2024", "P@ssword2024",
        "Company1", "Company123", "Corp2024",
    ]
    ms_entries = [f"{u}:{p}" for u in mssql_users for p in mssql_pw]
    ms_entries.extend(["guest:", "public:", "sqlbackup:"])
    _emit("creds-mssql",
          "# MSSQL sa passwords — comprehensive coverage. Every documented\n"
          "# default from Microsoft docker-quickstart, Bitnami images, plus\n"
          "# wild recurring seasonal/company patterns × 10 SQL Auth users.",
          ms_entries)
    # Postgres
    pg_users = ["postgres", "admin", "pgadmin", "dba", "root",
                  "app", "appuser", "webuser", "readonly", "readwrite",
                  "backup", "replicator", "airflow", "gitlab", "keycloak",
                  "confluence", "jira", "sonar", "grafana", "matomo",
                  "wordpress", "drupal", "postgresql"]
    pg_pw = [
        "", "postgres", "password", "admin", "root", "changeme", "changeit",
        "default", "pgpass", "pgsql", "pgadmin", "secret", "Password1",
        "P@ssw0rd", "P@ssw0rd1", "mysecretpassword", "docker", "1234",
        "12345", "123456", "test", "demo", "Aa123456", "P@55w0rd",
        "Welcome1", "Winter2024!", "Summer2024!", "Company1", "Corp2024",
        "postgrespassword", "postgres1234", "pgpassword",
        "postgres!", "postgres@123",
    ]
    pg_entries = [f"{u}:{p}" for u in pg_users for p in pg_pw]
    _emit("creds-postgres",
          "# PostgreSQL defaults — comprehensive coverage. Every documented\n"
          "# quick-start password × application-specific role name (airflow,\n"
          "# gitlab, keycloak, jira, wordpress...) common in real deployments.",
          pg_entries)
    # MongoDB
    mongo_users = ["admin", "root", "mongo", "mongodb", "mongoadmin",
                     "myUserAdmin", "test", "readonly", "readwrite", "backup",
                     "app", "appuser", "webuser", "clusterAdmin", "dbOwner",
                     "userAdmin"]
    mongo_pw = [
        "admin", "password", "changeme", "secret", "mongo", "mongodb",
        "root", "P@ssw0rd", "Password1", "abc123", "1234", "12345",
        "123456", "12345678", "changeit", "test", "demo", "Aa123456",
        "readonly", "readwrite", "backup", "Winter2024!", "Summer2024!",
        "Welcome1", "Welcome123", "mongo1234", "mongoDBpass",
    ]
    mongo_entries = [f"{u}:{p}" for u in mongo_users for p in mongo_pw]
    _emit("creds-mongodb",
          "# MongoDB defaults — comprehensive. Docker quick-start + Bitnami\n"
          "# + Atlas + application-role variants × common weak passwords.",
          mongo_entries)
    # MySQL
    mysql_users = ["root", "mysql", "admin", "dba", "webadmin", "readonly",
                     "readwrite", "backup", "replica", "user", "test", "demo",
                     "app", "appuser", "wordpress", "drupal", "phpmyadmin",
                     "webuser", "sqluser", "reporter"]
    mysql_pw = [
        "", "root", "toor", "mysql", "password", "changeme", "admin",
        "default", "1234", "12345", "123456", "mariadb", "mysqlpass",
        "P@ssw0rd", "Password1", "MyStrongPass123!", "secret", "docker",
        "changeit", "1234567890", "abc123", "Aa123456", "Welcome1",
        "Winter2024!", "Summer2024!", "Company1", "Corp2024", "mysql1234",
        "root1234", "root123", "test", "demo",
    ]
    my_entries = [f"{u}:{p}" for u in mysql_users for p in mysql_pw]
    _emit("creds-mysql",
          "# MySQL / MariaDB defaults — comprehensive. root/blank at the top\n"
          "# (historical MySQL default still shipped by many images) plus\n"
          "# every documented quick-start × app-user variant.",
          my_entries)
    # MongoDB / redis — pattern users
    redis_users = ["default", "admin", "user", "readonly", "readwrite",
                     "app", "backup", "replica", "monitor"]
    redis_pw = [
        "redis", "password", "foobared", "changeme", "admin", "123456",
        "secret", "redispass", "redispasswd", "redisdefaultpassword",
        "P@ssw0rd", "Password1", "Aa123456", "Welcome1", "Winter2024!",
        "Company1", "Corp2024", "changeit", "redispass1234", "test",
    ]
    r_entries = [f"{u}:{p}" for u in redis_users for p in redis_pw]
    _emit("creds-redis",
          "# Redis requirepass values — comprehensive. Pre-6.0 accepts any\n"
          "# username (`default` common); 6.x ACL users listed at bottom.",
          r_entries)


if __name__ == "__main__":
    print(f"Writing to {OUT}\n")
    build_paths_big()
    build_creds_top_passwords()
    build_users_big()
    build_creds_defaults_big()
    build_subdomains_big()
    build_paths_wordpress()
    build_paths_tomcat_java()
    build_paths_secrets()
    build_creds_engine_expanded()
    print("\nDone.")
