#!/bin/bash
# Set smbpasswd at runtime (needs smbd config loaded)
(echo "smbpass123"; echo "smbpass123") | smbpasswd -a -s smbuser 2>/dev/null
exec smbd --foreground --no-process-group
