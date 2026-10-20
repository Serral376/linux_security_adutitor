"""Security check modules."""

from .users import check_users
from .ssh import check_ssh
from .permissions import check_permissions
from .network import check_network
from .packages import check_packages
from .services import check_services
from .firewall import check_firewall
from .cron import check_cron

AVAILABLE_CHECKS = {
    "users": check_users,
    "ssh": check_ssh,
    "permissions": check_permissions,
    "network": check_network,
    "packages": check_packages,
    "services": check_services,
    "firewall": check_firewall,
    "cron": check_cron,
}
