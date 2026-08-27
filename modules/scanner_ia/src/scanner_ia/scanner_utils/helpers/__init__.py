#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShieldAI — Helpers d'authentification
"""

import os
import sys

sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, "..", "..", ".."))))
from scanner_ia.scanner_utils.helpers.dvwa_helpers import (
    dvwa_login,
    dvwa_set_security_level,
    dvwa_full_setup,
)
from scanner_ia.scanner_utils.helpers.auth_helpers import (
    form_login,
    csrf_form_login,
    basic_auth,
    bearer_token,
    api_key_header,
    api_key_cookie,
    inject_cookies,
    inject_headers,
    jwt_login,
    oauth2_password,
    digest_auth,
    multi_step_login,
    noop,
    dvwa_auth,
    juice_shop_auth,
    webgoat_auth,
    bwapp_auth,
    mutillidae_auth,
    wordpress_auth,
    joomla_auth,
    phpmyadmin_auth,
    grafana_auth,
    jenkins_auth,
    gitlab_auth,
    gitea_auth,
    nextcloud_auth,
    portainer_auth,
    keycloak_auth,
    metabase_auth,
    awx_auth,
    roundcube_auth,
    openwrt_auth,
    pfsense_auth,
)

__all__ = [
    # dvwa_helpers (legacy)
    "dvwa_login",
    "dvwa_set_security_level",
    "dvwa_full_setup",
    # génériques
    "form_login",
    "csrf_form_login",
    "basic_auth",
    "bearer_token",
    "api_key_header",
    "api_key_cookie",
    "inject_cookies",
    "inject_headers",
    "jwt_login",
    "oauth2_password",
    "digest_auth",
    "multi_step_login",
    "noop",
    # apps connues
    "dvwa_auth",
    "juice_shop_auth",
    "webgoat_auth",
    "bwapp_auth",
    "mutillidae_auth",
    "wordpress_auth",
    "joomla_auth",
    "phpmyadmin_auth",
    "grafana_auth",
    "jenkins_auth",
    "gitlab_auth",
    "gitea_auth",
    "nextcloud_auth",
    "portainer_auth",
    "keycloak_auth",
    "metabase_auth",
    "awx_auth",
    "roundcube_auth",
    "openwrt_auth",
    "pfsense_auth",
]
