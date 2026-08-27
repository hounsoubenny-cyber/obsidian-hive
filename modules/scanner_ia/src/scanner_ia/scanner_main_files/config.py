#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 18 13:46:09 2026

@author: hounsousamuel
"""

VULNS = [
    'SQLi', 'CMDi', 'InsecDeser', 'InsecUpload', 'BufOvr', 'CredsExpose', 
    'BrokenAuth', 'XSS', 'DirTrav', 'XXE', 'NoSQLi', 'LDAPi', 'InsecPerm', 
    'IDOR', 'SessFix', 'SSRF', 'SSTI', 'Prototype_Pollution', 
    'HTTP_Request_Smuggling', 'XPATH_Injection', 'GraphQLi', 
    'CORS', 'CSRF', 'RateLimit', 'InfoDisc', 'InsecCrypto',
    'OpenRedirect', 'JWT', 'CRLF_Injection', 'RaceCondition'
]

FEATURES_LIST = [
    # ===== 1. Features HTML/Balises (13 features) =====
    'num_balise_a',
    'num_balise_img',
    'num_balise_script',
    'num_balise_link',
    'num_balise_style',
    'num_balise_iframe',
    'num_balise_video',
    'num_balise_audio',
    'num_balise_embed',
    'num_balise_object',
    'num_balise_form',
    'num_balise_meta',
    'num_balise_cite',
    
    # ===== 2. Features Page/Réponse (12 features) =====
    'status_code',
    'deep',
    'response_time',
    'body_length',
    'body_entropy',
    'js_code_entropy',
    'has_password_field',
    'has_file_upload',
    'has_hidden_fields',
    'num_links',
    'num_html_link',
    'other_link_ratio',
    'n_redirects',
    
    # ===== 3. Features Sécurité Headers (7 features) =====
    'strict_transport_security',
    'x_frame_options',
    'x_content_type_options',
    'content_security_policy',
    'x_xss_protection',
    'referrer_policy',
    'permissions_policy',
    
    # ===== 4. Features Technologies (12 features) =====
    'tech_wordpress',
    'tech_joomla',
    'tech_drupal',
    'tech_laravel',
    'tech_django',
    'tech_express',
    'tech_php',
    'tech_aspnet',
    'tech_jquery',
    'tech_angular',
    'tech_react',
    
    # ===== 5. Features Analyse Passive (4 features) =====
    'total_passive_issues',
    'passive_high_count',
    'passive_critical_count',
    
    # ===== 6. Features Analyse Code (11 features) =====
    'code_body_total_vulns',
    'code_body_critical_vulns',
    'code_body_medium_vulns',
    'code_body_high_vulns',
    'code_body_low_vulns',
    'code_body_max_score',
    'code_scripts_total_vulns',
    'code_scripts_high_vulns',
    'code_scripts_critical_vulns',
    'code_scripts_medium_vulns',
    'code_scripts_low_vulns',
    # 'code_scripts_max_score',
    
    # ===== 7. Features Fuzzer - Binaires (31 features) =====
    'fuzzer_SQLi',
    'fuzzer_CMDi',
    'fuzzer_InsecDeser',
    'fuzzer_InsecUpload',
    'fuzzer_BufOvr',
    'fuzzer_CredsExpose',
    'fuzzer_BrokenAuth',
    'fuzzer_XSS',
    'fuzzer_DirTrav',
    'fuzzer_XXE',
    'fuzzer_NoSQLi',
    'fuzzer_LDAPi',
    'fuzzer_InsecPerm',
    'fuzzer_IDOR',
    'fuzzer_SessFix',
    'fuzzer_SSRF',
    'fuzzer_SSTI',
    'fuzzer_Prototype_Pollution',
    'fuzzer_HTTP_Request_Smuggling',
    'fuzzer_XPATH_Injection',
    'fuzzer_GraphQLi',
    'fuzzer_CORS',
    'fuzzer_CSRF',
    'fuzzer_RateLimit',
    'fuzzer_InfoDisc',
    'fuzzer_InsecCrypto',
    'fuzzer_OpenRedirect',
    'fuzzer_JWT',
    'fuzzer_CRLF_Injection',
    'fuzzer_RaceCondition',
    
    # ===== 8. Features Fuzzer - Métriques (6 features) =====
    'num_active_test',
    'fuzer_ratio_vuln',
    'fuzzer_ratio_indicators_matched',
    'fuzzer_ration_status_changed',
    'fuzzer_ratio_headers_changed',
    'fuzzer_ratio_body_changed',
    'fuzzer_max_score',
]

FEATURES_BY_CATEGORY = {
    'html_balises': [
        'num_balise_a', 'num_balise_img', 'num_balise_script', 'num_balise_link',
        'num_balise_style', 'num_balise_iframe', 'num_balise_video', 'num_balise_audio',
        'num_balise_embed', 'num_balise_object', 'num_balise_form', 'num_balise_meta',
        'num_balise_cite'
    ],
    
    'page_reponse': [
        'status_code', 'deep', 'response_time', 'body_length', 'body_entropy',
        'js_code_entropy', 'has_password_field', 'has_file_upload', 'has_hidden_fields',
        'num_links', 'num_html_link', 'other_link_ratio', 'n_redirects'
    ],
    
    'securite_headers': [
        'strict_transport_security', 'x_frame_options', 'x_content_type_options',
        'content_security_policy', 'x_xss_protection', 'referrer_policy',
        'permissions_policy'
    ],
    
    'technologies': [
        'tech_wordpress', 'tech_joomla', 'tech_drupal', 'tech_laravel', 'tech_django',
        'tech_express', 'tech_php', 'tech_aspnet', 'tech_jquery', 'tech_angular',
        'tech_react'
    ],
    
    'analyse_passive': [
        'total_passive_issues', 'passive_high_count', 'passive_critical_count',
    ],
    
    'analyse_code': [
        'code_body_total_vulns', 'code_body_critical_vulns', 'code_body_medium_vulns',
        'code_body_high_vulns', 'code_body_low_vulns', 'code_body_max_score',
        'code_scripts_total_vulns', 'code_scripts_high_vulns',
        'code_scripts_critical_vulns', 'code_scripts_medium_vulns',
        'code_scripts_low_vulns', #'code_scripts_max_score'
    ],
    
    'fuzzer_binaires': [
        'fuzzer_SQLi', 'fuzzer_CMDi', 'fuzzer_InsecDeser', 'fuzzer_InsecUpload',
        'fuzzer_BufOvr', 'fuzzer_CredsExpose', 'fuzzer_BrokenAuth', 'fuzzer_XSS',
        'fuzzer_DirTrav', 'fuzzer_XXE', 'fuzzer_NoSQLi', 'fuzzer_LDAPi',
        'fuzzer_InsecPerm', 'fuzzer_IDOR', 'fuzzer_SessFix', 'fuzzer_SSRF',
        'fuzzer_SSTI', 'fuzzer_Prototype_Pollution', 'fuzzer_HTTP_Request_Smuggling',
        'fuzzer_XPATH_Injection', 'fuzzer_GraphQLi', 'fuzzer_CORS', 'fuzzer_CSRF',
        'fuzzer_RateLimit', 'fuzzer_InfoDisc', 'fuzzer_InsecCrypto',
        'fuzzer_OpenRedirect', 'fuzzer_JWT', 'fuzzer_CRLF_Injection',
        'fuzzer_RaceCondition'
    ],
    
    'fuzzer_metriques': [
        'num_active_test', 'fuzer_ratio_vuln', 'fuzzer_ratio_indicators_matched',
        'fuzzer_ration_status_changed', 'fuzzer_ratio_headers_changed',
        'fuzzer_ratio_body_changed', 'fuzzer_max_score'
    ]
}
