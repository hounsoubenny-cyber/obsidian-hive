#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 22:25:14 2026

@author: hounsousamuel
"""

from ids_ips_ia.ids_ips_utils.instance_id import INSTANCE_SUFFIX

NFT_TABLE_NAME = f"shieldai_ids_ips_table_{INSTANCE_SUFFIX}"
DEFAULT_RULE_TIMEOUT = 60
DEFAULT_RULE_UNIT = "m"

NFT_RATE_LIMITE = "100/minute"
NFT_RATE_DATA_LIMITE = "100 mbytes/second"

# cmds = [
#     f"nft add table inet {NFT_TABLE_NAME}",
#     f"nft add chain inet {NFT_TABLE_NAME} input {{ type filter hook input priority 0 ; policy accept }}",  #Chain pour trafic entrant
#     f"nft add chain inet {NFT_TABLE_NAME} output {{ type filter hook output priority 0 ; policy accept }}", # Chain pour traffic sortant
    
#     f"nft add set inet {NFT_TABLE_NAME} whitelist_ip4 {{ type ipv4_addr ; flags interval , dynamic }}",
#     f"nft add set inet {NFT_TABLE_NAME} whitelist_ip6 {{ type ipv6_addr ; flags interval , dynamic }}",
    
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_input_ip4 {{ type ipv4_addr ; flags interval , timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_input_ip4 {{ type ipv4_addr ; flags interval ,  timeout, dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_data_input_ip4 {{ type ipv4_addr ; flags interval ,  timeout, dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_input_ip6 {{ type ipv6_addr ; flags interval ,  timeout, dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_input_ip6 {{ type ipv6_addr ; flags interval ,  timeout, dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_data_input_ip6 {{ type ipv6_addr ; flags interval ,  timeout, dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
    
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_output_ip4 {{ type ipv4_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_output_ip4 {{ type ipv4_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_data_output_ip4 {{ type ipv4_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_output_ip6 {{ type ipv6_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_output_ip6 {{ type ipv6_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
#     f"nft add set inet {NFT_TABLE_NAME} blacklist_rate_limite_data_output_ip6 {{ type ipv6_addr ; flags interval ,  timeout , dynamic ; timeout {DEFAULT_RULE_TIMEOUT}{DEFAULT_RULE_UNIT} }}",
    
#     f"nft add rule inet {NFT_TABLE_NAME} input ip saddr @whitelist_ip4 accept",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip6 saddr @whitelist_ip6 accept",
    
#     f"nft add rule inet {NFT_TABLE_NAME} input ip saddr @blacklist_input_ip4 log prefix \"SHIELD_IDS_IPS_BLACKLIST_IP4\" drop",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip saddr @blacklist_rate_limite_input_ip4 meter rate_in_ip4_meter {{ ip saddr limit rate {NFT_RATE_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip saddr @blacklist_rate_limite_data_input_ip4 meter rate_data_in_ip4_meter {{ ip saddr limit rate {NFT_RATE_DATA_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip6 saddr @blacklist_input_ip6 log prefix \"SHIELD_IDS_IPS_BLACKLIST_IP6\" drop",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip6 saddr @blacklist_rate_limite_input_ip6 meter rate_in_ip6_meter {{ ip6 saddr limit rate {NFT_RATE_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} input ip6 saddr @blacklist_rate_limite_data_input_ip6 meter rate_data_in_ip6_meter {{ ip6 saddr limit rate {NFT_RATE_DATA_LIMITE} }} accept",
    
#     f"nft add rule inet {NFT_TABLE_NAME} output ip daddr @blacklist_output_ip4 log prefix \"SHIELD_IDS_IPS_BLACKLIST_IP4\" drop",
#     f"nft add rule inet {NFT_TABLE_NAME} output ip daddr @blacklist_rate_limite_output_ip4 meter rate_out_ip4_meter {{ ip daddr limit rate {NFT_RATE_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} output ip daddr @blacklist_rate_limite_data_output_ip4 meter rate_data_out_ip4_meter {{ ip daddr limit rate {NFT_RATE_DATA_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} output ip6 daddr @blacklist_output_ip6 log prefix \"SHIELD_IDS_IPS_BLACKLIST_IP6\" drop",
#     f"nft add rule inet {NFT_TABLE_NAME} output ip6 daddr @blacklist_rate_limite_output_ip6 meter rate_in_ip6_meter {{ ip6 daddr limit rate {NFT_RATE_LIMITE} }} accept",
#     f"nft add rule inet {NFT_TABLE_NAME} output ip6 daddr @blacklist_rate_limite_data_output_ip6 meter rate_data_in_ip6_meter {{ ip6 daddr limit rate {NFT_RATE_DATA_LIMITE} }} accept",
#     ]
