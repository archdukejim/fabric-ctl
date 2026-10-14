from add_group_member import add_group_member
from add_sudo_rule import add_sudo_rule
from adopt_linux_machines import adopt_linux_machines
from create_host_group import create_host_group
from create_machine import create_machine
from create_person import create_person
from get_person import get_person
from grant_site_role import grant_site_role
from link_device_cert import link_device_cert
from list_host_groups import list_host_groups
from list_machines import list_machines
from list_people import list_people
from list_ssh_hosts import list_ssh_hosts
from list_sudo_rules import list_sudo_rules
from logon_groups import logon_groups
from list_site_roles import list_site_roles
from move_person import move_person
from place_fabric_host import place_fabric_host
from prepare_ssh_hosts import prepare_ssh_hosts
from read_dc_type_request import read_dc_type_request
from read_devices import read_devices
from read_networks import read_networks
from read_plan import read_plan
from read_scan_requests import read_scan_requests
from remake_site_group import remake_site_group
from read_site_dcs import read_site_dcs
from read_ssh_cas import read_ssh_cas
from remove_device import remove_device
from remove_group_member import remove_group_member
from remove_host_group import remove_host_group
from remove_machine import remove_machine
from remove_person import remove_person
from remove_role import remove_role
from remove_sudo_rule import remove_sudo_rule
from reset_password import reset_password
from save_device import save_device
from save_role import save_role
from set_dc_type_request import set_dc_type_request
from set_host_group_member import set_host_group_member
from set_machine import set_machine
from set_machine_class import set_machine_class
from set_person import set_person
from set_ssh_cas import set_ssh_cas
from set_ssh_host import set_ssh_host
from site_info import site_info
from sort_windows_machines import sort_windows_machines
from ssh_user_sites import ssh_user_sites
from sync_rodc_cache import sync_rodc_cache
from unlock_person import unlock_person
from write_plan import write_plan
from write_scan_request import write_scan_request

# the operations fabric-agent may ask for (directory_op): each is f(samdb, lp, site, **args) -> JSON-able result
OPS = {
    "add_group_member": add_group_member,
    "add_sudo_rule": add_sudo_rule,
    "adopt_linux_machines": adopt_linux_machines,
    "create_host_group": create_host_group,
    "create_machine": create_machine,
    "create_person": create_person,
    "get_person": get_person,
    "grant_site_role": grant_site_role,
    "link_device_cert": link_device_cert,
    "list_host_groups": list_host_groups,
    "list_machines": list_machines,
    "list_people": list_people,
    "list_ssh_hosts": list_ssh_hosts,
    "list_sudo_rules": list_sudo_rules,
    "logon_groups": logon_groups,
    "list_site_roles": list_site_roles,
    "move_person": move_person,
    "place_fabric_host": place_fabric_host,
    "prepare_ssh_hosts": prepare_ssh_hosts,
    "read_dc_type_request": read_dc_type_request,
    "read_devices": read_devices,
    "read_networks": read_networks,
    "read_plan": read_plan,
    "read_scan_requests": read_scan_requests,
    "remake_site_group": remake_site_group,
    "read_site_dcs": read_site_dcs,
    "read_ssh_cas": read_ssh_cas,
    "remove_device": remove_device,
    "remove_group_member": remove_group_member,
    "remove_host_group": remove_host_group,
    "remove_machine": remove_machine,
    "remove_person": remove_person,
    "remove_role": remove_role,
    "remove_sudo_rule": remove_sudo_rule,
    "reset_password": reset_password,
    "save_device": save_device,
    "save_role": save_role,
    "set_dc_type_request": set_dc_type_request,
    "set_host_group_member": set_host_group_member,
    "set_machine": set_machine,
    "set_machine_class": set_machine_class,
    "set_person": set_person,
    "set_ssh_cas": set_ssh_cas,
    "set_ssh_host": set_ssh_host,
    "site_info": site_info,
    "sort_windows_machines": sort_windows_machines,
    "ssh_user_sites": ssh_user_sites,
    "sync_rodc_cache": sync_rodc_cache,
    "unlock_person": unlock_person,
    "write_plan": write_plan,
    "write_scan_request": write_scan_request,
}
