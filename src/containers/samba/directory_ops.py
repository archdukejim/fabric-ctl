from add_group_member import add_group_member
from add_sudo_rule import add_sudo_rule
from adopt_linux_machines import adopt_linux_machines
from create_host_group import create_host_group
from create_machine import create_machine
from create_person import create_person
from get_person import get_person
from is_fabric_admin import is_fabric_admin
from link_device_cert import link_device_cert
from list_host_groups import list_host_groups
from list_machines import list_machines
from list_ssh_hosts import list_ssh_hosts
from list_sudo_rules import list_sudo_rules
from logon_groups import logon_groups
from list_people import list_people
from place_fabric_host import place_fabric_host
from prepare_ssh_hosts import prepare_ssh_hosts
from read_devices import read_devices
from read_networks import read_networks
from read_plan import read_plan
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
from set_host_group_member import set_host_group_member
from set_machine import set_machine
from set_person import set_person
from set_ssh_host import set_ssh_host
from site_info import site_info
from sort_windows_machines import sort_windows_machines
from write_plan import write_plan

# the operations fabric-agent may ask for (directory_op): each is f(samdb, lp, site, **args) -> JSON-able result
OPS = {
    "add_group_member": add_group_member,
    "add_sudo_rule": add_sudo_rule,
    "adopt_linux_machines": adopt_linux_machines,
    "create_host_group": create_host_group,
    "create_machine": create_machine,
    "create_person": create_person,
    "get_person": get_person,
    "is_fabric_admin": is_fabric_admin,
    "link_device_cert": link_device_cert,
    "list_host_groups": list_host_groups,
    "list_machines": list_machines,
    "list_ssh_hosts": list_ssh_hosts,
    "list_sudo_rules": list_sudo_rules,
    "logon_groups": logon_groups,
    "list_people": list_people,
    "place_fabric_host": place_fabric_host,
    "prepare_ssh_hosts": prepare_ssh_hosts,
    "read_devices": read_devices,
    "read_networks": read_networks,
    "read_plan": read_plan,
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
    "set_host_group_member": set_host_group_member,
    "set_machine": set_machine,
    "set_person": set_person,
    "set_ssh_host": set_ssh_host,
    "site_info": site_info,
    "sort_windows_machines": sort_windows_machines,
    "write_plan": write_plan,
}
