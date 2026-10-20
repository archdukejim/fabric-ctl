from add_group_member import add_group_member
from add_sudo_rule import add_sudo_rule
from adopt_linux_machines import adopt_linux_machines
from create_group import create_group
from create_host_group import create_host_group
from create_machine import create_machine
from create_ou import create_ou
from create_person import create_person
from dc_info import dc_info
from delete_ou import delete_ou
from edit_person import edit_person
from get_person import get_person
from group_scope import group_scope
from link_device_cert import link_device_cert
from list_groups import list_groups
from list_host_groups import list_host_groups
from list_machines import list_machines
from list_ous import list_ous
from list_people import list_people
from list_spns import list_spns
from list_sudo_rules import list_sudo_rules
from move_machine import move_machine
from place_fabric_host import place_fabric_host
from read_devices import read_devices
from read_networks import read_networks
from remove_device import remove_device
from remove_group import remove_group
from remove_group_member import remove_group_member
from remove_host_group import remove_host_group
from remove_machine import remove_machine
from remove_person import remove_person
from remove_role import remove_role
from remove_sudo_rule import remove_sudo_rule
from rename_ou import rename_ou
from reset_password import reset_password
from save_device import save_device
from save_role import save_role
from set_group_managers import set_group_managers
from set_host_group_member import set_host_group_member
from set_machine import set_machine
from set_machine_site import set_machine_site
from set_machine_type import set_machine_type
from set_person import set_person
from sort_windows_machines import sort_windows_machines
from unlock_person import unlock_person

# the operations fabric-agent may ask for (directory_op): each is f(samdb, lp, site, **args) -> JSON-able result
# (and the request's dc, for one that takes it)
OPS = {
    "add_group_member": add_group_member,
    "add_sudo_rule": add_sudo_rule,
    "adopt_linux_machines": adopt_linux_machines,
    "create_group": create_group,
    "create_host_group": create_host_group,
    "create_machine": create_machine,
    "create_ou": create_ou,
    "create_person": create_person,
    "dc_info": dc_info,
    "delete_ou": delete_ou,
    "edit_person": edit_person,
    "get_person": get_person,
    "group_scope": group_scope,
    "link_device_cert": link_device_cert,
    "list_groups": list_groups,
    "list_host_groups": list_host_groups,
    "list_machines": list_machines,
    "list_ous": list_ous,
    "list_people": list_people,
    "list_spns": list_spns,
    "list_sudo_rules": list_sudo_rules,
    "move_machine": move_machine,
    "place_fabric_host": place_fabric_host,
    "read_devices": read_devices,
    "read_networks": read_networks,
    "remove_device": remove_device,
    "remove_group": remove_group,
    "remove_group_member": remove_group_member,
    "remove_host_group": remove_host_group,
    "remove_machine": remove_machine,
    "remove_person": remove_person,
    "remove_role": remove_role,
    "remove_sudo_rule": remove_sudo_rule,
    "rename_ou": rename_ou,
    "reset_password": reset_password,
    "save_device": save_device,
    "save_role": save_role,
    "set_group_managers": set_group_managers,
    "set_host_group_member": set_host_group_member,
    "set_machine": set_machine,
    "set_machine_site": set_machine_site,
    "set_machine_type": set_machine_type,
    "set_person": set_person,
    "sort_windows_machines": sort_windows_machines,
    "unlock_person": unlock_person,
}
