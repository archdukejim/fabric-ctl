from add_group_member import add_group_member
from adopt_linux_machines import adopt_linux_machines
from create_machine import create_machine
from create_person import create_person
from get_person import get_person
from link_device_cert import link_device_cert
from list_machines import list_machines
from logon_groups import logon_groups
from list_people import list_people
from read_devices import read_devices
from read_networks import read_networks
from remove_device import remove_device
from remove_group_member import remove_group_member
from remove_machine import remove_machine
from remove_person import remove_person
from remove_role import remove_role
from reset_password import reset_password
from save_device import save_device
from save_role import save_role
from set_machine import set_machine
from set_person import set_person
from site_info import site_info
from sort_windows_machines import sort_windows_machines

# the operations fabric-agent may ask for (directory_op): each is f(samdb, lp, site, **args) -> JSON-able result
OPS = {
    "add_group_member": add_group_member,
    "adopt_linux_machines": adopt_linux_machines,
    "create_machine": create_machine,
    "create_person": create_person,
    "get_person": get_person,
    "link_device_cert": link_device_cert,
    "list_machines": list_machines,
    "logon_groups": logon_groups,
    "list_people": list_people,
    "read_devices": read_devices,
    "read_networks": read_networks,
    "remove_device": remove_device,
    "remove_group_member": remove_group_member,
    "remove_machine": remove_machine,
    "remove_person": remove_person,
    "remove_role": remove_role,
    "reset_password": reset_password,
    "save_device": save_device,
    "save_role": save_role,
    "set_machine": set_machine,
    "set_person": set_person,
    "site_info": site_info,
    "sort_windows_machines": sort_windows_machines,
}
