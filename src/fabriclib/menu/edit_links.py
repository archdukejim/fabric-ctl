import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW
from fabriclib.common.load_vars import load_vars
from fabriclib.common.paths import DEPLOY_BASE_DIR, INSTALL_DIR
from fabriclib.menu.save_menu_change import save_menu_change


def links_file():
    """Purpose: the landing page links file the menu edits.
    Inputs:  env LINK_VARS_PATH.
    Returns: LINK_VARS_PATH, else <fabric>/config/link-vars.yaml — or <base>/link-vars.yaml when only that exists.
    Fails:   never.
    Feeds:   edit_links."""
    path = os.environ.get("LINK_VARS_PATH", os.path.join(INSTALL_DIR, "config", "link-vars.yaml"))
    legacy = os.path.join(DEPLOY_BASE_DIR, "link-vars.yaml")
    return legacy if not os.path.exists(path) and os.path.exists(legacy) else path


def edit_links():
    """Purpose: menu to add, change or delete the landing page links (link-vars.yaml).
    Inputs:  none; the file from links_file(). A link may hold Jinja such as {{ domain }}.
    Returns: None when "b" is picked; each change saved and audited.
    Fails:   OSError / yaml.YAMLError reading or saving; EOFError from input().
    Feeds:   run_vars_menu (menu 5)."""
    path = links_file()
    data = load_vars(path)
    if not isinstance(data.get("links"), list):
        data["links"] = []
    links = data["links"]
    while True:
        os.system("clear")
        print(f"{BOLD}--- Landing Page Links Editor ---{NC}\n")
        if not links:
            print(f"{YELLOW}No custom links defined.{NC}")
        for i, item in enumerate(links, 1):
            print(f"  {i}) {item.get('name', f'Link {i}')} -> {item.get('link', '')}")
        print("\n  a) Add new link")
        if links:
            print("  m) Modify link")
            print("  d) Delete link")
        print("  b) Back to main menu")
        choice = ask("menu.links.option", "Select an option: ").lower()
        if choice == "b":
            return
        if choice == "a":
            name = ask("menu.links.name", "\n  Name: ")
            link = ask("menu.links.link", "  Link (e.g. nas.{{ domain }}): ")
            if name and link:
                links.append({"name": name, "link": link})
                save_menu_change(path, data, "links", "None", f"Added {name}")
        elif choice in ("m", "d") and links:
            pick = ask("menu.links.pick",
                       f"Enter link number to {'modify' if choice == 'm' else 'delete'} (1-{len(links)}): ")
            if not (pick.isdigit() and 1 <= int(pick) <= len(links)):
                continue
            idx = int(pick) - 1
            if choice == "d":
                del links[idx]
                save_menu_change(path, data, "links", "item", "None", "DELETED")
                continue
            item = links[idx]
            print(f"\nModifying entry {idx + 1}:")
            name = ask("menu.links.edit_name", f"  Name [{item.get('name', '')}]: ")
            link = ask("menu.links.edit_link", f"  Link [{item.get('link', '')}]: ")
            item.update({k: v for k, v in (("name", name), ("link", link)) if v})
            save_menu_change(path, data, "links", "old", f"Modified {item.get('name')}")
