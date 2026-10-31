# fabriclib/access

fabric-agent's check of who may do what, on every call, console and CLI alike (manual 1.6.12.2, 1.6.12.11; decisions
2.1.6.66 to 2.1.6.68, 2.1.6.73): the tiers, the grants' people and machines rights, a group's two levels. The check
itself runs inside the DC (`src/containers/samba/authorize_action.py`, through `grants_tool.py`).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `check_access.py` | Whether a caller may do an action on a person, a machine or a group; refused with why |
