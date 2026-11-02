# fabriclib/settings

The setup wizard's settings and the settings file (manual
[1.8.5](../../../docs/volume_1_description_and_architecture/1.8.5-setup-wizard.md#185-the-setup-wizard-setups-choices-in-the-console-and-in-a-file),
decision 2.1.8.7): what the web console's *Settings* and `fabricctl settings` change, through one plan and one apply.

| File | What |
|---|---|
| `constants.py` | `WIZARD_KEYS` (DHCP's `install_kea` and `dhcp` among them from 0.9.0), the file's `FORMAT`, the console-only settings shown read only, why an import ignores a key |
| `read_settings.py` | The wizard's settings as they are now, defaults filled in, no secret and nothing console-only |
| `export_settings.py` | The settings file: `fabric_settings: 1`, when and where it was exported, every wizard key |
| `parse_settings_file.py` | A settings file read: its wizard keys taken, every other key ignored and listed by reason |
| `check_wizard_value.py` | One wizard setting checked as setup and its own page check it |
| `plan_settings.py` | The plan: each change old to new, the parts started or stopped, the memory plan, what was ignored |
| `plan_is_current.py` | Whether a plan still matches what is installed (a stale plan is refused at Apply) |
| `apply_settings.py` | A plan applied: written under the lock, audited `SETTINGS_CHANGE`, one apply |
| `settings_from_form.py` | The wizard's fields as the settings they set |
| `form_from_settings.py` | The wizard's fields filled in with settings |
| `settings_overview.py` | What the console's wizard shows: today's settings, the console-only ones, whether it is finished |
| `wizard_finished.py` | Whether the wizard has been applied once or dismissed |
| `mark_wizard_finished.py` | Record that it has (a dismissal audited) |
| `run_settings_command.py` | `fabricctl settings export [FILE]` and `import FILE [--yes]` |
