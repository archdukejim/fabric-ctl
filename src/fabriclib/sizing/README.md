# fabriclib/sizing

The sizing advice: what the host is small for ([1.8.8.8](../../../docs/volume_1_description_and_architecture/1.8.8-directory-browser.md),
decisions [2.1.8.36 to 2.1.8.40](../../../docs/volume_2_engineering_decisions/2.1.8-webui.md), the numbers
[2.3.8.5](../../../docs/volume_2_engineering_decisions/2.3.8-webui-notes.md)). Computed on the host by a timer, read by
the console and the host's commands; nothing is sent anywhere.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `table.py` | The recommended-resources table: the measured fit |
| `advice.py` | The model: what a size needs, the alerts, what one person still sees |
| `state.py` | The timer's last result and each person's dismissals, on the host |
| `refresh_sizing.py` | The timer's work: the size from the DC, what the host has, the alerts written |
| `run_sizing_command.py` | `fabricctl sizing show\|refresh`; what `status` and `doctor` print |
