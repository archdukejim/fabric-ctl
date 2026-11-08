# fabriclib/readcache

What fabric-agent keeps for the console, and how hard it may work on this host ([1.8.9](../../../docs/volume_1_description_and_architecture/1.8.9-console-read-cache.md), decisions [2.1.8.43 to 2.1.8.45](../../../docs/volume_2_engineering_decisions/2.1.8-webui.md)).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `host_rules.py` | The host's classes, the refresh's interval, pressure and the held processes' limit: pure rules |
| `kept_reads.py` | The store and its refresher: memory only, one refresh at a time |
