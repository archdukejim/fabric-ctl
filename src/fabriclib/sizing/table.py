"""The recommended-resources table (manual 1.8.8.8, decision 2.1.8.36): a straight line per resource, a fixed part
plus a part per directory object (a person, a computer or a group), for the minimum and the recommended. Fitted from the
measurements in the notes (2.3.8.5.1, 2.3.8.5.2). MiB for memory and disk; cores for CPU, rounded up."""

TABLE = {
    # what the test Pi's whole host used (about 2.6 GB at every size) for the minimum, with a quarter's room for the
    # recommended; per object, the sandbox's slopes at rest and under the load (the Pi's own are hidden by its limit)
    "ram": {"min": 2600, "min_per": 0.02, "rec": 3300, "rec_per": 0.04},
    # the domain controller does the directory's work; everything else stays idle
    "cores": {"min": 2, "min_per": 0.0, "rec": 3, "rec_per": 0.000125},
    # fabric's data volume: what it must have free to take an update's images and the logs' growth
    "disk": {"min": 2048, "min_per": 0.05, "rec": 8192, "rec_per": 0.1},
    # the one service that grows with the directory, against its own limit
    "dc_memory": {"min": 450, "min_per": 0.045, "rec": 600, "rec_per": 0.07},
}
