"""The recommended-resources table (manual 1.8.8.8, decision 2.1.8.36): a straight line per resource, a fixed part
plus a
part per directory object (a person, a computer or a group), for the minimum and the recommended. Fitted from the
measurements in the notes (2.3.8.5.1, 2.3.8.5.2). MiB for memory and disk; cores for CPU, rounded up."""

TABLE = {
    # the whole stack: at rest for the minimum, at its highest under the console's reads with a quarter's room for the
    # recommended; each with what the host's own system takes
    "ram": {"min": 1900, "min_per": 0.0285, "rec": 2400, "rec_per": 0.055},
    # the domain controller does the directory's work; everything else stays idle
    "cores": {"min": 2, "min_per": 0.0, "rec": 3, "rec_per": 0.000125},
    # fabric's data volume: what it must have free to take an update's images and the logs' growth
    "disk": {"min": 2048, "min_per": 0.05, "rec": 8192, "rec_per": 0.1},
    # the one service that grows with the directory, against its own limit
    "dc_memory": {"min": 200, "min_per": 0.021, "rec": 250, "rec_per": 0.047},
}
