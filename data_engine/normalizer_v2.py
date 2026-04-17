def normalize_event(e):
    return {
        "layer": e.get("layer", ""),
        "bytes": e.get("bytes", 0),
        "status": e.get("status", 200),
        "process": e.get("process", ""),
        "user": e.get("user", ""),
        "timestamp": e.get("timestamp", 0)
    }