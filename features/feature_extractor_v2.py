def extract_features(e):

    is_network = 1 if e["layer"] == "network" else 0
    is_endpoint = 1 if e["layer"] == "endpoint" else 0
    is_application = 1 if e["layer"] == "application" else 0

    high_bytes = 1 if e["bytes"] > 5000 else 0
    login_fail = 1 if e["status"] == 401 else 0
    suspicious_process = 1 if e["process"] in ["cmd.exe", "powershell.exe"] else 0

    return [
        is_network,
        is_endpoint,
        is_application,
        high_bytes,
        login_fail,
        suspicious_process
    ]