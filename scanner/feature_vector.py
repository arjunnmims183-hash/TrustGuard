# scanner/feature_vector.py

def create_feature_vector():

    return {

        "file_read": False,
        "file_write": False,

        "network_request": False,
        "network_recv": False,

        "subprocess": False,

        "eval_usage": False,
        "exec_usage": False,

        "obfuscation": False,

        "persistence_attempt": False,

        "credential_access": False,

        "system_recon": False,

        "anti_forensics": False,

        "data_flow_paths": [],
    }