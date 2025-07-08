# Audit Checks for OCP

import subprocess

# V-257583
def check_sshd_all_nodes_disable():
    try:

        command = subprocess.run(["oc","get","nodes","-o","name"],
                                 capture_output=True,
                                text=True)
        
        if command.returncode != 0:
            return f"Error: {command.stdout.strip()}"
        
        nodes = command.stdout.strip().splitlines()
        finding = {}

        for node in nodes:
            node_name = node.split("/")[-1]

            cmd = ["oc","debug", f"node/{node_name}",
                   "--", 
                   "chroot", "/host",
                   "/bin/bash/", "-c",
                   "systemctl is-enabled sshd.service && systemctl is-active sshd.service"]
            
            proc = subprocess.run(cmd, capture_output=True,text=True)
            output = proc.stdout.strip() if proc.returncode == 0 else proc.stderr

            if "enabled" in output or "active" in output:
                finding[node_name] = "Fail"
            else:
                finding[node_name] = "Pass"
        return finding
    except Exception as e:
        return f"Error: {e}"

# V-257557
def check_ocp_least_privileges():
