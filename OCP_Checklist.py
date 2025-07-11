# Audit Checks for OCP

import subprocess
import json
import re
import glob

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

    allowed_subjects = {
        "system:cluster-admins",
        "system:nodes",
        "system:masters",
        "system:admin",
        "system:serviceaccount:openshift-infra:build-controller",
        "system:serviceaccount:openshift-ifra:pv-recycler-controller"
        "system:serviceaccount:openshift-machine-api:machine-api-termination-handler"
    }

    platform_namespace = ("kube-", "openshift-")

    try:
        command = subprocess.run(["oc","get","scc","-ojson"]
                                 capture_output=True,
                                 text=True)
        command.check_returncode()
        sccs = json.loads(command.stdout)

    except Exception as e:
        print("Error: ", e)
        return
    bad_sccs = set()
    risky_roles = set()

    for scc in sccs['item']:
        name = scc['metadata']['name']
        risky = any([
            scc.get("allowHostIPC"),
            scc.get("allowHostPID"),
            scc.get("allowHostPorts"),
            scc.get("allowHostNetwork"),
            scc.get("allhowHostDirVolumePlugin"),
            scc.get("allowPrivilegedContainer"),
            scc.get("runAsUser", {}.get("type")) != "MustRunAsRange"
        ])
        if risky:
            bad_sccs.add(name)
            users = set(scc.get("users", []))
            groups = set(scc.get("groups", []))
            unauthorized = users.union(groups) - allowed_subjects
            
            if name == "restricted" and "system:authenticated" not in groups:
                print(f"[!] 'restricted' SCC missing 'System:Authenticated")
        elif unauthorized:
            print(f"[!] SCC '{name} has unapproved users/groups: {unauthorized}")

        try:

            cluster_roles_data = subprocess.run(["oc", "get", "clusterrole.rbac", "-ojson"],
                                                capture_output=True,
                                                text=True)
            cluster_roles_data.check_returncode()
            cluster_roles = json.loads(cluster_roles_data.stdout)['items']
        except Exception as e:
            print(f"Error: {e}")
            return
        
        try:
            local_roles_data = subprocess.run(["oc", "get", "role.rbac", "--all-namespaces", "-ojson"],
                                              capture_output=True,
                                              text=True)
            local_roles_data.check_returncode()
            local_roles = json.loads(local_roles_data)['items']
        except Exception as e:
            print(f"Error: {e}")
            return
        
        for roles in cluster_roles + local_roles:
            for rule in roles.get("rules", []):
                if "securitycontextconstraints" in rule.get("resources",[]) and "use" in rule.get("verbs", []):
                    sccs = rule.get("resourceNames", [])
                    if any(scc in bad_sccs for scc in sccs):
                        risky_roles.add(roles['metadata']['name'])
        print(f"Roles using risky sccs: {risky_roles}")

        try:
            crb_data = subprocess.run(["oc", "get", "clusterrolebinding.rbac", "-ojson"],
                                      capture_output=True,
                                      text=True)
            crb_data.check_returncode()
            crbs = json.loads(crb_data.stdout)['items']
        except Exception as e:
            print(f"error: {e}")
            return
        
        try:
            rb_data = subprocess.run(["oc", "get", "rolebinding.rbac","--all-namespaces","-ojson"],
                                     capture_output=True,
                                     text=True)
            rb_data.check_returncode()
            rbs = json.loads(rb_data.stdout)['items']
        except Exception as e:
            print(f"error: {e}")
            return
        
        for binding in crbs + rbs:
            role_name = binding['roleRef']["name"]
            ns = binding.get('metadata', {}).get('namespace', '')
            if role_name in risky_roles:
                if not ns or not any(ns.startswith(p) for p in platform_namespace):
                     print(f"[!] Binding '{binding['metadata']['name']}' in namespace '{ns}' uses risky role '{role_name}' with subjects: {binding.get('subjects', [])}")


# V-257546
def check_nodes_strong_ciphers():
    try:

        command = subprocess.run(["oc","get","nodes","-o","name"],
                             capture_output=True,
                             text=True)
        if command.returncode != 0:
            return f"Error: {command.stdout.strip()}"
        nodes = command.stdout.strip().splitlines()
        findings = {}
        for node in nodes:
            node_name = node.split("/")[-1]

            cmd = ["oc", "debug", f"node/{node_name}",
                   "--", "chroot","/host","bash", "-c",
                   "update-crypto-policies --show"]
            proc = subprocess.run(cmd,capture_output=True,text=True)
            output = proc.stdout.strip() if proc.returncode == 0 else proc.stderr

            if "FUTURE" in output:
                findings[node_name] = "Pass"
            else:
                findings[node_name] = "Fail"
        return findings
    except Exception as e:
        return f"error: {e}"


# V-257543

def check_ldap_oidc():
    try:
        cmd = ["oc","get","oauth","cluster","-o",'jsonpath={.spec.identityProviders[*].type}{"\\n"}']

        proc = subprocess.run(cmd, capture_output=True,text=True)
        output = proc.stdout.strip() if proc.returncode == 0 else proc.stderr

        if "LDAP" in output or "OpenID" in output:
            return "Pass"
        else:
            return "Fail"
    except Exception as e:
        return f"Error: {e}"
    
# V-257540

def check_disable_root_login():
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
            cmd = ["oc","debug",f"node/{node_name}",
                   "--", "chroot","/host","/bin/bash", "-c",
                   'grep -i PermitRootLogin /etc/ssh/sshd_config || echo "PermitRootLogin not set"']
            proc = subprocess.run(cmd,capture_output=True,text=True)
            output = (proc.stdout if proc.returncode == 0 else proc.stderr).strip().lower()
            

            if output.strip() == "permitrootlogin no":
                finding[node_name] = "Pass"
            else:
                finding[node_name] = "Fail"
        return finding
    except Exception as e:
        return f"Error: {e}"
    
    # V-257540
def check_idle_termination():
    try:

        command = subprocess.run(["oc","get","node","-oname"],
                                 capture_output=True,
                                 text=True)
        if command.returncode != 0:
            return f"error: {command.stdout.strip()}"
        
        nodes = command.stdout.strip().splitlines()
        findings = {}
        for node in nodes:
            node_name = node.split("/")[-1]
            cmd = ["oc","debug",f"node/{node_name}",
                   "--","chroot","/host", "/bin/bash", "-c",
                   'grep -i clientalive /etc/ssh/sshd_config']
            proc = subprocess.run(cmd,capture_output=True,text=True)
            output = (proc.stdout if proc.returncode == 0 else proc.stderr).strip().lower()

            interval = None
            countmax = None

            for line in output.splitlines():
                if "clientaliveinterval" in line:
                    match = re.search(r"clientaliveinterval\s+(\d+)", line)
                    if match:
                        interval = int(match.group(1))
                elif "clientalivecountmax" in line:
                    match = re.search(r"clientalivecountmax\s+(\d+)", line)
                    if match:
                        countmax = int(match.group(1))
            if interval is None or countmax is None:
                findings[node_name] = "Fail"
            elif countmax == 0 or interval > 600:
                findings[node_name] = "Fail"
            else:
                findings[node_name] = "Pass"
        return findings
    except Exception as e:
        return f"Error: {e}"
    

def check_audit_startup():

    try:
        command = subprocess.run(["oc","get","node","-oname"],
                                 capture_output=True,
                                 text=True)
        if command.returncode != 0:
            return f"error: {command.stdout.strip()}"
        
        nodes = command.stdout.strip().splitlines()
        findings = {}
        file_path = glob.glob("/boot/loader/entries/*.conf")
        files_str = " ".join(file_paths)

        for node in nodes:
            node_name = node.split("/")[-1]
            cmd = ["oc","debug",f"node/{node_name}",
                   "--","chroot","/host","/bin/bash", "-c",
                   f'grep audit {file_path}']
            proc = subprocess.run(cmd,capture_output=True,text=True)
            output = (proc.stdout if proc.returncode == 0 else proc.stderr).strip()

            status_code = None
            limit = None

            for line in output.splitlines():
                if "audit=" in line:
                    match = re.search(r"audit\s*=\s*(\d+)", line)
                    if match:
                        status_code = int(match.group(1))
                elif "audit_backlog_limit=" in line:
                    match = re.search(r"audit_backlog_limit\s*=\s*(\d+)", line)
                    if match:
                        limit = int(match.group(1))
                if status_code is None or limit is None:
                    findings[node_name] = "Fail"
                elif status_code != 1 and limit != 8192:
                    findings[node_name] = "Fail"
                else:
                    findings[node_name] = "Pass"
        return findings
    except Exception as e:
        return f"Error: {e}"

# V-257513

def check_rbac_enforced():
    results = {}
    for name, cmd in {
            "clusterrole": ["oc", "describe","clusterrole.rbac"],
            "clusterrolebinding": ["oc", "describe","clusterrolebinding.rbac"],
            "role":["oc","describe","role.rbac"]

        }.items():

        try:

            proc = subprocess.run(cmd,capture_output=True,text=True)
            if proc.returncode != 0:
                results[name] = f"Error: {proc.stderr.strip() or proc.stdout.strip()}"
            else:
                results[name] = proc.stdout.strip()
        except Exception as e:
            return F"Error: {e}"
    return results

# V-257579
import subprocess

def check_logon_auditing():
    try:
        command = subprocess.run(["oc", "get", "node", "-o", "name"],
                                 capture_output=True, text=True)
        if command.returncode != 0:
            return {f"Error: could not list nodes: {command.stderr.strip()}"}

        nodes = command.stdout.strip().splitlines()

        
        rules = [
            "-w /var/run/faillock -p wa -k logins",
            "-w /var/log/lastlog -p wa -k logins"
        ]

        result = {}

        for node in nodes:
            node_name = node.split("/")[-1]
            cmd = [
                "oc", "debug", f"node/{node_name}",
                "--", "chroot", "/host", "/bin/bash", "-c",
                'grep "logins" /etc/audit/audit.rules /etc/audit/rules.d/* 2>/dev/null'
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            output = proc.stdout.strip() if proc.returncode == 0 else ""

            findings = []
            for rule in rules:
                if rule not in output:
                    findings.append(f"Missing: {rule}")

            result[node_name] = "Pass" if not findings else "Fail: " + " ; ".join(findings)

        return result

    except Exception as e:
        return {"error": str(e)}

# V-257578 V-257577 V-257576
def check_delete_modify_security_privilege_objects():
        
    try:
            command = subprocess.run(["oc", "get", "node", "-o", "name"],
                                 capture_output=True, text=True)
            if command.returncode != 0:
                return {f"Error: could not list nodes: {command.stderr.strip()}"}

            nodes = command.stdout.strip().splitlines()
            rules = [
               "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete",
                "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete",
                "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete",
                "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccessful-delete",
                "-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b64 -S renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S renameat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S renameat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S rename -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b64 -S rename -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S rename -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S rename -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlinkat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b64 -S unlinkat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S unlinkat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S unlinkat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlink -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b64 -S unlink -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S unlink -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F arch=b32 -S unlink -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access",
                "-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/libexec/pt_chown -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/userhelper -F auid>=1000 -F auid!=unset -F key=privileged",
                "-w /etc/group -p wa -k audit_rules_usergroup_modification",
                "-w /etc/gshadow -p wa -k audit_rules_usergroup_modification",
                "-w /etc/passwd -p wa -k audit_rules_usergroup_modification",
                "-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification",
                "-w /etc/shadow -p wa -k audit_rules_usergroup_modification",
                "-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete",
                "-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/libexec/pt_chown -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/userhelper -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod",
                "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/restorecon -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=unset -F key=privileged",
                "-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=unset -F key=privileged",
                 "-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=unset -F key=privileged",
                 

            ]

            result = {}

            for node in nodes:
                node_name = node.split("/")[-1]
                cmd = [
                "oc", "debug", f"node/{node_name}",
                "--", "chroot", "/host", "/bin/bash", "-c",
                'cat /etc/audit/audit.rules /etc/audit/rules.d/* 2>/dev/null'
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                output = proc.stdout.strip() if proc.returncode == 0 else ""

            findings = []
            for rule in rules:
                if rule not in output:
                    findings.append(f"Missing: {rule}")

            result[node_name] = "Pass" if not findings else "Fail: " + " ; ".join(findings)

            return result

    except Exception as e:
        return f"Error: {e}"
            
# V-257569

def check_aslr():
    try:

        command = subprocess.run(["oc","get","node","-oname"],capture_output=True,text=True)
        if command.returncode != 0:
            return {f"error: could not find list of nodes{command.stderr.strip()}"}
        
        nodes = command.stdout.strip().splitlines()
        result = {}
        for node in nodes:
            node_name = node.split("/")[-1]
            cmd = [
                "oc","debug"f"node/{node_name}",
                "--","chroot","/host","/bin/bash","-c",
                "systctl kernel.randomize_va_space"
            ]
            proc = subprocess.run(cmd,capture_output=True,text=True)
            output = (proc.stdout if proc.returncode == 0 else " ").strip().lower()
            
            match = re.search(r"kernel\.randomize_va_space\s*=\s*(\d+)", output)
            if match:
                value = int(match.group(1))
                if value == 2:
                    result[node_name] = "Pass"
                else:
                    result[node_name] = "Fail"
            else:
                result[node_name] =f"Fail: unable to parse sysctl output {output}"
        return result
    except Exception as e:
        return f"Error: {e}"

# V-257508
def kubeadmin_disabled():
    try:

        command = subprocess.run(["oc","get","secrets","kubeadmin","-n","kube-system"], capture_output=True,text=True)

        output = command.stderr.strip().lower()

        if "notfound" in output:
            return "Pass"
        else:
            return "Fail"            
    except Exception as e:
        return f"Error: {e}"
