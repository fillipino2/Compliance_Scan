
import subprocess
import re
import glob

# def umask_077():
#     with open("/etc/login.defs", "r") as umask:

# V-230385
def check_umask_077():
    result = subprocess.run(["grep", "-i", "umask","/etc/login.defs"], capture_output=True, text=True )
    for line in result.stdout.splitlines():
        if line.strip().startswith("#"):
            continue
        if not "077" in line:
            return ("Fail", f"insecure line {line.strip()}")
    return "Pass"


# V-230264
def check_signed_packages():
    try:
        result = subprocess.run(
            " grep -E '^\\[.*\\]|gpgcheck' /etc/yum.repos.d/*.repo",
            shell=True,
            capture_output=True,
            text=True 
        )
        for line in result.stdout.splitlines():
            if "gpgcheck" in line:
                if line.strip().endswith("gpgcheck=1"):
                    continue
                else:
                    return "Fail"
        return "Pass"
    except Exception as e:
        return f"Error: {e}"
# V-230265    
def check_signed_pacakges_dnf():
    try:
        with open("/etc/dnf/dnf.conf", "r") as dnf:
            for line in dnf:
                line = line.strip()
                if  line.startswith("localpkgcheck_gpg"):
                    key_value = [s.strip() for s in line.split("=", 1)]
                    if len(key_value) == 2 and key_value[1].lower() == "true":
                        return "Pass"
                else:
                    return "Fail"
    except Exception as e:
        return f"Error; {e}"
    
# V-230282   
def check_selinux_enabled():
    try:
        result = subprocess.run(["sestatus"], capture_output=True,text=True )
        output = result.stdout.lower()
        for line in output.splitlines():
            if line.startswith("SELinux status:"):
                status = line.split(":", 1)[1].strip()
                if status == "enabled":
                    return "Pass"
                else:
                    return "Fail"
        return " Fail"
    except Exception as e:
        return f"Error: {e}"

# V-230282   
def check_selinux_target_policy():
    try:
        verify = subprocess.run("grep -i selinuxtype /etc/selinux/config | grep -v '^#'",
                                shell=True,
                                capture_output=True,
                                text=True)
        if verify.returncode != 0 or not verify.stdout.strip():
            return "Fail"
        verification = verify.stdout.lower().strip()
        final = verification.split("=", 1)[1].strip()
        result = subprocess.run(["sestatus"], capture_output=True, text=True)
        output = result.stdout.lower()
        for line in output.splitlines():
            if line.startswith("Loaded policy name:"):
                target = line.split(":", 1)[1].strip()
                if target == "targeted" and final == "targeted":
                    return "Pass"
                else:
                    return "Fail"
        return "Fail"
    except Exception as e:
        return f"Error: {e}"



#V-251706   
def check_blank_password():
    empty_user = []
    with open("/etc/shadow", "r") as empty:
        for line in empty:
            fields = line.strip().split(":")
            if len(fields) > 1 and fields[1] == "":
                empty_user.append(fields[0])
    if empty_user:
        return ",".join(empty_user)
    else:
        return ("No empty passwords for users")

# Ensure System is using Updated Crpytography
def check_crypto_policies():
    try:
        result = subprocess.run("update-crypto-policies --show", shell=True, capture_output=True, text=True)
        output = result.stdout.lower().strip()
        if output == "future":
            return "Pass"
        else:
            return "Fail"
    except Exception as e:
        return f"Error: {e}"


def check_auto_login_with_gui():
    try:
        with open("/etc/gdm/custom.conf", "r") as auto:
            for line in auto:
                line = line.strip().lower()
                if line.startswith("automaticloginenable"):
                    if "#" in line or ";" in line:
                        continue
                    value = line.split("=", 1)[1].strip()
                    return "Pass" if value == "false" else "fail"
        return "Fail"
    except Exception as e:
        return f"Error: {e}"

def check_bios_UEFI():
    try:
        firmware = subprocess.run("test -d /sys/firmware/efi && echo UEFI || echo BIOS", shell=True, capture_output=True, text=True)
        if firmware.stdout.strip().lower() == "uefi":
            result = subprocess.run("grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg", shell=True, capture_output=True, text=True)
            output = result.stdout.strip().lower()
            if output.startswith("grub2_password=grub.pbkdf2.sha512"):
                return "Pass"
            else:
                return "Fail"
        return "Only Applicable to UEFI systems"
    except Exception as e:
        return f"Error: {e}"
def check_ctl_alt_del():
    try:
        command = subprocess.run("sudo systemctl status ctrl-alt-del.target", shell=True, capture_output=True, text=True)
        result = command.stdout.strip().lower()
        for line in result.splitlines():
            if line.startswith("loaded:"):
                key_value = [s.strip() for s in line.split(":",1)]
                if len(key_value) == 2 and "masked" in key_value[1].lower():
                    return "Pass"
        return "Fail"
    except Exception as e:
        return f"Error: {e}"
    
#    V-230221
def check_os_release(min_required_version="8.10"):
    try:
        command = subprocess.run("sudo cat /etc/redhat-release", shell=True, capture_output=True, text=True)
        result = command.stdout.strip()
        match = re.search(r'release\s+(\d+\.\d+)', result.lower())
        if not match:
            return "Fail"
        current_version = float(match.group(1))
        required_version = float(min_required_version)
        if current_version >= required_version:
            return "Pass"
        else:
            return "Fail"
        
    except Exception as e:
        return f"Error: {e}"
    
# V-230534 Will work on this later

# V-230487
def check_telnet_server_package():
    try:
        command = subprocess.run("yum list installed telnet-server",shell=True,capture_output=True,text=True)
        
        if command.returncode != 0:
            return "Pass"
        else:
            return "Fail"
    except Exception as e:
        return f"Error {e}"

# V-244542
def check_audit_services():
    try:
        command = subprocess.run("systemctl status auditd.service", shell=True, capture_output=True, text=True)
        output = command.stdout.strip()
        for line in output.splitlines():
            if line.startswith("Active:"):
                    if "active (running)" in line.lower():
                        return "Pass"
                    else:
                        return "Fail"
    except Exception as e:
        return f"Error: {e}"
# V-230284
def check_shosts_file():
    try:
        command = subprocess.run("find / -name '*.shosts' 2>/dev/null", shell=True, capture_output=True, text=True)
        output = command.stdout.strip()
        if output:
            return "Fail"
        else:
            return "Pass"
    except Exception as e:
        return f"Error: {e}"
    
# V-230558
def check_ftp_package():
    try:
        command = subprocess.run("sudo yum list installed | grep ftpd", shell=True, capture_output=True, text=True)
        if command.returncode == 0:
            return "Fail"
        else:
            return "Pass"
    except Exception as e:
        return f"Error: {e}"

# V-230492
def check_rsh_server_package():
        try:
            command = subprocess.run("yum list installed  rsh-server",shell=True,capture_output=True,text=True)
        
            if command.returncode == 0:
                return "Fail"
            else:
                return "Pass"
        except Exception as e:
            return f"Error {e}"

# V-230380
def check_permitemptypassword_sshd():
    try:
        with open("/etc/ssh/sshd_config", "r") as permitpasswd:
            for line in permitpasswd:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue
                
                if line.lower().startswith("permitemptypassword"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].lower() == "no":
                        return ("PermitEmptyPasswords", "pass", "set to no")
                    else:
                        return ("PermitEmptyPasswords", "Fail", f"{parts[1] if len(parts) > 1 else 'missing'}")
        return (" PermitEmptyPasswords", "Pass", "Directive not found")
    except Exception as e:
        return ("PermitEmptyPasswords", "error", str(e))
    
#V-230283
def check_shosts_equiv_file():
    try:
        command = subprocess.run("find / -name '*.shosts.equiv' 2>/dev/null", shell=True, capture_output=True, text=True)
        output = command.stdout.strip()
        if output:
            return "Fail"
        else:
            return "Pass"
    except Exception as e:
        return f"Error: {e}"
# Need to work on logic and verifiy the output status when command is ran    V-244553
def check_icmp_redirect():
    try:
        file_list =["/run/sysctl.d/*.conf",
                    "/usr/local/lib/sysctl.d/*.conf",
                    "/usr/lib/sysctl.d/*.conf",
                    "/lib/sysctl.d/*.conf",
                    "/etc/sysctl.conf",
                    "/etc/sysctl.d/*.conf"]
        
        command = subprocess.run("sysctl net.ipv4.conf.all.accept_redirects", shell=True,
                                 capture_output=True,
                                 text=True)
        output = command.stdout.strip()
        if output != "net.ipv4.conf.all.accept_redirects = 0":
            return "Fail"
        files_to_check = []
        for path in file_list:
            if "*" in path:
                files_to_check.extend(glob.glob(path))
            else:
                files_to_check.append(path)

        for file_path in files_to_check:
            try:
                with open(file_path, "r")as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "net.ipv4.conf.all.accept_redirects" in line and "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "net.ipv4.conf.all.accept_redirects" and val != "0":
                                return "Fail"
            except Exception:
                continue
        return "Pass"
    except Exception as e:
            return f"Error: {e}"
    
# still need to do all icmp stuff

# V-230554
def check_promisc_mode():
    try:
        command = subprocess.run("sudo ip link | grep -i promisc", shell=True, capture_output=True, text=True)
        output = command.stdout.strip()
        if output:
            return "Fail"
        else:
            return "Pass"
    except Exception as e:
        return f"Error: {e}"

# V-230550
def check_postfix():
    try:
        command = subprocess.run("yum list installed postfix",
                                 shell=True,
                                 capture_output=True,
                                 text=True)
        if command.returncode != 0:
            return
        
        config_check = subprocess.run("postconf -n smtpd_client_restrictions",
                                      shell=True,
                                      capture_output=True,
                                      text=True)
        if config_check.returncode != 0:
            return "Not Applicable"
        
        output = config_check.stdout.strip()

        if "smtpd_client_restrictions" in output and "=" in output:
            key, val = [x.strip() for x in output.split("=",1)]
            if key == "smtpd_client_restrictions" and val == "permit_mynetworks, reject":
                return "Pass"
            else:
                return "Fail"
    except Exception as e:
        return f"Error {e}"
    
 #  V-250317 
def check_ipv4_forwarding():
    try:
        file_list =["/run/sysctl.d/*.conf",
                    "/usr/local/lib/sysctl.d/*.conf",
                    "/usr/lib/sysctl.d/*.conf",
                    "/lib/sysctl.d/*.conf",
                    "/etc/sysctl.conf",
                    "/etc/sysctl.d/*.conf"]
        
        command = subprocess.run("sysctl sysctl net.ipv4.conf.all.forwarding", shell=True,
                                 capture_output=True,
                                 text=True)
        output = command.stdout.strip()
        if output != "sysctl net.ipv4.conf.all.forwarding = 0":
            return "Fail"
        files_to_check = []
        for path in file_list:
            if "*" in path:
                files_to_check.extend(glob.glob(path))
            else:
                files_to_check.append(path)

        for file_path in files_to_check:
            try:
                with open(file_path, "r")as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "sysctl net.ipv4.conf.all.forwarding" in line and "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "sysctl net.ipv4.conf.all.forwarding" and val != "0":
                                return "Fail"
            except Exception:
                continue
        return "Pass"
    except Exception as e:
            return f"Error: {e}"
# V-230540   
def check_ipv4_forwarding():
    try:
        file_list =["/run/sysctl.d/*.conf",
                    "/usr/local/lib/sysctl.d/*.conf",
                    "/usr/lib/sysctl.d/*.conf",
                    "/lib/sysctl.d/*.conf",
                    "/etc/sysctl.conf",
                    "/etc/sysctl.d/*.conf"]
        
        command = subprocess.run("sysctl sysctl net.ipv6.conf.all.forwarding", shell=True,
                                 capture_output=True,
                                 text=True)
        output = command.stdout.strip()
        if output != "sysctl net.ipv6.conf.all.forwarding = 0":
            return "Fail"
        files_to_check = []
        for path in file_list:
            if "*" in path:
                files_to_check.extend(glob.glob(path))
            else:
                files_to_check.append(path)

        for file_path in files_to_check:
            try:
                with open(file_path, "r")as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "sysctl net.ipv6.conf.all.forwarding" in line and "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "sysctl net.ipv6.conf.all.forwarding" and val != "0":
                                return "Fail"
            except Exception:
                continue
        return "Pass"
    except Exception as e:
            return f"Error: {e}"

# V-230553
def check_gui():

    try:
        command = subprocess.run("rpm -qa | grep xorg | grep server",
                                 shell=True,
                                 capture_output=True,
                                 text=True)
        if command.returncode == 0:
            return "Fail, Unless approved previously"
        else:
            return "Pass"
    except Exception as e:
        return f"Error: {e}"
    
# V-230274
def check_pki_status():
    
    try:

        command = subprocess.run("grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v \"^#\"",
                                 shell=True,
                                 capture_output=True,
                                 text=True,)
        if command.returncode == 0:
            output = command.stdout.strip()
            if "=" in output:
                key, val = [x.strip() for x in output.split("=", 1)]
                if key == "certificate_verification" and val == "ocsp_dgst=sha1":
                    return "Pass"
                else:
                    return "Fail"
        else:
            return "Fail"
    except Exception as e:
        return f"Error: {e}"

# V-230404
def check_audit_shadow_file():
    try:

        command = subprocess.run("grep /etc/shadow /etc/audit/audit.rules",
                                 shell=True,
                                 capture_output=True,
                                 text=True)
        
        output = command.stdout.strip()
        for line in output.splitlines():
            if "-w /etc/shadow" in line:
                match = re.search(r"-p\s*([rwa]+)", line)
                if match:
                    perms = match.group(1)
                    if "w" in perms and "a" in perms:
                        return "Pass"
        return "Fail"

    except Exception as e:
        return f"Error: {e}"

# V-230267

def check_access_symlinks():
    try:

        command = subprocess.run(["sysctl", "fs.protected_symlinks"],
                                 capture_output=True,
                                 text=True)
        if command.returncode != 0:
            return "Fail"

        output = command.stdout.strip()
        if "=" not in output:
            return "Fail"

        key, val = [x.strip() for x in output.split("=", 1)]
        if key != "fs.protected_symlinks" or val != "1":
            return "Fail"


        file_list = [
            "/run/sysctl.d/*.conf",
            "/usr/local/lib/sysctl.d/*.conf",
            "/usr/lib/sysctl.d/*.conf",
            "/lib/sysctl.d/*.conf",
            "/etc/sysctl.conf",
            "/etc/sysctl.d/*.conf"
        ]
        files_to_check = []
        for path in file_list:
            if "*" in path:
                files_to_check.extend(glob.glob(path))
            else:
                files_to_check.append(path)

        for file_path in files_to_check:
            try:
                with open(file_path, "r") as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "fs.protected_symlinks" in line and "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "fs.protected_symlinks":
                                if val == "1":
                                    return "Pass"
                                else:
                                    return "Fail"
            except Exception:
                continue  # skip unreadable files

        return "Fail"  # No valid persistent config found

    except Exception as e:
        return f"Error: {e}"
    
# V-230268

def check_access_hardlinks():
    try:

        command = subprocess.run(["sysctl", "fs.protected_symlinks"],
                                 capture_output=True,
                                 text=True)
        if command.returncode != 0:
            return "Fail"

        output = command.stdout.strip()
        if "=" not in output:
            return "Fail"

        key, val = [x.strip() for x in output.split("=", 1)]
        if key != "fs.protected_symlinks" or val != "1":
            return "Fail"


        file_list = [
            "/run/sysctl.d/*.conf",
            "/usr/local/lib/sysctl.d/*.conf",
            "/usr/lib/sysctl.d/*.conf",
            "/lib/sysctl.d/*.conf",
            "/etc/sysctl.conf",
            "/etc/sysctl.d/*.conf"
        ]
        files_to_check = []
        for path in file_list:
            if "*" in path:
                files_to_check.extend(glob.glob(path))
            else:
                files_to_check.append(path)

        for file_path in files_to_check:
            try:
                with open(file_path, "r") as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "fs.protected_hardlinks" in line and "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "fs.protected_hardlinks":
                                if val == "1":
                                    return "Pass"
                                else:
                                    return "Fail"
            except Exception:
                continue  

        return "Fail" 

    except Exception as e:
        return f"Error: {e}"

# V-230531
def check_ctrlaltdelete_burst():
    try:
        with open("/etc/systemd/system.conf", "r") as output:
            for line in output:
                line = line.strip()
                if "CtrlAltDelBurstAction" in line and "=" in line:
                    key, val = [x.strip() for x in line.split("=, 1")]
                    if key == "CtrlAltDelBurstAction" and val == "none":
                        return "Pass"
                    else:
                        return "Fail"
            return "Fail"
    except Exception as e:
        return f"Error: {e}"

# V-230530        
import subprocess
import glob

def check_gui_ctrlaltdel_86():
    try:
        # Check if system is running in GUI mode
        command = subprocess.run(["systemctl", "get-default"],
                                 capture_output=True,
                                 text=True)
        output = command.stdout.strip()

        if output == "multi-user.target":
            return "Not Applicable"

        # Check for logout setting in dconf files
        file_paths = glob.glob("/etc/dconf/db/local.d/*")
        for file_path in file_paths:
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = [x.strip() for x in line.split("=", 1)]
                            if key == "logout" and val == "":
                                return "Pass"
            except Exception:
                continue  # skip unreadable files

        return "Fail"
    except Exception as e:
        return f"Error: {e}"

