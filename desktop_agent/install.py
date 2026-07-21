"""
CipherGuard Desktop Agent - Service Installation Script

Installs the desktop agent as a Windows scheduled task or systemd service
for continuous network traffic monitoring.
"""

import os
import sys
import subprocess
import platform


def install_windows():
    """Install as a Windows Scheduled Task"""
    script_path = os.path.abspath("agent.py")
    python_path = sys.executable

    # Create XML for scheduled task
    task_name = "CipherGuardAgent"
    command = (
        f'schtasks /Create /SC MINUTE /MO 1 '
        f'/TN "{task_name}" '
        f'/TR "{python_path} {script_path}" '
        f'/F'
    )

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"✅ Windows Scheduled Task '{task_name}' created successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create scheduled task: {e}")
        return False


def install_linux():
    """Install as a systemd service (Linux)"""
    service_content = f"""[Unit]
Description=CipherGuard IDS Desktop Agent
After=network.target

[Service]
ExecStart={sys.executable} {os.path.abspath('agent.py')}
WorkingDirectory={os.path.abspath('.')}
Restart=always
RestartSec=10
User={os.getenv('USER', 'root')}

[Install]
WantedBy=multi-user.target
"""

    service_path = "/etc/systemd/system/cipherguard-agent.service"
    try:
        # Write service file
        with open("/tmp/cipherguard-agent.service", "w") as f:
            f.write(service_content)

        subprocess.run(
            f"sudo mv /tmp/cipherguard-agent.service {service_path} "
            f"&& sudo systemctl daemon-reload "
            f"&& sudo systemctl enable cipherguard-agent.service "
            f"&& sudo systemctl start cipherguard-agent.service",
            shell=True, check=True
        )
        print("✅ systemd service installed and started.")
        return True
    except Exception as e:
        print(f"❌ Failed to install systemd service: {e}")
        return False


def install():
    """Detect platform and install accordingly"""
    print("=" * 60)
    print("🛡️ CipherGuard Desktop Agent Installer")
    print("=" * 60)

    system = platform.system()

    if system == "Windows":
        return install_windows()
    elif system == "Linux":
        return install_linux()
    else:
        print(f"❌ Unsupported platform: {system}")
        print("   On macOS, run manually: python agent.py")
        return False


if __name__ == "__main__":
    install()