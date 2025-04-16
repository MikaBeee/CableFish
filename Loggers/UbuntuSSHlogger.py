import paramiko
import os
from pathlib import Path
import json
import time

CONFIG_FILE = "ssh_config.json"

class SSHLogger:
    @staticmethod
    def save_config(host, username, private_key_path):
        config = {
            "host": host,
            "username": username,
            "private_key_path": private_key_path
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
        print("Configuration saved.")

    @staticmethod
    def load_config():
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            print("Configuration loaded.")
            return config
        return None

    @staticmethod
    def check_ssh_authentication(host, username, private_key_path, private_key_pass=None):
        try:
            # Load the private key
            try:
                private_key = paramiko.RSAKey.from_private_key_file(private_key_path, password=private_key_pass)
            except paramiko.SSHException:
                try:
                    private_key = paramiko.Ed25519Key.from_private_key_file(private_key_path, password=private_key_pass)
                except paramiko.SSHException:
                    print("Failed to load private key. Please ensure the key is valid and accessible.")
                    return False

            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
            # Establish the connection
            ssh_client.connect(hostname=host, username=username, pkey=private_key, timeout=10)
        
            # If connection is successful, close the connection and return True
            ssh_client.close()
            return True
        except paramiko.AuthenticationException:
            print("Authentication failed. Check username and private key.")
        except Exception as e:
            print(f"An error occurred during authentication: {str(e)}")
        return False

    @staticmethod
    def get_auth_log(host, username, private_key_path, private_key_pass=None):
        try:
            # Verify key file exists
            if not os.path.exists(private_key_path):
                return False
            
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
            # Load private key with automatic type detection
            try:
                private_key = paramiko.RSAKey.from_private_key_file(
                    private_key_path,
                    password=private_key_pass
                )
            except paramiko.SSHException:
                try:
                    private_key = paramiko.Ed25519Key.from_private_key_file(
                        private_key_path,
                        password=private_key_pass
                    )
                except paramiko.SSHException:
                    print("Failed to load private key. Please ensure the key is valid and accessible.")
                    return False
            
            # Connect to server with timeout
            ssh_client.connect(
                hostname=host,
                username=username,
                pkey=private_key,
                timeout=10
            )
        
            # Create SFTP client
            sftp_client = ssh_client.open_sftp()
        
            # Download the file
            remote_path = "/var/log/auth.log"
            local_path = "Loggers/SshLogs/auth.log"
        
            print(f"Downloading {remote_path}...")
            sftp_client.get(remote_path, local_path)
            print("Download completed successfully!")
        
            # Close connections
            sftp_client.close()
            ssh_client.close()
            return True
        
        except paramiko.AuthenticationException:
            print("Authentication failed. Check username and private key.")
        except FileNotFoundError:
            print("Remote file not found.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            try:
                sftp_client.close()
                ssh_client.close()
            except:
                pass
        return False

    @staticmethod
    def wait_for_authorization(host, username, private_key_path):
        """Check authentication and wait until successful."""
        while not SSHLogger.check_ssh_authentication(host, username, str(private_key_path)):
            print("Authentication failed, retrying... is the server running?")
            time.sleep(5)  # Retry after a delay (e.g., 5 seconds)

        print("Authentication successful.")
    
    @staticmethod
    def start_monitoring():
        config = SSHLogger.load_config()

        if config:
            use_saved = input("Use saved ssh configuration? (y/n): ").strip().lower()
            if use_saved == 'y':
                host = config['host']
                username = config['username']
                private_key_path = Path(config['private_key_path'])
            else:
                # Ask for new configuration if saved config is not used
                host = input("Enter the host (IP or hostname): ")
                username = input("Enter the username: ")
                pathtokey = input("Enter the path to the private key: ")
                private_key_path = Path(pathtokey)
                SSHLogger.save_config(host, username, str(private_key_path))  # Save the new config
        else:
            # Ask for new configuration if no config found
            host = input("Enter the host (IP or hostname): ")
            username = input("Enter the username: ")
            pathtokey = input("Enter the path to the private key: ")
            private_key_path = Path(pathtokey)
            SSHLogger.save_config(host, username, str(private_key_path))  # Save the new config

        # Wait for authentication to be successful before proceeding
        SSHLogger.wait_for_authorization(host, username, private_key_path)

        # Continuous monitoring of the auth log
        while True:
            print("Proceeding with log download...")
            success = SSHLogger.get_auth_log(host, username, str(private_key_path))
            if not success:
                print("Failed to download auth.log.")
            
            # Sleep for a defined period before checking again (e.g., 30 seconds)
            time.sleep(30)  


# Start the monitoring process when the script runs