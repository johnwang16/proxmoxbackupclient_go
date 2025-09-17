This software implements a proxmox backup client software for windows, backup only as of now
Works on linux too especially for development

The software is still alpha quality and i take no responsability for any kind of damage or data loss even of source files.

Contributions are welcome especially 

1. GUI with tray icon to show backup progress and backup taking place
2. A GUI way of configuring it and maybe create a json job file similiar freefilesync does
3. Async upload / compress and multicore upload + compression of chunks
4. Proxmox side patch to add another kind of entry to pxar format with Windows security descriptors in it
5. Support for windows symlinks
6. Anything interesting you can come up with :)

Usage
=====

A typical command would look like:
```shell
proxmoxbackupgo.exe -baseurl "https://yourpbshost:8007" -certfingerprint pbsfingerprint -authid "user@realm!apiid" -secret "apisecret" -backupdir "C:\path\to\backup" -datastore "datastorename"

```


```
proxmoxbackupgo.exe
  -authid string
        Authentication ID (PBS Api token)
  -secret string
        Secret for authentication
  -backupdir string
        Backup source directory, must not be symlink
  -baseurl string
        Base URL for the proxmox backup server, example: https://192.168.1.10:8007
  -certfingerprint string
        Certificate fingerprint for SSL connection, example: ea:7d:06:f9...
  -datastore string
        Datastore name
  -namespace string
        Namespace (optional)
  -backup-id string
        Backup ID (optional - if not specified, the hostname is used as the default for host-type backups)
  -pxarout string
        Output PXAR archive for debug purposes (optional)
  -backupstream string  ***NEW***
    	Filename for stream backup
  -mail-host string
        mail notification system: mail server host(optional)
  -mail-port string
        mail notification system: mail server port(optional)
  -mail-username string
        mail notification system: mail server username(optional)
  -mail-password string
        mail notification system: mail server password(optional)
  -mail-insecure bool
        mail notification system: allow insecure communications(optional)
  -mail-from string
        mail notification system: sender mail(optional)
  -mail-to string
        mail notification system: receiver mail(optional)

  -mail-subject-template string
        mail notification system: mail subject template(optional)
  -mail-body-template string
        mail notification system: mail body template(optional)

  -encryption-key-path string
        Path to encryption key file (optional)
  -encryption-password string
        Password for encrypted key file (optional)
  -master-key-path string
        Path to RSA master key for key recovery (optional)
  -force-full-backup bool
        Force a full backup, ignoring previous backup for incremental deduplication (optional)

  -config string
        Path to JSON config file. If this flag is provided all the others will override the loaded config file

```

For JSON configuration, several examples are provided:
- `config.json.example` - Basic backup configuration
- `config.json.encryption.example` - Configuration with encryption enabled for backup and restore
- `config.combined.example.json` - Combined config supporting both backup and restore modes
- `config.restore.example.json` - Restore-only configuration

Fill in only the needed fields.


Note on mail templating:
[Go's templating engine](https://pkg.go.dev/text/template) is used for mail subjects and bodies, please refer to the documentation for the syntax.
The following variables are available for templating:
- `.NewChunks`: number of new chunks created
- `.ReusedChunks`: number of chunks reused
- `.Datastore`: datastore name
- `.Error`: error message if any
- `.Hostname`: hostname of the machine
- `.StartTime`: time the backup started
- `.EndTime`: time the backup ended
- `.Duration`: duration of the backup
- `.FromattedDuration`: formatted duration of the backup
- `.Success`: a boolean telling whether the backup was successful 
- `.Status`: string representation of the backup status [SUCCESS, FAILURE]

Stream Backup
=============
This allows backing up a stream instead of a PXAR, allows endless possibilities for example you can invoke 

```
mysqldump yourdatabase | ./proxmoxbackupgo -backupstream yourdatabase.sql [other options]
```

This allows leveraging buzhash for dedup even when using tar for example, or the sql dump itself, and if someone wants to attempt it should be possible with some hack to pipe DISM command to generate WIM image to this and have full host backup

Encryption
==========

This client supports PBS-compatible client-side encryption with:
- AES-256-GCM encryption algorithm with 16-byte IV support
- Scrypt key derivation function for password-protected keys
- PBKDF2 for internal key derivation
- Master key support for key recovery
- JSON key file format compatible with proxmox-backup-client

## Native Go Cryptography

This client uses **native Go cryptographic operations** for full PBS compatibility without external dependencies:

- **Pure Go AES-256-GCM encryption** using `crypto/cipher.NewGCMWithNonceSize()` for 16-byte IV support
- **Cross-platform support** (Windows, Linux, macOS) with no runtime dependencies
- **No CGO required** - builds as a pure Go binary
- **Simplified deployment** - single executable with no DLL/shared library requirements

**For detailed technical information about the encryption implementation, see [Encryption.md](Encryption.md)**

### Using Encryption

To use encryption:
1. Create an encryption key using `proxmox-backup-client key create` or any PBS-compatible tool
2. Specify the key file path with `-encryption-key-path` parameter
3. Provide the key password with `-encryption-password` parameter (if key is password-protected)
4. Optionally specify a master key with `-master-key-path` parameter for recovery purposes

Example with encryption:
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backupdir "C:\data" -encryption-key-path "backup.key" -encryption-password "mypass123"
```

### Building

The client can be built as a standard Go application:

**Windows:**
```cmd
go build -o proxmoxbackupclient_go.exe .
```

Or use the provided build script:
```cmd
build.sh
```

**Linux/macOS:**
```bash
go build -o proxmoxbackupclient_go .
```

No special build flags or external libraries are required for encryption support.

Restore Operations
==================

This client supports full restore operations for both encrypted and unencrypted PBS backups, including PXAR archives and stream backups.

### List Available Snapshots

Before restoring, you can list all available backup snapshots:

```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backup-id "hostname" -list-snapshots
```

This will show available snapshots with timestamps, files, and encryption status.

### Restore Parameters

```
  -restore string
        Enable restore mode with optional path filter (use '*' to restore everything)
  -restore-archive string
        Archive name to restore (defaults to "backup.pxar.didx")
  -restore-output string
        Output path for restored data (required when using -restore)
  -restore-snapshot string
        Backup snapshot timestamp (e.g., "1704110400" or "2024-01-01T12:00:00Z") 
        or 'latest' for most recent (default: "latest")
```

### Selective Restore

The restore functionality supports selective restoration of specific files or directories:

- **Restore everything**: `-restore "*"` or `-restore="*"`
- **Restore specific path**: `-restore="path/to/file"` or `-restore="directory/"`
- **Case-insensitive filtering**: Path matching is case-insensitive for better cross-platform compatibility

When using selective restore, only files and directories matching the specified path will be extracted.

### How Restore Works

1. **Snapshot Resolution**: The client first fetches the list of available snapshots from PBS
2. **Snapshot Selection**: 
   - If `-restore-snapshot` is "latest" or omitted, selects the most recent snapshot
   - If a timestamp is provided, finds the exact matching snapshot
3. **Data Retrieval**: Downloads and decrypts/decompresses chunks as needed
4. **Data Integrity Verification**: Each chunk is validated against its expected digest to ensure data integrity
5. **PXAR Extraction**: For PXAR archives, extracts all files and directories with proper permissions

### Data Integrity Verification

The client implements comprehensive data integrity checks during restore operations:

- **Chunk Digest Validation**: Every restored chunk is verified against its expected digest from the backup index
- **Encryption-Aware**: Uses appropriate digest calculation method based on chunk encryption status
  - Encrypted chunks: SHA256(plaintext + id_key) following PBS specification
  - Unencrypted chunks: SHA256(plaintext) standard checksum
- **Error Detection**: Corrupted chunks, transmission errors, or storage issues are detected and reported
- **PBS Compatibility**: Uses identical digest validation logic as the official proxmox-backup-client

If a chunk fails digest verification, the restore operation will stop with an error message like:
```
failed to decode chunk abc123...: detected chunk with wrong digest
```

### Restore Examples

**Restore everything (uses defaults: backup.pxar.didx, latest snapshot):**
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backup-id "hostname" -restore "*" -restore-output "C:\restored"
```

**Restore specific file or directory:**
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backup-id "hostname" -restore "Documents/important.txt" -restore-output "C:\restored"
```

**Restore specific snapshot with encryption:**
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backup-id "hostname" -restore "*" -restore-output "C:\restored" -restore-snapshot "1704110400" -encryption-key-path "backup.key" -encryption-password "mypass123"
```

**Restore stream backup to file:**
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backup-id "hostname" -restore "*" -restore-archive "database.sql.didx" -restore-output "C:\database-restored.sql"
```

### Using Config Files for Both Backup and Restore

The same config file can contain both backup and restore settings. Use the `-restore` flag to switch modes:

**Combined config file (config.json):**
```json
{
  "baseurl": "https://pbs.example.com:8007",
  "authid": "user@pbs!token",
  "secret": "your-secret-token",
  "datastore": "backup",
  "backup-id": "hostname",
  
  "comment": "Backup settings (used when -restore flag is NOT present)",
  "backupdir": "C:\\data",
  "force-full-backup": false,
  
  "comment": "Restore settings (used when -restore flag IS present)",
  "restore-archive": "backup.pxar.didx",
  "restore-output": "C:\\restored",
  "restore-snapshot": "latest",
  
  "comment": "Encryption settings (used for both backup and restore)",
  "encryption-key-path": "backup.key",
  "encryption-password": "mypass123"
}
```

**For backup mode:**
```shell
proxmoxbackupgo.exe -config config.json
```

**For restore mode (same config file):**
```shell
proxmoxbackupgo.exe -config config.json -restore "*"
```

**Restore specific path:**
```shell
proxmoxbackupgo.exe -config config.json -restore "Documents/folder"
```

**Override config values:**
```shell
proxmoxbackupgo.exe -config config.json -restore "*" -restore-output "D:\\different-location"
```


Force Full Backup
==================

The `-force-full-backup` flag disables incremental backup and forces a complete backup of all data. 

**Automatic Detection**: The client now automatically detects when switching between encrypted and unencrypted modes and forces a full backup to prevent chunk format mismatches. You'll see a message like:
```
Encryption mode mismatch detected (current: true, previous: false) - forcing full backup
```

**Manual Override**: You can still manually force full backups when needed for:

1. **Recovery scenarios**: After corruption or when you want to ensure a clean backup baseline
2. **Storage migration**: When moving to a new backup repository
3. **Troubleshooting**: When incremental backups aren't working as expected

Example forcing full backup:
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backupdir "C:\data" -force-full-backup
```

Known Issues
============

Windows defender antimalware being active will slow backup down up to 25% of attainable speed 

There's as of now no mechanism to prevent two instances being launched at same time which will screw up VSS and backup
If you using windows planning utility it should theoretically prevent two instances starting at same time when originating from same job

