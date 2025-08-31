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

For JSON configuration examples are provided:
- `config.json.example` - Basic configuration
- `config.json.encryption.example` - Configuration with encryption enabled

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
- AES-256-GCM encryption algorithm
- PBKDF2 key derivation function 
- Master key support for key recovery
- JSON key file format compatible with proxmox-backup-client

To use encryption:
1. Create an encryption key using `proxmox-backup-client key create` or any PBS-compatible tool
2. Specify the key file path with `-encryption-key-path` parameter
3. Provide the key password with `-encryption-password` parameter (if key is password-protected)
4. Optionally specify a master key with `-master-key-path` parameter for recovery purposes

Example with encryption:
```shell
proxmoxbackupgo.exe -baseurl "https://pbs:8007" -authid "user@realm!token" -secret "secret" -datastore "backup" -backupdir "C:\data" -encryption-key-path "backup.key" -encryption-password "mypass123"
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

