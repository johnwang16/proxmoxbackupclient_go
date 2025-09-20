package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type MailSendConfig struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type MailTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type SMTPConfig struct {
	Host     string           `json:"host"`
	Port     string           `json:"port"`
	Username string           `json:"username"`
	Password string           `json:"password"`
	Insecure bool             `json:"insecure"`
	Mails    []MailSendConfig `json:"mails"`
	Template *MailTemplate    `json:"template"`
}

type Config struct {
	BaseURL              string      `json:"baseurl"`
	CertFingerprint      string      `json:"certfingerprint"`
	AuthID               string      `json:"authid"`
	Secret               string      `json:"secret"`
	Datastore            string      `json:"datastore"`
	Namespace            string      `json:"namespace"`
	BackupID             string      `json:"backup-id"`
	BackupSourceDir      string      `json:"backupdir"`
	BackupStreamName     string      `json:"backupstreamname"`
	PxarOut              string      `json:"pxarout"`
	EncryptionKeyPath    string      `json:"encryption-key-path"`
	EncryptionPassword   string      `json:"encryption-password"`
	MasterKeyPath        string      `json:"master-key-path"`
	LogLevel             string             `json:"log-level"`
	Performance          *PerformanceConfig `json:"performance"`
	SMTP                 *SMTPConfig        `json:"smtp"`
	
	// Restore options
	RestoreArchive       string      `json:"restore-archive"`
	RestoreOutput        string      `json:"restore-output"`
	RestoreSnapshot      string      `json:"restore-snapshot"`  // backup timestamp, e.g., "2024-01-01T12:00:00Z"
	ListSnapshots        bool        `json:"list-snapshots"`
}

func (c *Config) valid(isRestore bool) bool {
	// Base connection requirements for both backup and restore
	baseValid := c.BaseURL != "" && c.AuthID != "" && c.Secret != "" && c.Datastore != ""
	if !baseValid {
		return baseValid
	}
	
	// List snapshots mode - only requires connection info
	if c.ListSnapshots {
		return true
	}
	
	// Restore mode validation
	if isRestore {
		return c.RestoreOutput != ""  // Only output path is required for restore
	}
	
	// Backup mode validation
	backupValid := c.BackupSourceDir != "" || c.BackupStreamName != ""
	if !backupValid {
		return backupValid
	}

	if c.SMTP != nil {
		mailCfgValid := c.SMTP.Host != "" && c.SMTP.Port != "" && c.SMTP.Username != "" && c.SMTP.Password != ""
		if len(c.SMTP.Mails) == 0 {
			return false
		}
		for i := range c.SMTP.Mails {
			mailCfgValid = mailCfgValid && (c.SMTP.Mails[i].From != "" && c.SMTP.Mails[i].To != "")
		}
		return mailCfgValid
	}

	return true
}

func loadConfig() (*Config, bool, string) {
	// Define flags
	baseURLFlag := flag.String("baseurl", "", "Base URL for the proxmox backup server, example: https://192.168.1.10:8007")
	certFingerprintFlag := flag.String("certfingerprint", "", "Certificate fingerprint for SSL connection, example: ea:7d:06:f9...")
	authIDFlag := flag.String("authid", "", "Authentication ID (PBS Api token)")
	secretFlag := flag.String("secret", "", "Secret for authentication")
	datastoreFlag := flag.String("datastore", "", "Datastore name")
	namespaceFlag := flag.String("namespace", "", "Namespace (optional)")
	backupIDFlag := flag.String("backup-id", "", "Backup ID (optional - if not specified, the hostname is used as the default)")
	backupSourceDirFlag := flag.String("backupdir", "", "Backup source directory, must not be symlink")
	backupStreamNameFlag := flag.String("backupstream", "", "Filename for stream backup")
	pxarOutFlag := flag.String("pxarout", "", "Output PXAR archive for debug purposes (optional)")

	mailHostFlag := flag.String("mail-host", "", "mail notification system: mail server host(optional)")
	mailPortFlag := flag.String("mail-port", "", "mail notification system: mail server port(optional)")
	mailUsernameFlag := flag.String("mail-username", "", "mail notification system: mail server username(optional)")
	mailPasswordFlag := flag.String("mail-password", "", "mail notification system: mail server password(optional)")
	mailInsecureFlag := flag.Bool("mail-insecure", false, "mail notification system: allow insecure communications(optional)")
	mailFromFlag := flag.String("mail-from", "", "mail notification system: sender mail(optional)")
	mailToFlag := flag.String("mail-to", "", "mail notification system: receiver mail(optional)")
	mailSubjectTemplateFlag := flag.String("mail-subject-template", "", "mail notification system: mail subject template(optional)")
	mailBodyTemplateFlag := flag.String("mail-body-template", "", "mail notification system: mail body template(optional)")

	encryptionKeyPathFlag := flag.String("encryption-key-path", "", "Path to encryption key file (optional)")
	encryptionPasswordFlag := flag.String("encryption-password", "", "Password for encrypted key file (optional)")
	masterKeyPathFlag := flag.String("master-key-path", "", "Path to RSA master key for key recovery (optional)")
	logLevelFlag := flag.String("log-level", DEFAULT_LOG_LEVEL, "Log level: info, performance, debug (default: info)")
	
	// Performance tuning flags
	readBufferFlag := flag.Int("read-buffer-mb", 0, "Read buffer size in MB for files and streams (default: 8MB if omitted)")
	workerCountFlag := flag.Int("worker-count", 0, "Number of parallel workers (0=auto) (optional)")

	// Restore flags
	// Note: Use -restore=* or just -restore * to restore everything, or -restore=path for specific path
	restoreFlag := flag.String("restore", "", "Enable restore mode with optional path filter (use '*' to restore everything)")
	restoreArchiveFlag := flag.String("restore-archive", PXAR_ARCHIVE_NAME, "Archive name to restore (defaults to backup.pxar.didx)")
	restoreOutputFlag := flag.String("restore-output", "", "Output path for restored data (required when using -restore)")
	restoreSnapshotFlag := flag.String("restore-snapshot", "latest", "Backup snapshot timestamp (e.g., 2024-01-01T12:00:00Z) or 'latest' for most recent (default: latest)")
	listSnapshotsFlag := flag.Bool("list-snapshots", false, "List available backup snapshots and exit")

	configFile := flag.String("config", "", "Path to JSON config file. If this flag is provided all the others will override the loaded config file")

	// Parse command line flags
	flag.Parse()

	config := &Config{}
	if *configFile != "" {
		file, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Printf("Error reading config file: %v\n", err)
			os.Exit(1)
		}
		err = json.Unmarshal(file, config)
		if err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

	if *baseURLFlag != "" {
		config.BaseURL = *baseURLFlag
	}
	if *certFingerprintFlag != "" {
		config.CertFingerprint = *certFingerprintFlag
	}
	if *authIDFlag != "" {
		config.AuthID = *authIDFlag
	}
	if *secretFlag != "" {
		config.Secret = *secretFlag
	}
	if *datastoreFlag != "" {
		config.Datastore = *datastoreFlag
	}
	if *namespaceFlag != "" {
		config.Namespace = *namespaceFlag
	}
	if *backupIDFlag != "" {
		config.BackupID = *backupIDFlag
	}
	if *backupSourceDirFlag != "" {
		config.BackupSourceDir = *backupSourceDirFlag
	}

	if *backupStreamNameFlag != "" {
		config.BackupStreamName = *backupStreamNameFlag
	}
	if *pxarOutFlag != "" {
		config.PxarOut = *pxarOutFlag
	}

	initSmtpConfigIfNeeded := func() {
		if config.SMTP == nil {
			config.SMTP = &SMTPConfig{}
		}
	}
	initMailConfsIfNeeded := func() {
		initSmtpConfigIfNeeded()
		if len(config.SMTP.Mails) == 0 {
			config.SMTP.Mails = append(config.SMTP.Mails, MailSendConfig{})
		}
	}

	if *mailHostFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Host = *mailHostFlag
	}
	if *mailPortFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Port = *mailPortFlag
	}
	if *mailUsernameFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Username = *mailUsernameFlag
	}
	if *mailPasswordFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Password = *mailPasswordFlag
	}
	if *mailInsecureFlag {
		initSmtpConfigIfNeeded()
		config.SMTP.Insecure = *mailInsecureFlag
	}
	if *mailFromFlag != "" {
		initMailConfsIfNeeded()
		config.SMTP.Mails[0].From = *mailFromFlag
	}
	if *mailToFlag != "" {
		initMailConfsIfNeeded()
		config.SMTP.Mails[0].To = *mailToFlag
	}
	if *mailSubjectTemplateFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Template.Subject = *mailSubjectTemplateFlag
	}
	if *mailBodyTemplateFlag != "" {
		initSmtpConfigIfNeeded()
		config.SMTP.Template.Body = *mailBodyTemplateFlag
	}
	if *encryptionKeyPathFlag != "" {
		config.EncryptionKeyPath = *encryptionKeyPathFlag
	}
	if *encryptionPasswordFlag != "" {
		config.EncryptionPassword = *encryptionPasswordFlag
	}
	if *masterKeyPathFlag != "" {
		config.MasterKeyPath = *masterKeyPathFlag
	}
	if *logLevelFlag != "" {
		config.LogLevel = *logLevelFlag
	}
	
	// Initialize performance configuration
	if config.Performance == nil {
		perfConfig := DefaultPerformanceConfig()
		config.Performance = &perfConfig
	}
	
	// Override performance settings from command line flags
	if *readBufferFlag > 0 {
		config.Performance.ReadBufferMB = *readBufferFlag
	} else if *readBufferFlag < 0 {
		fmt.Printf("Error: read-buffer-mb must be positive (got %d), using default 8MB\n", *readBufferFlag)
	}
	if *workerCountFlag > 0 {
		config.Performance.WorkerCount = *workerCountFlag
	}
	
	// Validate the final configuration
	config.Performance.ValidateConfig()

	// Set restore flags - archive and snapshot have defaults
	config.RestoreArchive = *restoreArchiveFlag  // Default: "backup.pxar.didx"
	if *restoreOutputFlag != "" {
		config.RestoreOutput = *restoreOutputFlag
	}
	config.RestoreSnapshot = *restoreSnapshotFlag  // Default: "latest"
	config.ListSnapshots = *listSnapshotsFlag

	// Return config and restore info (path from flag, mode determined by flag being set)
	restoreFlagSet := false
	restorePath := ""
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "restore" {
			restoreFlagSet = true
			// Handle special case: "*" means restore everything (same as empty)
			if *restoreFlag == "*" {
				restorePath = ""
			} else {
				restorePath = *restoreFlag
			}
		}
	})
	return config, restoreFlagSet, restorePath
}
