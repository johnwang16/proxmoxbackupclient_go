package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cornelk/hashmap"
	"github.com/gen2brain/beeep"
	"github.com/getlantern/systray"
	"github.com/tawesoft/golib/v2/dialog"
)




var defaultMailSubjectTemplate = "Backup {{.Status}}"
var defaultMailBodyTemplate = `{{if .Success}}Backup complete ({{.FromattedDuration}})
Chunks New {{.NewChunks}}, Reused {{.ReusedChunks}}.{{else}}Error occurred while working, backup may be not completed.
Last error is: {{.ErrorStr}}{{end}}`

// Constants moved to constants.go

type ChunkState struct {
	assignments        []string
	assignments_offset []uint64
	pos                uint64
	wrid               uint64
	chunkcount         uint64
	chunkdigests       hash.Hash
	current_chunk      []byte
	C                  Chunker
	newchunk *atomic.Uint64 
	reusechunk *atomic.Uint64
	knownChunks *hashmap.Map[string, bool]
	cryptConfig *CryptConfig
}

type DidxEntry struct {
	offset uint64
	digest []byte
}

func (c *ChunkState) Init(newchunk *atomic.Uint64 , reusechunk *atomic.Uint64, knownChunks *hashmap.Map[string, bool], cryptConfig *CryptConfig ) {
	c.assignments = make([]string, 0)
	c.assignments_offset = make([]uint64, 0)
	c.pos = 0
	c.chunkcount = 0
	c.chunkdigests = sha256.New()
	c.current_chunk = make([]byte, 0)
	c.cryptConfig = cryptConfig
	
	chunkAvgSize := uint64(DEFAULT_CHUNK_SIZE)
	if cryptConfig != nil {
		// Reduce chunk size to account for encryption overhead (28 bytes for AES-GCM)
		// Use safety margin to ensure max chunks stay under PBS 16MB limit
		chunkAvgSize = uint64(DEFAULT_CHUNK_SIZE - 100)
	}
	c.C = Chunker{}
	c.C.New(chunkAvgSize)
	c.reusechunk = reusechunk
	c.newchunk = newchunk
	c.knownChunks = knownChunks
}

// computeChunkDigest computes the correct digest for a chunk following PBS spec
func (c *ChunkState) computeChunkDigest(data []byte) ([]byte, string) {
	if c.cryptConfig != nil {
		// For encrypted chunks: hash plaintext + encryption key
		digest := c.cryptConfig.ComputeDigest(data)
		return digest[:], hex.EncodeToString(digest[:])
	} else {
		// For unencrypted chunks: hash plaintext only
		h := sha256.New()
		h.Write(data)
		bindigest := h.Sum(nil)
		return bindigest, hex.EncodeToString(bindigest)
	}
}

func (c *ChunkState) HandleData(b []byte, client *PBSClient){
	// Use standard chunking algorithm
	chunkpos := c.C.Scan(b)

	if chunkpos == 0 {
		//No break happened, just append data 
		c.current_chunk = append(c.current_chunk, b...)
	} else {

		for chunkpos > 0 {
			//Append data until break position
			c.current_chunk = append(c.current_chunk, b[:chunkpos]...)

			chunkData := c.current_chunk
			var bindigest []byte
			var shahash string
			
			if c.cryptConfig != nil {
				var err error
				
				// First create the encrypted DataBlob (this determines what data gets encrypted)
				chunkData, err = c.cryptConfig.EncodeDataBlob(c.current_chunk, true)
				if err != nil {
					fmt.Printf("DataBlob encoding failed: %v\n", err)
					return
				}
				
				// Calculate digest on the exact data that was encrypted (stored in lastDigestData)
				bindigest, shahash = c.computeChunkDigest(c.cryptConfig.lastDigestData)
			} else {
				// Unencrypted chunks - digest on original data
				bindigest, shahash = c.computeChunkDigest(c.current_chunk)
			}

			if _, ok := c.knownChunks.GetOrInsert(shahash, true); !ok {
				fmt.Printf("New chunk[%s] %d bytes\n", shahash, len(chunkData))
				c.newchunk.Add(1)

				if c.cryptConfig != nil {
					// For encrypted chunks, upload as raw blob since it's already in DataBlob format
					client.UploadRawChunk(c.wrid, shahash, chunkData, len(c.current_chunk))
				} else {
					client.UploadCompressedChunk(c.wrid, shahash, chunkData, len(c.current_chunk))
				}
			} else {
				fmt.Printf("Reuse chunk[%s] %d bytes\n", shahash, len(chunkData))
				c.reusechunk.Add(1)
			}

			// TODO: error handling inside callback
			binary.Write(c.chunkdigests, binary.LittleEndian, (c.pos + uint64(len(c.current_chunk))))
			// TODO: error handling inside callback
			c.chunkdigests.Write(bindigest)

			c.assignments_offset = append(c.assignments_offset, c.pos)
			c.assignments = append(c.assignments, shahash)
			c.pos += uint64(len(c.current_chunk))
			c.chunkcount += 1

			c.current_chunk = make([]byte, 0)
			b = b[chunkpos:] //Take remainder of data 
			chunkpos = c.C.Scan(b)
			
		}

		//No further break happened, append remaining data
		c.current_chunk = append(c.current_chunk, b...)
	}
}

func (c *ChunkState) Eof(client *PBSClient) {
	//Here we write the remainder of data for which cyclic hash did not trigger
	
	if len(c.current_chunk) > 0 {
		chunkData := c.current_chunk
		var bindigest []byte
		var shahash string
		
		if c.cryptConfig != nil {
			var err error
			
			// First create the encrypted DataBlob (this determines what data gets encrypted)
			chunkData, err = c.cryptConfig.EncodeDataBlob(c.current_chunk, true)
			if err != nil {
				fmt.Printf("DataBlob encoding failed: %v\n", err)
				return
			}
			
			// Calculate digest on the exact data that was encrypted (stored in lastDigestData)
			bindigest, shahash = c.computeChunkDigest(c.cryptConfig.lastDigestData)
		} else {
			// Unencrypted chunks - digest on original data
			bindigest, shahash = c.computeChunkDigest(c.current_chunk)
		}

		binary.Write(c.chunkdigests, binary.LittleEndian, (c.pos + uint64(len(c.current_chunk))))
		c.chunkdigests.Write(bindigest)

		if _, ok := c.knownChunks.GetOrInsert(shahash, true); !ok {
			fmt.Printf("New chunk[%s] %d bytes\n", shahash, len(chunkData))
			if c.cryptConfig != nil {
				// For encrypted chunks, upload as raw blob since it's already in DataBlob format
				client.UploadRawChunk(c.wrid, shahash, chunkData, len(c.current_chunk))
			} else {
				client.UploadCompressedChunk(c.wrid, shahash, chunkData, len(c.current_chunk))
			}
			c.newchunk.Add(1)
		} else {
			fmt.Printf("Reuse chunk[%s] %d bytes\n", shahash, len(chunkData))
			c.reusechunk.Add(1)
		}
		c.assignments_offset = append(c.assignments_offset, c.pos)
		c.assignments = append(c.assignments, shahash)
		c.pos += uint64(len(c.current_chunk))
		c.chunkcount += 1

	}
	//Avoid incurring in request entity too large by chunking assignment PUT requests in blocks of at most 128 chunks
	for k := 0; k < len(c.assignments); k += 128 {
		k2 := k + 128
		if k2 > len(c.assignments) {
			k2 = len(c.assignments)
		}
		client.AssignChunks(c.wrid, c.assignments[k:k2], c.assignments_offset[k:k2])
	}

	digest := hex.EncodeToString(c.chunkdigests.Sum(nil))
	client.CloseDynamicIndex(c.wrid, digest, c.pos, c.chunkcount)
}



func main() {
	var newchunk *atomic.Uint64 = new(atomic.Uint64)
	var reusechunk *atomic.Uint64 = new(atomic.Uint64)

	cfg, isRestore, restorePath := loadConfig()
	cfg.InitializeLogLevel()
	
	// Show worker count for all parallel operations
	if cfg.Performance != nil {
		fmt.Printf("Using %d workers for parallel processing\n", cfg.Performance.GetWorkerCount())
	}

	var cryptConfig *CryptConfig
	if cfg.EncryptionKeyPath != "" {
		var err error
		cryptConfig, err = NewCryptConfig(cfg.EncryptionKeyPath, cfg.EncryptionPassword, cfg.MasterKeyPath)
		if err != nil {
			fmt.Printf("Failed to initialize encryption: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Encryption enabled")
	} else {
		fmt.Printf("No encryption configured\n")
	}

	if ok := cfg.valid(isRestore); !ok {
		if runtime.GOOS == "windows" {
			usage := "All options are mandatory:\n"
			flag.VisitAll(func(f *flag.Flag) {
				usage += "-" + f.Name + " " + f.Usage + "\n"
			})
			dialog.Error(usage)
		} else {
			fmt.Println("All options are mandatory")

			flag.PrintDefaults()
		}
		os.Exit(1)
	}

	L := Locking{}

	
	lock_ok := L.AcquireProcessLock()
	if !lock_ok {
		
		dialog.Error("Backup jobs need to run exclusively, please wait until the previous job has finished")
		os.Exit(2)
	}
	defer L.ReleaseProcessLock()
	if runtime.GOOS == "windows" {
		go systray.Run(func() {
			systray.SetIcon(ICON)
			systray.SetTooltip("PBSGO Backup running")
			beeep.Notify("Proxmox Backup Go", "Backup started", "")
		},
			func() {

			})
	}
	

	insecure := cfg.CertFingerprint != ""

	client := &PBSClient{
		baseurl:         cfg.BaseURL,
		certfingerprint: cfg.CertFingerprint, //"ea:7d:06:f9:87:73:a4:72:d0:e8:05:a4:b3:3d:95:d7:0a:26:dd:6d:5c:ca:e6:99:83:e4:11:3b:5f:10:f4:4b",
		authid:          cfg.AuthID,
		secret:          cfg.Secret,
		datastore:       cfg.Datastore,
		namespace:       cfg.Namespace,
		insecure:        insecure,
		cryptConfig:     cryptConfig,
		manifest: BackupManifest{
			BackupID: cfg.BackupID,
		},
	}
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Failed to retrieve hostname:", err)
		hostname = "unknown"
	}

	begin := time.Now()
	
	// Handle list snapshots mode
	if cfg.ListSnapshots {
		fmt.Printf("Listing available snapshots...\n")
		client.ConnectRestore()
		
		snapshots, err := client.ListSnapshots()
		if err != nil {
			fmt.Printf("Failed to list snapshots: %v\n", err)
			os.Exit(1)
		}
		
		if len(snapshots) == 0 {
			fmt.Printf("No snapshots found in datastore '%s'\n", cfg.Datastore)
		} else {
			fmt.Printf("Available snapshots in datastore '%s':\n", cfg.Datastore)
			for _, snapshot := range snapshots {
				// Convert timestamp to readable format
				backupTime := time.Unix(snapshot.BackupTime, 0)
				fmt.Printf("  - Backup ID: %s\n", snapshot.BackupID)
				fmt.Printf("    Time: %s (%d)\n", backupTime.Format("2006-01-02 15:04:05 MST"), snapshot.BackupTime)
				fmt.Printf("    Type: %s\n", snapshot.BackupType)
				if snapshot.Comment != "" {
					fmt.Printf("    Comment: %s\n", snapshot.Comment)
				}
				fmt.Printf("    Files:\n")
				for _, file := range snapshot.Files {
					fmt.Printf("      - %s (%s, %d bytes)\n", file.Filename, file.CryptMode, file.Size)
				}
				fmt.Printf("\n")
			}
		}
		os.Exit(0)
	}
	
	// Handle restore mode (triggered by -restore flag)
	if isRestore {
		fmt.Printf("Starting restore mode\n")
		
		// Determine restore type based on archive name
		if strings.HasSuffix(cfg.RestoreArchive, ".pxar"+DIDX_EXTENSION) {
			// Full PXAR restore
			err = restorePXAR(client, cfg.RestoreOutput, cryptConfig, cfg.RestoreSnapshot, restorePath)
		} else {
			// Generic archive restore
			err = restoreBackup(client, cfg.RestoreArchive, cfg.RestoreOutput, cryptConfig, cfg.RestoreSnapshot)
		}
		
		if err != nil {
			fmt.Printf("Restore failed: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Restore completed successfully\n")
		os.Exit(0)
	}
	
	// Backup mode
	if cfg.BackupSourceDir != "" {
		err = backup(client, newchunk, reusechunk, cfg.PxarOut, cfg.BackupSourceDir, cryptConfig, cfg)
	} else if cfg.BackupStreamName != "" {
		sn := cfg.BackupStreamName
		if ! strings.HasSuffix(sn, DIDX_EXTENSION ) {
			sn += DIDX_EXTENSION
		}
		fmt.Printf("Backing up from STDIN to %s", sn)
		err = backup_stream(client, newchunk, reusechunk, sn, os.Stdin, cryptConfig, cfg )

	}else{
		panic("No backup dir or stream name specified, exiting")
	}

	
	end := time.Now()

	mailCtx := mailCtx{
		NewChunks:    newchunk.Load(),
		ReusedChunks: reusechunk.Load(),
		Error:        err,
		Hostname:     hostname,
		Datastore:    cfg.Datastore,
		StartTime:    begin,
		EndTime:      end,
	}

	mailBodyTemplate := defaultMailBodyTemplate
	if cfg.SMTP != nil && cfg.SMTP.Template != nil && cfg.SMTP.Template.Body != "" {
		mailBodyTemplate = cfg.SMTP.Template.Body
	}

	fmt.Printf("New %d, Reused %d, backup took %s.\n", newchunk.Load(), reusechunk.Load(), end.Sub(begin))
	var msg string
	msg, err = mailCtx.buildStr(mailBodyTemplate)
	if err != nil {
		fmt.Println("Cannot use custom mail body: " + err.Error())
		msg, err = mailCtx.buildStr(defaultMailBodyTemplate)
		if err != nil {
			// this should never happen
			panic(err)
		}
	}
	if runtime.GOOS == "windows" {
		systray.Quit()
		beeep.Notify("Proxmox Backup Go", msg, "")
	}
	if cfg.SMTP != nil {
		var subject string

		mailSubjectTemplate := defaultMailSubjectTemplate
		if cfg.SMTP.Template != nil && cfg.SMTP.Template.Subject != "" {
			mailSubjectTemplate = cfg.SMTP.Template.Subject
		}

		subject, err = mailCtx.buildStr(mailSubjectTemplate)
		if err != nil {
			fmt.Println("Cannot use custom mail subject: " + err.Error())
			msg, err = mailCtx.buildStr(defaultMailSubjectTemplate)
			if err != nil {
				// this should never happen
				panic(err)
			}
		}
		client, err := setupClient(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Insecure)
		if err != nil {
			fmt.Println("Cannot connect to mail server: " + err.Error())
			os.Exit(1)
		}
		defer client.Quit()
		for _, ccc := range cfg.SMTP.Mails {
			err = sendMail(ccc.From, ccc.To, subject, msg, client)
			if err != nil {
				fmt.Println("Cannot send email: " + err.Error())
				os.Exit(1)
			}
		}
	}

}

func backup_stream(client *PBSClient, newchunk, reusechunk *atomic.Uint64, filename string, stream io.Reader, cryptConfig *CryptConfig, config *Config ) error {
	var err error
	var previousDidx []byte
	knownChunks := hashmap.New[string, bool]()
	client.Connect(false)

	forceFullBackup := false

	// Auto-detect encryption mode mismatch
	currentlyEncrypted := (cryptConfig != nil)
	previousEncryptionMode := client.CheckPreviousEncryptionMode()
	if previousEncryptionMode == EncryptionUnknown {
		fmt.Printf("Error: Could not parse previous manifest, forcing full backup\n")
		forceFullBackup = true
	} else {
		previouslyEncrypted := (previousEncryptionMode == EncryptionEnabled)
		if currentlyEncrypted != previouslyEncrypted {
			fmt.Printf("Encryption mode mismatch detected (current: %t, previous: %t) - forcing full backup\n", currentlyEncrypted, previouslyEncrypted)
			forceFullBackup = true
		}
	}

	if !forceFullBackup {
		previousDidx, err = client.DownloadPreviousToBytes(filename)
		if err != nil {
			fmt.Printf("Could not download previous DIDX (this is normal for first backup): %v\n", err)
			fmt.Printf("Forcing full backup mode\n")
			forceFullBackup = true
		}

	}

	if !forceFullBackup && len(previousDidx) > 0 {
		fmt.Printf("Downloaded previous DIDX: %d bytes\n", len(previousDidx))

		if !bytes.HasPrefix(previousDidx, DIDX_MAGIC) {
			fmt.Printf("Previous index has wrong magic (%s)!\n", previousDidx[:8])

		} else {
			//Header as per proxmox documentation is fixed size of 4096 bytes,
			//then offset of type uint64 and sha256 digests follow , so 40 byte each record until EOF
			previousDidx = previousDidx[4096:]
			
			// Parallel DIDX parsing for faster startup on large backups
			numChunks := len(previousDidx) / DIDX_ENTRY_SIZE
			if numChunks > 0 {
				fmt.Printf("Parsing %d chunks from previous backup index...\n", numChunks)
				
				// Use worker pool for parallel parsing from performance config
				numWorkers := config.Performance.GetWorkerCount()
				
				chunkSize := (numChunks + numWorkers - 1) / numWorkers // Divide work evenly
				var wg sync.WaitGroup
				
				parseStart := time.Now()
				for w := 0; w < numWorkers; w++ {
					start := w * chunkSize
					end := (w + 1) * chunkSize
					if end > numChunks {
						end = numChunks
					}
					
					wg.Add(1)
					go func(startIdx, endIdx int) {
						defer wg.Done()
						
						for i := startIdx; i < endIdx; i++ {
							e := DidxEntry{}
							e.offset = binary.LittleEndian.Uint64(previousDidx[i*DIDX_ENTRY_SIZE : i*DIDX_ENTRY_SIZE+8])
							e.digest = previousDidx[i*DIDX_ENTRY_SIZE+8 : i*DIDX_ENTRY_SIZE+DIDX_ENTRY_SIZE]
							shahash := hex.EncodeToString(e.digest)
							// Skip debug logging in parallel mode - too much contention on stdout
							knownChunks.Set(shahash, true)
						}
					}(start, end)
				}
				
				wg.Wait()
				
				if config.ShouldLogPerformance() {
					parseDuration := time.Since(parseStart)
					fmt.Printf("Parsed %d previous chunks in %v using %d workers\n", 
						numChunks, parseDuration, numWorkers)
				}
			}
		}
	} else {
		fmt.Printf("Full backup mode - skipping previous DIDX processing\n")
	}

	fmt.Printf("Known chunks: %d!\n", knownChunks.Len())

	// Use parallel processing for stream backups
	streamChunk := &ParallelChunkState{}
	streamChunk.InitWithConfig(newchunk, reusechunk, knownChunks, cryptConfig, config)

	streamChunk.wrid, err = client.CreateDynamicIndex(filename)
	if err != nil {
		return err
	}
	
	// Start parallel processing pipeline
	streamChunk.StartParallel(client)
	
	// Use configurable buffer for I/O throughput
	bufferSizes := config.Performance.GetBufferSizes()
	B := make([]byte, bufferSizes.StreamReadBuffer)
	
	// Stream backup processing
	
	for {
		
		n, err := stream.Read(B)
		
		if n > 0 {
			streamChunk.HandleData(B[:n])
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	streamChunk.Eof()

	// CloseDynamicIndex is now handled inside Eof()

	err = client.UploadManifest()
	if err != nil {
		return err
	}

	return client.Finish()
}

func backup(client *PBSClient, newchunk, reusechunk *atomic.Uint64, pxarOut string, backupdir string, cryptConfig *CryptConfig, config *Config) error {
	var err error
	var previousDidx []byte
	knownChunks := hashmap.New[string, bool]()

	fmt.Printf("Starting backup of %s\n", backupdir)

	backupdir = createVSSSnapshot(backupdir)
	//Remove VSS snapshot on windows, on linux for now NOP
	defer VSSCleanup()

	client.Connect(false)

	archive := &PXARArchive{}
	archive.archivename = PXAR_ARCHIVE_NAME
	archive.perfConfig = config.Performance

	forceFullBackup := false

	// Auto-detect encryption mode mismatch
	currentlyEncrypted := (cryptConfig != nil)
	previousEncryptionMode := client.CheckPreviousEncryptionMode()
	if previousEncryptionMode == EncryptionUnknown {
		fmt.Printf("Error: Could not parse previous manifest, forcing full backup\n")
		forceFullBackup = true
	} else {
		previouslyEncrypted := (previousEncryptionMode == EncryptionEnabled)
		if currentlyEncrypted != previouslyEncrypted {
			fmt.Printf("Encryption mode mismatch detected (current: %t, previous: %t) - forcing full backup\n", currentlyEncrypted, previouslyEncrypted)
			forceFullBackup = true
		}
	}

	if !forceFullBackup {
		previousDidx, err = client.DownloadPreviousToBytes(archive.archivename)
		if err != nil {
			fmt.Printf("Could not download previous DIDX (this is normal for first backup): %v\n", err)
			fmt.Printf("Forcing full backup mode\n")
			forceFullBackup = true
		}

	}

	if !forceFullBackup && len(previousDidx) > 0 {
		fmt.Printf("Downloaded previous DIDX: %d bytes\n", len(previousDidx))

		// Download the previous dynamic index to figure out which chunks are the same
		// to avoid unnecessary traffic and compression cpu usage

		if !bytes.HasPrefix(previousDidx, DIDX_MAGIC) {
			fmt.Printf("Previous index has wrong magic (%s)!\n", previousDidx[:8])

		} else {
			//Header as per proxmox documentation is fixed size of 4096 bytes,
			//then offset of type uint64 and sha256 digests follow , so 40 byte each record until EOF
			previousDidx = previousDidx[4096:]
			
			// Parallel DIDX parsing for faster startup
			numChunks := len(previousDidx) / DIDX_ENTRY_SIZE
			if numChunks > 0 {
				fmt.Printf("Parsing %d chunks from previous backup index...\n", numChunks)
				
				// Use worker pool for parallel parsing from performance config
				numWorkers := config.Performance.GetWorkerCount()
				
				chunkSize := (numChunks + numWorkers - 1) / numWorkers // Divide work evenly
				var wg sync.WaitGroup
				
				parseStart := time.Now()
				for w := 0; w < numWorkers; w++ {
					start := w * chunkSize
					end := (w + 1) * chunkSize
					if end > numChunks {
						end = numChunks
					}
					
					wg.Add(1)
					go func(startIdx, endIdx int) {
						defer wg.Done()
						
						for i := startIdx; i < endIdx; i++ {
							e := DidxEntry{}
							e.offset = binary.LittleEndian.Uint64(previousDidx[i*DIDX_ENTRY_SIZE : i*DIDX_ENTRY_SIZE+8])
							e.digest = previousDidx[i*DIDX_ENTRY_SIZE+8 : i*DIDX_ENTRY_SIZE+DIDX_ENTRY_SIZE]
							shahash := hex.EncodeToString(e.digest)
							// Skip debug logging in parallel mode - too much contention on stdout
							knownChunks.Set(shahash, true)
						}
					}(start, end)
				}
				
				wg.Wait()
				
				if config.ShouldLogPerformance() {
					parseDuration := time.Since(parseStart)
					fmt.Printf("Parsed %d previous chunks in %v using %d workers\n", 
						numChunks, parseDuration, numWorkers)
				}
			}
		}
	} else {
		fmt.Printf("Full backup mode - skipping previous DIDX processing\n")
	}

	fmt.Printf("Known chunks: %d!\n", knownChunks.Len())
	f := &os.File{}
	if pxarOut != "" {
		f, err = os.Create(pxarOut)
		if err != nil {
			return err
		}
		defer f.Close()
	}

	// Use parallel processing for PXAR backups
	pxarChunk := &ParallelChunkState{}
	pxarChunk.InitWithConfig(newchunk, reusechunk, knownChunks, cryptConfig, config)

	pcat1Chunk := &ParallelChunkState{}
	pcat1Chunk.InitWithConfig(newchunk, reusechunk, knownChunks, cryptConfig, config)

	pxarChunk.wrid, err = client.CreateDynamicIndex(archive.archivename)
	if err != nil {
		return err
	}
	pcat1Chunk.wrid, err = client.CreateDynamicIndex(CATALOG_ARCHIVE_NAME)
	if err != nil {
		return err
	}

	// Start parallel processing pipelines
	pxarChunk.StartParallel(client)
	pcat1Chunk.StartParallel(client)

	archive.writeCB = func(b []byte) {
		

		if pxarOut != "" {
			// TODO: error handling inside callback
			f.Write(b)
		}

		pxarChunk.HandleData(b)

		//
	}

	archive.catalogWriteCB = func(b []byte) {
		pcat1Chunk.HandleData(b)
	}

	//This is the entry point of backup job which will start streaming with the PCAT and PXAR write callback
	//Data to be hashed and eventuall uploaded

	archive.WriteDir(backupdir, "", true)

	
	pxarChunk.Eof()
	pcat1Chunk.Eof()
	// Note: Eof() now handles CloseDynamicIndex internally

	

	err = client.UploadManifest()
	if err != nil {
		return err
	}

	return client.Finish()
}


