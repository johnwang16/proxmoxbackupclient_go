package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"
)

type IndexCreateResp struct {
	WriterID int `json:"data"`
}

type IndexPutReq struct {
	DigestList []string `json:"digest-list"`
	OffsetList []uint64 `json:"offset-list"`
	WriterID   uint64   `json:"wid"`
}

type DynamicCloseReq struct {
	ChunkCount uint64 `json:"chunk-count"`
	CheckSum   string `json:"csum"`
	Size       uint64 `json:"size"`
	WriterID   uint64 `json:"wid"`
}

type EncryptionMode int

const (
	EncryptionUnknown EncryptionMode = iota
	EncryptionEnabled
	EncryptionDisabled
)

type File struct {
	CryptMode string `json:"crypt-mode"`
	Csum      string `json:"csum"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
}

type ChunkUploadStats struct {
	CompressedSize int64 `json:"compressed_size"`
	Count          int   `json:"count"`
	Duplicates     int   `json:"duplicates"`
	Size           int64 `json:"size"`
}

type Unprotected struct {
	ChunkUploadStats ChunkUploadStats `json:"chunk_upload_stats"`
}

type BackupManifest struct {
	BackupID    string      `json:"backup-id"`
	BackupTime  int64       `json:"backup-time"`
	BackupType  string      `json:"backup-type"`
	Files       []File      `json:"files"`
	Signature   interface{} `json:"signature"`
	Unprotected Unprotected `json:"unprotected"`
}

type AuthErr struct {
}

func (e *AuthErr) Error() string {
	return "Authentication error"
}

type PBSClient struct {
	baseurl         string
	certfingerprint string
	apitoken        string
	secret          string
	authid          string

	datastore string
	namespace string
	manifest  BackupManifest

	insecure bool
	cryptConfig *CryptConfig

	client    http.Client
	tlsConfig tls.Config

	writersManifest map[uint64]int
}

// Magic bytes moved to constants.go

// sanitizeFilename ensures filename complies with PBS regex requirements for stream backups
func sanitizeFilename(name string) string {
	// For standard backups (backup.pxar.didx, catalog.pcat1.didx), return as-is
	if name == PXAR_ARCHIVE_NAME || name == CATALOG_ARCHIVE_NAME {
		return name
	}
	
	// Only sanitize user-provided stream backup names
	// Remove any path separators and ensure only valid characters
	var result []rune
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
		   (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			result = append(result, r)
		} else {
			result = append(result, '_') // Replace invalid chars with underscore
		}
	}
	sanitized := string(result)
	
	// Ensure it has a valid extension for dynamic indices
	if !strings.HasSuffix(sanitized, DIDX_EXTENSION) && !strings.HasSuffix(sanitized, FIDX_EXTENSION) {
		if strings.Contains(sanitized, ".") {
			// Replace extension with .didx
			lastDot := strings.LastIndex(sanitized, ".")
			sanitized = sanitized[:lastDot] + DIDX_EXTENSION
		} else {
			// Add .didx extension
			sanitized += DIDX_EXTENSION
		}
	}
	
	return sanitized
}

func (pbs *PBSClient) CreateDynamicIndex(name string) (uint64, error) {
	// Sanitize filename to ensure PBS compliance
	sanitizedName := sanitizeFilename(name)

	req, err := http.NewRequest("POST", pbs.baseurl+"/dynamic_index", bytes.NewBuffer([]byte(fmt.Sprintf("{\"archive-name\": \"%s\"}", sanitizedName))))
	if err != nil {
		return 0, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return 0, err
	}

	if resp2.StatusCode != http.StatusOK {
		resp1, err := io.ReadAll(resp2.Body)
		fmt.Println("Error making request:", string(resp1), string(resp2.Proto))
		return 0, err
	}

	resp1, err := io.ReadAll(resp2.Body)
	var R IndexCreateResp
	err = json.Unmarshal(resp1, &R)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return 0, err
	}
	fmt.Println("Writer id: ", R.WriterID)
	defer resp2.Body.Close()
	cryptMode := "none"
	if pbs.cryptConfig != nil {
		cryptMode = "encrypt"
	}
	f := File{
		CryptMode: cryptMode,
		Csum:      "",
		Filename:  sanitizedName,
		Size:      0,
	}
	pbs.manifest.Files = append(pbs.manifest.Files, f)
	pbs.writersManifest[uint64(R.WriterID)] = len(pbs.manifest.Files) - 1
	return uint64(R.WriterID), nil
}

func (pbs *PBSClient) UploadUncompressedChunk(writerid uint64, digest string, chunkdata []byte, originalSize int) error {
	outBuffer := make([]byte, 0)
	outBuffer = append(outBuffer, BLOB_UNCOMPRESSED_MAGIC...)
	checksum := crc32.Checksum(chunkdata, crc32.IEEETable)
	outBuffer = binary.LittleEndian.AppendUint32(outBuffer, checksum)
	outBuffer = append(outBuffer, chunkdata...)

	q := &url.Values{}
	q.Add("digest", digest)
	q.Add("encoded-size", fmt.Sprintf("%d", len(outBuffer)))
	q.Add("size", fmt.Sprintf("%d", originalSize))
	q.Add("wid", fmt.Sprintf("%d", writerid))

	req, err := http.NewRequest("POST", pbs.baseurl+"/dynamic_chunk?"+q.Encode(), bytes.NewBuffer(outBuffer))

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}

	if resp2.StatusCode != http.StatusOK {
		resp1, err := io.ReadAll(resp2.Body)
		fmt.Println("Error making request:", string(resp1), string(resp2.Proto))
		return err
	}
	return nil
}

func (pbs *PBSClient) UploadCompressedChunk(writerid uint64, digest string, chunkdata []byte, originalSize int) error {
	outBuffer := make([]byte, 0)
	outBuffer = append(outBuffer, BLOB_COMPRESSED_MAGIC...)
	compressedData := make([]byte, 0)

	//opt := zstd.WithEncoderLevel(zstd.SpeedFastest)
	w, _ := zstd.NewWriter(nil)
	compressedData = w.EncodeAll(chunkdata, compressedData)
	checksum := crc32.Checksum(compressedData, crc32.IEEETable)
	//binary.Write(outBuffer, binary.LittleEndian, checksum)
	outBuffer = binary.LittleEndian.AppendUint32(outBuffer, checksum)

	//fmt.Printf("Appended checksum %08x , len: %d\n", checksum, len(outBuffer))

	outBuffer = append(outBuffer, compressedData...)

	if len(compressedData) > len(chunkdata) {
		pbs.UploadUncompressedChunk(writerid, digest, chunkdata, originalSize)
		return nil
	}
	//fmt.Printf("Compressed: %d , Orig: %d\n", len(compressedData), len(chunkdata))

	q := &url.Values{}
	q.Add("digest", digest)
	q.Add("encoded-size", fmt.Sprintf("%d", len(outBuffer)))
	q.Add("size", fmt.Sprintf("%d", originalSize))
	q.Add("wid", fmt.Sprintf("%d", writerid))

	req, err := http.NewRequest("POST", pbs.baseurl+"/dynamic_chunk?"+q.Encode(), bytes.NewBuffer(outBuffer))

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}

	if resp2.StatusCode != http.StatusOK {
		resp1, err := io.ReadAll(resp2.Body)
		fmt.Println("Error making request:", string(resp1), string(resp2.Proto))
		return err
	}

	return nil
}

func (pbs *PBSClient) AssignChunks(writerid uint64, digests []string, offsets []uint64) error {
	indexput := &IndexPutReq{
		WriterID:   writerid,
		DigestList: digests,
		OffsetList: offsets,
	}

	jsondata, err := json.Marshal(indexput)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", pbs.baseurl+"/dynamic_index", bytes.NewBuffer(jsondata))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}
	defer resp2.Body.Close()
	return nil
}

func (pbs *PBSClient) CloseDynamicIndex(writerid uint64, checksum string, totalsize uint64, chunkcount uint64) error {
	finishreq := &DynamicCloseReq{
		WriterID:   writerid,
		CheckSum:   checksum,
		Size:       totalsize,
		ChunkCount: chunkcount,
	}
	jsonpayload, err := json.Marshal(finishreq)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", pbs.baseurl+"/dynamic_close", bytes.NewBuffer(jsonpayload))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}

	
	if resp2.StatusCode != http.StatusOK {
		_, _ = io.ReadAll(resp2.Body)
		resp2.Body.Close()
		return fmt.Errorf("close dynamic index failed with status %d", resp2.StatusCode)
	}

	f := &pbs.manifest.Files[pbs.writersManifest[writerid]]

	f.Csum = checksum
	f.Size = int64(totalsize)

	defer resp2.Body.Close()
	return nil
}

func (pbs *PBSClient) UploadBlob(name string, data []byte) error {
	out := make([]byte, 0)
	out = append(out, BLOB_UNCOMPRESSED_MAGIC...)

	checksum := crc32.ChecksumIEEE(data)
	out = binary.LittleEndian.AppendUint32(out, checksum)
	out = append(out, data...)

	q := &url.Values{}
	q.Add("encoded-size", fmt.Sprintf("%d", len(out)))
	q.Add("file-name", name)

	req, _ := http.NewRequest("POST", pbs.baseurl+"/blob?"+q.Encode(), bytes.NewBuffer(out))

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}

	if resp2.StatusCode != http.StatusOK {
		resp1, err := io.ReadAll(resp2.Body)
		fmt.Println("Error making request:", string(resp1), string(resp2.Proto))
		return err
	}

	return nil
}

func (pbs *PBSClient) UploadManifest() error {
	manifestBin, err := json.Marshal(pbs.manifest)
	if err != nil {
		return err
	}
	return pbs.UploadBlob("index.json.blob", manifestBin)
}

func (pbs *PBSClient) Finish() error {
	req, err := http.NewRequest("POST", pbs.baseurl+"/finish", nil)
	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))
	if err != nil {
		return err
	}
	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		if err != nil {
			return err
		}
	}
	defer resp2.Body.Close()
	return nil
}

func (pbs *PBSClient) UploadRawChunk(writerid uint64, digest string, chunkdata []byte, originalSize int) error {
	// For encrypted chunks, chunkdata is already a properly formatted DataBlob
	// Just upload it directly without any additional processing
	q := &url.Values{}
	q.Add("digest", digest)
	q.Add("encoded-size", fmt.Sprintf("%d", len(chunkdata)))
	q.Add("size", fmt.Sprintf("%d", originalSize))
	q.Add("wid", fmt.Sprintf("%d", writerid))

	req, err := http.NewRequest("POST", pbs.baseurl+"/dynamic_chunk?"+q.Encode(), bytes.NewBuffer(chunkdata))
	if err != nil {
		return err
	}

	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		resp1, err := io.ReadAll(resp2.Body)
		fmt.Println("Error making request:", string(resp1), string(resp2.Proto))
		return err
	}
	return nil
}

func (pbs *PBSClient) ConnectRestore() {
	// For restore operations, use a standard HTTP client without protocol upgrade
	pbs.tlsConfig = tls.Config{
		InsecureSkipVerify: pbs.insecure,
	}
	
	// Only validate certificate fingerprint if not in insecure mode AND fingerprint is provided
	if !pbs.insecure && pbs.certfingerprint != "" {
		pbs.tlsConfig.InsecureSkipVerify = true // Skip CA validation to use custom fingerprint validation
		pbs.tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Extract the peer certificate
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates presented by the peer")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}

			// Calculate the SHA-256 fingerprint of the certificate
			expectedFingerprint := strings.ToLower(strings.ReplaceAll(pbs.certfingerprint, ":", ""))
			calculatedFingerprint := sha256.Sum256(peerCert.Raw)
			calculatedFingerprintStr := strings.ToLower(hex.EncodeToString(calculatedFingerprint[:]))

			// Compare the calculated fingerprint with the expected one (case-insensitive)
			if calculatedFingerprintStr != expectedFingerprint {
				return fmt.Errorf("certificate fingerprint does not match (%s,%s)", expectedFingerprint, calculatedFingerprintStr)
			}

			// If the fingerprint matches, the certificate is considered valid
			return nil
		}
	}

	// Standard HTTP client for REST API calls
	pbs.client = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &pbs.tlsConfig,
		},
		Timeout: 60 * time.Second,
	}
}

// ConnectReader establishes a reader protocol connection for downloading data
func (pbs *PBSClient) ConnectReader(backupType, backupID string, backupTime int64) error {
	// Set the manifest information for the reader connection
	pbs.manifest.BackupType = backupType
	pbs.manifest.BackupID = backupID
	pbs.manifest.BackupTime = backupTime
	
	// Use the Connect function in reader mode
	pbs.Connect(true)
	return nil
}

// DownloadFile downloads a file using the reader protocol /download endpoint
func (pbs *PBSClient) DownloadFile(filename string) ([]byte, error) {
	q := &url.Values{}
	q.Add("file-name", filename)
	
	url := pbs.baseurl + "/download?" + q.Encode()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := pbs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error downloading file: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(respBody))
	}
	
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}


func (pbs *PBSClient) Connect(reader bool) {
	pbs.writersManifest = make(map[uint64]int)
	pbs.tlsConfig = tls.Config{
		InsecureSkipVerify: pbs.insecure,
	}
	
	// Only validate certificate fingerprint if not in insecure mode AND fingerprint is provided
	if !pbs.insecure && pbs.certfingerprint != "" {
		pbs.tlsConfig.InsecureSkipVerify = true // Skip CA validation to use custom fingerprint validation
		pbs.tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Extract the peer certificate
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates presented by the peer")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}

			// Calculate the SHA-256 fingerprint of the certificate
			expectedFingerprint := strings.ToLower(strings.ReplaceAll(pbs.certfingerprint, ":", ""))
			calculatedFingerprint := sha256.Sum256(peerCert.Raw)
			calculatedFingerprintStr := strings.ToLower(hex.EncodeToString(calculatedFingerprint[:]))

			// Compare the calculated fingerprint with the expected one (case-insensitive)
			if calculatedFingerprintStr != expectedFingerprint {
				return fmt.Errorf("certificate fingerprint does not match (%s,%s)", expectedFingerprint, calculatedFingerprintStr)
			}

			// If the fingerprint matches, the certificate is considered valid
			return nil
		}
	}

	// Only set current time and defaults for backup mode, not restore mode
	if !reader {
		pbs.manifest.BackupTime = time.Now().Unix()
		pbs.manifest.BackupType = "host"
		if pbs.manifest.BackupID == "" {
			hostname, _ := os.Hostname()
			pbs.manifest.BackupID = hostname
		}
	}
	// For reader mode, keep the values set by ConnectReader
	pbs.client = http.Client{
		Transport: &http2.Transport{

			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {

				//This is one of the trickiest parts, GO http2 library does not support starting with http1 and upgrading to 2 after
				//So to achieve that the function to create SSL socket has been hijacked here
				//Here an http 1.1 request to authenticate, start the backup and require upgrade to HTTP2 is done then the socket is passed to
				// http2.Transport handler
				conn, err := tls.Dial(network, addr, &pbs.tlsConfig)
				if err != nil {
					return nil, err
				}
				q := &url.Values{}
				
				// Different parameters for reader vs backup protocol
				if !reader {
					// Backup protocol parameters
					q.Add("backup-time", fmt.Sprintf("%d", pbs.manifest.BackupTime))
					q.Add("backup-type", pbs.manifest.BackupType)
					q.Add("store", pbs.datastore)
					if pbs.namespace != "" {
						q.Add("ns", pbs.namespace)
					}
					q.Add("backup-id", pbs.manifest.BackupID)
				} else {
					// Reader protocol parameters - might need different parameters
					q.Add("backup-time", fmt.Sprintf("%d", pbs.manifest.BackupTime))
					q.Add("backup-type", pbs.manifest.BackupType)
					q.Add("store", pbs.datastore)
					if pbs.namespace != "" {
						q.Add("ns", pbs.namespace)
					}
					q.Add("backup-id", pbs.manifest.BackupID)
				}
				
				// Use different endpoint for reader vs backup protocol
				endpoint := API_BACKUP_ENDPOINT
				if reader {
					endpoint = API_READER_ENDPOINT
				}
				
				requestLine := "GET " + endpoint + "?" + q.Encode() + " HTTP/1.1\r\n"
				conn.Write([]byte(requestLine))
				conn.Write([]byte("Authorization: " + fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret) + "\r\n"))
				if !reader {
					conn.Write([]byte("Upgrade: proxmox-backup-protocol-v1\r\n"))
				} else {
					conn.Write([]byte("Upgrade: proxmox-backup-reader-protocol-v1\r\n"))
				}
				conn.Write([]byte("Connection: Upgrade\r\n\r\n"))
				fmt.Printf("Reading response to upgrade...\n")
				buf := make([]byte, 0)
				for !strings.HasSuffix(string(buf), "\r\n\r\n") && !strings.HasSuffix(string(buf), "\n\n") {
					//fmt.Println(buf)
					b2 := make([]byte, 1)
					nbytes, err := conn.Read(b2)
					if err != nil || nbytes == 0 {
						fmt.Println("Connection unexpectedly closed")
						return nil, err
					}
					buf = append(buf, b2[:nbytes]...)

					//fmt.Println(string(b2))
				}
				lines := strings.Split(string(buf), "\n")

				if len(lines) > 0 {
					toks := strings.Split(lines[0], " ")
					if len(toks) > 1 && toks[1] != "101" {
						fmt.Println("Unexpected response code: " + strings.Join(toks[1:], " "))
						return nil, &AuthErr{}
					}
				}

				fmt.Printf("Upgraderesp: %s\n", string(buf))
				fmt.Println("Successfully upgraded to HTTP/2.")
				return conn, nil
			},
		},
	}

}

func (pbs *PBSClient) DownloadPreviousToBytes(archivename string) ([]byte, error) { //In the future also download to tmp if index is extremely big...
	q := &url.Values{}

	q.Add("archive-name", archivename)

	req, err := http.NewRequest("GET", pbs.baseurl+"/previous?"+q.Encode(), nil)
	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))
	if err != nil {
		return nil, err
	}
	resp2, err := pbs.client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return nil, err
	}
	defer resp2.Body.Close()

	ret, err := io.ReadAll(resp2.Body)

	if err != nil {
		return nil, err
	}

	return ret, nil

}

func (pbs *PBSClient) CheckPreviousEncryptionMode() EncryptionMode {
	manifestData, err := pbs.DownloadPreviousToBytes("index.json.blob")
	if err != nil {
		fmt.Printf("Could not download previous manifest (this is normal for first backup): %v\n", err)
		return EncryptionUnknown // No previous backup
	}

	var manifestJSON []byte
	var prevManifest BackupManifest
	
	// First try: parse as unencrypted manifest (skip 12-byte DataBlob header)
	if len(manifestData) >= 12 {
		manifestJSON = manifestData[12:]
		err = json.Unmarshal(manifestJSON, &prevManifest)
		if err == nil {
			return EncryptionDisabled // Previous backup was unencrypted
		}
	}
	
	// Second try: decode as encrypted DataBlob (if we have encryption configured)
	if pbs.cryptConfig != nil {
		manifestJSON, err = DecodeDataBlob(manifestData, pbs.cryptConfig)
		if err == nil {
			err = json.Unmarshal(manifestJSON, &prevManifest)
			if err == nil {
				return EncryptionEnabled // Previous backup was encrypted
			}
		}
	}
	
	return EncryptionUnknown // Could not parse manifest
}

func (pbs *PBSClient) DownloadChunk(digest string) ([]byte, error) {
	q := &url.Values{}
	q.Add("digest", digest)

	url := pbs.baseurl + "/chunk?" + q.Encode()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))

	resp, err := pbs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making chunk download request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("chunk download failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	chunkData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading chunk data: %v", err)
	}
	
	return chunkData, nil
}

type BackupSnapshot struct {
	BackupID   string `json:"backup-id"`
	BackupTime int64  `json:"backup-time"`
	BackupType string `json:"backup-type"`
	Comment    string `json:"comment"`
	Files      []File `json:"files"`
}

func (pbs *PBSClient) ListSnapshots() ([]BackupSnapshot, error) {
	q := &url.Values{}
	q.Add("backup-type", "host")
	if pbs.namespace != "" {
		q.Add("ns", pbs.namespace)
	}

	req, err := http.NewRequest("GET", pbs.baseurl+API_SNAPSHOTS_ENDPOINT+pbs.datastore+"/snapshots?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("PBSAPIToken=%s:%s", pbs.authid, pbs.secret))

	resp, err := pbs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making snapshot list request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snapshot list failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var response struct {
		Data []BackupSnapshot `json:"data"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("error parsing snapshot list: %v", err)
	}

	return response.Data, nil
}


