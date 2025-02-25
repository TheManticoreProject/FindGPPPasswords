package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

type JSONString string

// https://stackoverflow.com/a/53098314

func (c JSONString) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if len(string(c)) == 0 {
		buf.WriteString(`null`)
	} else {
		buf.WriteString(`"` + string(c) + `"`) // add double quation mark as json format required
	}
	return buf.Bytes(), nil
}

func (c *JSONString) UnmarshalJSON(in []byte) error {
	str := string(in)
	if str == `null` {
		*c = ""
		return nil
	}
	res := JSONString(str)
	if len(res) >= 2 {
		res = res[1 : len(res)-1] // remove the wrapped qutation
	}
	*c = res
	return nil
}

// Files IO

func WriteJSONToFile(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	return encoder.Encode(data)
}

func PadStringRight(input string, padChar string, length int) string {
	input += " "
	if len(input) < length {
		for range length - len(input) {
			input += padChar
		}
	}

	return input
}

func FormatSize(size uint64) string {
	KiB := uint64(1024)
	MiB := KiB * 1024
	GiB := MiB * 1024

	switch {
	case size >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	case size >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	case size >= KiB:
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
