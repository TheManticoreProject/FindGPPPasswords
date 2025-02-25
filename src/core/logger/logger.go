package logger

import (
	"fmt"
	"time"
)

func Info(message string) {
	Dateprintf("INFO: %s\n", message)
}

func Warn(message string) {
	Dateprintf("WARN: %s\n", message)
}

func Debug(message string) {
	Dateprintf("DEBUG: %s\n", message)
}

func Dateprintf(format string, message ...any) {
	currentTime := time.Now().Format("2006-01-02 15h04m05s")
	format = fmt.Sprintf("[%s] %s", currentTime, format)
	fmt.Printf(format, message...)
}
