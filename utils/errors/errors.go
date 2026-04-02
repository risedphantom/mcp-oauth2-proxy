package errors

import (
	log "github.com/sirupsen/logrus"
)

// LogOnError logs an error if it exists
func LogOnError(err error) {
	if err != nil {
		log.Error(err)
	}
}

// DieOnError logs a fatal error and exits if error exists
func DieOnError(msg string, err error) {
	if err != nil {
		log.Fatal(msg, err)
	}
}
