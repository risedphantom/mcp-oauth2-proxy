package log

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type loggerKey struct{}

// Init initializes the logger with the specified log level and format
func Init(level string, format string) error {
	// Set default values if empty
	if level == "" {
		level = "info"
	}
	if format == "" {
		format = "json"
	}

	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logrus.SetLevel(logLevel)

	// Set log format
	switch format {
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	default:
		return fmt.Errorf("unsupported log format: %s", format)
	}

	// Set output to standard output
	logrus.SetOutput(os.Stdout)

	return nil
}

// WithLogger returns a new context with the provided logger
func WithLogger(ctx context.Context, logger *logrus.Entry) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// GetLogger retrieves the logger from the context
func GetLogger(ctx context.Context) *logrus.Entry {
	logger, ok := ctx.Value(loggerKey{}).(*logrus.Entry)
	if !ok {
		return logrus.NewEntry(logrus.StandardLogger())
	}
	return logger
}
