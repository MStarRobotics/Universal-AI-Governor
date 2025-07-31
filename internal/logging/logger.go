package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"github.com/universal-ai-governor/internal/config"
)

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	Sync() error
}

// zapLogger implements the Logger interface using zap
type zapLogger struct {
	logger *zap.Logger
}

// NewLogger creates a new logger instance based on configuration
func NewLogger(config config.LoggingConfig) (Logger, error) {
	// Determine log level
	level, err := zapcore.ParseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create encoder based on format
	var encoder zapcore.Encoder
	if config.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create cores for different outputs
	var cores []zapcore.Core

	// Add stdout/stderr output
	for _, output := range config.Output {
		var writer zapcore.WriteSyncer
		switch output {
		case "stdout":
			writer = zapcore.AddSync(os.Stdout)
		case "stderr":
			writer = zapcore.AddSync(os.Stderr)
		case "file":
			// Create log directory if it doesn't exist
			logDir := filepath.Dir(config.File.Path)
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create log directory: %w", err)
			}

			// Configure log rotation
			writer = zapcore.AddSync(&lumberjack.Logger{
				Filename:   config.File.Path,
				MaxSize:    config.File.MaxSize,
				MaxBackups: config.File.MaxBackups,
				MaxAge:     config.File.MaxAge,
				Compress:   config.File.Compress,
			})
		default:
			return nil, fmt.Errorf("unsupported output: %s", output)
		}

		cores = append(cores, zapcore.NewCore(encoder, writer, level))
	}

	// Combine all cores
	core := zapcore.NewTee(cores...)

	// Create logger with caller information
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &zapLogger{logger: logger}, nil
}

// Debug logs a debug message with optional fields
func (l *zapLogger) Debug(msg string, fields ...interface{}) {
	l.logger.Debug(msg, l.convertFields(fields...)...)
}

// Info logs an info message with optional fields
func (l *zapLogger) Info(msg string, fields ...interface{}) {
	l.logger.Info(msg, l.convertFields(fields...)...)
}

// Warn logs a warning message with optional fields
func (l *zapLogger) Warn(msg string, fields ...interface{}) {
	l.logger.Warn(msg, l.convertFields(fields...)...)
}

// Error logs an error message with optional fields
func (l *zapLogger) Error(msg string, fields ...interface{}) {
	l.logger.Error(msg, l.convertFields(fields...)...)
}

// Fatal logs a fatal message with optional fields and exits
func (l *zapLogger) Fatal(msg string, fields ...interface{}) {
	l.logger.Fatal(msg, l.convertFields(fields...)...)
}

// Sync flushes any buffered log entries
func (l *zapLogger) Sync() error {
	return l.logger.Sync()
}

// convertFields converts key-value pairs to zap fields
func (l *zapLogger) convertFields(fields ...interface{}) []zap.Field {
	if len(fields)%2 != 0 {
		// If odd number of fields, add the last one as a generic field
		fields = append(fields, "MISSING_VALUE")
	}

	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			key = fmt.Sprintf("field_%d", i/2)
		}
		value := fields[i+1]

		// Convert value to appropriate zap field type
		switch v := value.(type) {
		case string:
			zapFields = append(zapFields, zap.String(key, v))
		case int:
			zapFields = append(zapFields, zap.Int(key, v))
		case int64:
			zapFields = append(zapFields, zap.Int64(key, v))
		case float64:
			zapFields = append(zapFields, zap.Float64(key, v))
		case bool:
			zapFields = append(zapFields, zap.Bool(key, v))
		case time.Duration:
			zapFields = append(zapFields, zap.Duration(key, v))
		case time.Time:
			zapFields = append(zapFields, zap.Time(key, v))
		case error:
			zapFields = append(zapFields, zap.Error(v))
		default:
			zapFields = append(zapFields, zap.Any(key, v))
		}
	}

	return zapFields
}

// NoOpLogger is a logger that does nothing (for testing)
type NoOpLogger struct{}

func (l *NoOpLogger) Debug(msg string, fields ...interface{}) {}
func (l *NoOpLogger) Info(msg string, fields ...interface{})  {}
func (l *NoOpLogger) Warn(msg string, fields ...interface{})  {}
func (l *NoOpLogger) Error(msg string, fields ...interface{}) {}
func (l *NoOpLogger) Fatal(msg string, fields ...interface{}) {}
func (l *NoOpLogger) Sync() error                             { return nil }

// NewNoOpLogger creates a no-op logger for testing
func NewNoOpLogger() Logger {
	return &NoOpLogger{}
}
