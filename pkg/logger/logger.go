package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

type LoggerConfig struct {
	Level    string `mapstructure:"level"`
	Format   string `mapstructure:"format"`
	FilePath string `mapstructure:"filePath"`
}

func Init(cfg LoggerConfig) {
	Log = logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	Log.SetLevel(level)

	// Set log format
	if cfg.Format == "json" {
		Log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Set output
	if cfg.FilePath != "" {
		file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			Log.SetOutput(file)
		} else {
			Log.SetOutput(os.Stdout)
			Log.Warn("Failed to open log file, using stdout")
		}
	} else {
		Log.SetOutput(os.Stdout)
	}
}

func Info(args ...interface{}) {
	if Log != nil {
		Log.Info(args...)
	}
}

func Error(args ...interface{}) {
	if Log != nil {
		Log.Error(args...)
	}
}

func Debug(args ...interface{}) {
	if Log != nil {
		Log.Debug(args...)
	}
}

func Warn(args ...interface{}) {
	if Log != nil {
		Log.Warn(args...)
	}
}

func Fatal(args ...interface{}) {
	if Log != nil {
		Log.Fatal(args...)
	}
}
