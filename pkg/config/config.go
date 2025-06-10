package config

import (
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	OpenVPN OpenVPNConfig `mapstructure:"openvpn"`
	LDAP    LDAPConfig    `mapstructure:"ldap"`
	Logger  LoggerConfig  `mapstructure:"logger"`
	JWT     JWTConfig     `mapstructure:"jwt"`
}

type ServerConfig struct {
	Port    string `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
	Timeout int    `mapstructure:"timeout"`
}

type OpenVPNConfig struct {
	Host     string `mapstructure:"host"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Port     int    `mapstructure:"port"`
}

type LDAPConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	BindDN       string `mapstructure:"bindDN"`
	BindPassword string `mapstructure:"bindPassword"`
	BaseDN       string `mapstructure:"baseDN"`
}

type LoggerConfig struct {
	Level    string `mapstructure:"level"`
	Format   string `mapstructure:"format"`
	FilePath string `mapstructure:"filePath"`
}

type JWTConfig struct {
	// Legacy HMAC configuration (deprecated)
	Secret        string `mapstructure:"secret"`
	RefreshSecret string `mapstructure:"refreshSecret"`

	// RSA configuration (recommended)
	UseRSA                     bool          `mapstructure:"useRSA"`
	AccessPrivateKey           string        `mapstructure:"accessPrivateKey"`
	RefreshPrivateKey          string        `mapstructure:"refreshPrivateKey"`
	AccessTokenExpireDuration  time.Duration `mapstructure:"accessTokenExpireDuration"`
	RefreshTokenExpireDuration time.Duration `mapstructure:"refreshTokenExpireDuration"`
}

func Load() (*Config, error) {
	var cfg Config

	// Set config file path based on environment
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	viper.SetConfigName("config-" + env)
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Set defaults
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Override port if PORT env variable is set
	if port := os.Getenv("PORT"); port != "" {
		cfg.Server.Port = port
	}

	return &cfg, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.mode", "debug")
	viper.SetDefault("server.timeout", 30)

	// OpenVPN defaults
	viper.SetDefault("openvpn.port", 943)

	// LDAP defaults
	viper.SetDefault("ldap.port", 389)

	// Logger defaults
	viper.SetDefault("logger.level", "info")
	viper.SetDefault("logger.format", "json")

	// JWT defaults
	viper.SetDefault("jwt.useRSA", true)
	viper.SetDefault("jwt.accessTokenExpireDuration", time.Hour)
	viper.SetDefault("jwt.refreshTokenExpireDuration", 24*time.Hour)

	// Legacy HMAC defaults (for backward compatibility)
	viper.SetDefault("jwt.secret", "default-hmac-secret-change-in-production")
	viper.SetDefault("jwt.refreshSecret", "default-refresh-secret-change-in-production")
}
