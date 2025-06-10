package ldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

type Config struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	BindDN       string `mapstructure:"bindDN"`
	BindPassword string `mapstructure:"bindPassword"`
	BaseDN       string `mapstructure:"baseDN"`
}

type Client struct {
	config *Config
}

func NewClient(config Config) *Client {
	return &Client{
		config: &config,
	}
}

func (c *Client) Connect() (*ldap.Conn, error) {
	ldapURL := fmt.Sprintf("ldap://%s:%d", c.config.Host, c.config.Port)

	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	err = conn.Bind(c.config.BindDN, c.config.BindPassword)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP server: %w", err)
	}

	return conn, nil
}

func (c *Client) CheckUserExists(username string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", username),
		[]string{"cn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return fmt.Errorf("user not found in LDAP")
	}

	return nil
}

func (c *Client) Authenticate(username, password string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", username),
		[]string{"dn"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(searchResult.Entries) != 1 {
		return fmt.Errorf("user not found or multiple users found")
	}

	userDN := searchResult.Entries[0].DN
	err = conn.Bind(userDN, password)
	if err != nil {
		if ldapErr, ok := err.(*ldap.Error); ok && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return fmt.Errorf("invalid credentials")
		}
		return fmt.Errorf("LDAP authentication failed: %w", err)
	}

	return nil
}
