package xmlrpc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Host     string `mapstructure:"host"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Port     int    `mapstructure:"port"`
}

type Client struct {
	url        string
	username   string
	password   string
	httpClient *http.Client
}

func NewClient(config Config) *Client {
	url := fmt.Sprintf("https://%s:%d/RPC2/", config.Host, config.Port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &Client{
		url:        url,
		username:   config.Username,
		password:   config.Password,
		httpClient: httpClient,
	}
}

func (c *Client) Call(xmlRequest string) (*http.Response, error) {
	req, err := http.NewRequest("POST", c.url, strings.NewReader(xmlRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "text/xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

func (c *Client) RunStart() error {
	xmlRequest := c.makeRunStartRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if !c.isSuccessResponse(string(body)) {
		return fmt.Errorf("run start failed: %s", string(body))
	}

	return nil
}

func (c *Client) makeRunStartRequest() string {
	return `<?xml version="1.0"?>
<methodCall>
	<methodName>RunStart</methodName>
	<params>
		<param>
			<value>
				<string>warm</string>
			</value>
		</param>
		<param>
			<value>
				<nil/>
			</value>
		</param>
	</params>
</methodCall>`
}

func (c *Client) isSuccessResponse(body string) bool {
	return strings.Contains(body, "<nil/>") ||
		strings.Contains(body, "Password changed successfully") ||
		strings.Contains(body, "last_restarted")
}

func (c *Client) xmlEscape(s string) string {
	var b bytes.Buffer
	for _, ch := range s {
		switch ch {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}
