package xmlrpc

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

type DisconnectClient struct {
	*Client
}

func NewDisconnectClient(client *Client) *DisconnectClient {
	return &DisconnectClient{
		Client: client,
	}
}

// DisconnectUsersRequest - request để disconnect users (đơn giản)
type DisconnectUsersRequest struct {
	Usernames []string `json:"usernames"`
	Message   string   `json:"message"`
}

// DisconnectUsers - disconnect multiple users từ VPN
func (c *DisconnectClient) DisconnectUsers(usernames []string, message string) error {
	xmlRequest := c.makeDisconnectUsersRequest(usernames, message)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to disconnect users: %w", err)
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
		return fmt.Errorf("disconnect users failed: %s", string(body))
	}

	return nil
}

// makeDisconnectUsersRequest - tạo XML-RPC request đơn giản
func (c *DisconnectClient) makeDisconnectUsersRequest(usernames []string, message string) string {
	var xmlBuilder strings.Builder

	xmlBuilder.WriteString(`<?xml version="1.0"?>
<methodCall>
	<methodName>DisconnectUsers</methodName>
	<params>`)

	// Param 1: Array of usernames
	xmlBuilder.WriteString(`
		<param>
			<value>
				<array>
					<data>`)

	for _, username := range usernames {
		xmlBuilder.WriteString(fmt.Sprintf(`
						<value>
							<string>%s</string>
						</value>`, c.xmlEscape(username)))
	}

	xmlBuilder.WriteString(`
					</data>
				</array>
			</value>
		</param>`)

	// Param 2: Kill existing connections (fixed to false)
	xmlBuilder.WriteString(`
		<param>
			<value>
				<boolean>0</boolean>
			</value>
		</param>`)

	// Param 3: Nil parameter
	xmlBuilder.WriteString(`
		<param>
			<value>
				<nil/>
			</value>
		</param>`)

	// Param 4: Disconnect message
	if message == "" {
		message = "Disconnected by administrator"
	}
	xmlBuilder.WriteString(fmt.Sprintf(`
		<param>
			<value>
				<string>%s</string>
			</value>
		</param>`, c.xmlEscape(message)))

	// Param 5: Force re-authentication (fixed to false)
	xmlBuilder.WriteString(`
		<param>
			<value>
				<boolean>0</boolean>
			</value>
		</param>`)

	xmlBuilder.WriteString(`
	</params>
</methodCall>`)

	return xmlBuilder.String()
}

// DisconnectSingleUser - disconnect một user
func (c *DisconnectClient) DisconnectSingleUser(username, message string) error {
	return c.DisconnectUsers([]string{username}, message)
}
