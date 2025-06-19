package xmlrpc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"govpn/internal/domain/entities"
	"io"
	"net/http"
	"strings"
	"time"
)

type UserClient struct {
	*Client
}

func NewUserClient(client *Client) *UserClient {
	return &UserClient{Client: client}
}

func (c *UserClient) CreateUser(user *entities.User) error {
	xmlRequest := c.makeCreateUserRequest(user)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
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
		return fmt.Errorf("create user failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) GetUser(username string) (*entities.User, error) {
	xmlRequest := c.makeGetUserRequest(username)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseUserResponse(username, body)
}
func (c *UserClient) ExistsByEmail(email string) (bool, error) {
	xmlRequest := c.makeGetAllUsersRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return false, fmt.Errorf("failed to get all: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}
	if !c.isSuccessResponse(string(body)) {
		return false, fmt.Errorf("get email failed: %s", string(body))
	}
	if strings.Contains(string(body), email) {
		return true, nil
	}
	return false, nil
}

func (c *UserClient) GetAllUsers() ([]*entities.User, error) {
	xmlRequest := c.makeGetAllUsersRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseAllUsersResponse(body)
}

func (c *UserClient) UpdateUser(user *entities.User) error {
	xmlRequest := c.makeUpdateUserRequest(user)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
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
		return fmt.Errorf("update user failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) DeleteUser(username string) error {
	xmlRequest := c.makeDeleteUserRequest(username)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
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
		return fmt.Errorf("delete user failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) UserPropDel(user *entities.User) error {
	xmlRequest := c.makeUserPropDelRequest(user)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to UserPropDel: %w", err)
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
		return fmt.Errorf("UserPropDel failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) SetUserPassword(username, password string) error {
	xmlRequest := c.makeSetPasswordRequest(username, password)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to set password: %w", err)
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
		return fmt.Errorf("set password failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) EnableUser(username string) error {
	return c.setUserDenyAccess(username, false)
}

func (c *UserClient) DisableUser(username string) error {
	return c.setUserDenyAccess(username, true)
}

func (c *UserClient) RegenerateTOTP(username string) error {
	xmlRequest := c.makeTOTPRequest(username)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to regenerate TOTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if !strings.Contains(string(body), username) {
		return fmt.Errorf("regenerate TOTP failed: %s", string(body))
	}

	return nil
}

func (c *UserClient) GetExpiringUsers(days int) ([]string, error) {
	xmlRequest := c.makeGetAllUsersRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return c.parseExpiringUsers(resp.Body, days)
}

func (c *UserClient) setUserDenyAccess(username string, deny bool) error {
	denyValue := "false"
	if deny {
		denyValue = "true"
	}

	xmlRequest := c.makeUserPropertyRequest(username, "prop_deny", denyValue)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to set user access: %w", err)
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
		return fmt.Errorf("set user access failed: %s", string(body))
	}

	return nil
}

// Request builders
func (c *UserClient) makeCreateUserRequest(user *entities.User) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropPut</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(user.Username) + `</string></value></param>`)
	buf.WriteString(`<param><value><struct>`)

	if user.Email != "" {
		buf.WriteString(`<member><name>email</name><value><string>` + c.xmlEscape(user.Email) + `</string></value></member>`)
	}
	if user.AuthMethod != "" {
		buf.WriteString(`<member><name>user_auth_type</name><value><string>` + c.xmlEscape(user.AuthMethod) + `</string></value></member>`)
	}
	if user.GroupName != "" {
		buf.WriteString(`<member><name>conn_group</name><value><string>` + c.xmlEscape(user.GroupName) + `</string></value></member>`)
	}
	if user.UserExpiration != "" {
		buf.WriteString(`<member><name>user_expiration</name><value><string>` + c.xmlEscape(user.UserExpiration) + `</string></value></member>`)
	}
	if user.IPAddress != "" {
		buf.WriteString(`<member><name>conn_ip</name><value><string>` + c.xmlEscape(user.IPAddress) + `</string></value></member>`)
	}

	// MAC addresses
	for i, mac := range user.MacAddresses {
		if i >= 5 {
			break
		}
		macField := fmt.Sprintf("pvt_hw_addr%s", map[int]string{0: "", 1: "2", 2: "3", 3: "4", 4: "5"}[i])
		buf.WriteString(`<member><name>` + macField + `</name><value><string>` + c.xmlEscape(mac) + `</string></value></member>`)
	}
	for i, accessControl := range user.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		accessValue := "+NAT:" + accessControl
		buf.WriteString(`<member><name>` + c.xmlEscape(accessName) + `</name><value><string>` + c.xmlEscape(accessValue) + `</string></value></member>`)
	}
	buf.WriteString(`<member><name>type</name><value><string>user_connect</string></value></member>`)
	buf.WriteString(`<member><name>prop_google_auth</name><value><string>true</string></value></member>`)
	buf.WriteString(`</struct></value></param>`)
	buf.WriteString(`<param><value><boolean>0</boolean></value></param>`)
	buf.WriteString(`</params></methodCall>`)
	return buf.String()
}

func (c *UserClient) makeGetUserRequest(username string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>UserPropMultiGet</methodName>
<params>
	<param>
		<value>
			<array>
				<data>
					<value>
						<string>%s</string>
					</value>
				</data>
			</array>
		</value>
	</param>
	<param>
		<value>
			<nil/>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(username))
}

func (c *UserClient) makeUpdateUserRequest(user *entities.User) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropPut</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(user.Username) + `</string></value></param>`)
	buf.WriteString(`<param><value><struct>`)

	if user.UserExpiration != "" {
		buf.WriteString(`<member><name>user_expiration</name><value><string>` + c.xmlEscape(user.UserExpiration) + `</string></value></member>`)
	}
	if user.DenyAccess != "" {
		buf.WriteString(`<member><name>prop_deny</name><value><string>` + c.xmlEscape(user.DenyAccess) + `</string></value></member>`)
	}
	if user.GroupName != "" {
		buf.WriteString(`<member><name>conn_group</name><value><string>` + c.xmlEscape(user.GroupName) + `</string></value></member>`)
	}
	if user.IPAddress != "" {
		buf.WriteString(`<member><name>conn_ip</name><value><string>` + c.xmlEscape(user.IPAddress) + `</string></value></member>`)
	}
	// MAC addresses
	for i, mac := range user.MacAddresses {
		if i >= 5 {
			break
		}
		macField := fmt.Sprintf("pvt_hw_addr%s", map[int]string{0: "", 1: "2", 2: "3", 3: "4", 4: "5"}[i])
		buf.WriteString(`<member><name>` + macField + `</name><value><string>` + c.xmlEscape(mac) + `</string></value></member>`)
	}
	for i, accessControl := range user.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		accessValue := "+NAT:" + accessControl
		buf.WriteString(`<member><name>` + c.xmlEscape(accessName) + `</name><value><string>` + c.xmlEscape(accessValue) + `</string></value></member>`)
	}
	buf.WriteString(`</struct></value></param>`)
	buf.WriteString(`<param><value><boolean>0</boolean></value></param>`)
	buf.WriteString(`</params></methodCall>`)

	return buf.String()
}

func (c *UserClient) makeDeleteUserRequest(username string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>UserPropDelete</methodName>
<params>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(username))
}

func (c *UserClient) makeUserPropDelRequest(user *entities.User) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropDel</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(user.Username) + `</string></value></param>`)
	buf.WriteString(`<param><value><array><data>`)
	// MAC addresses
	for i, _ := range user.MacAddresses {
		if i >= 5 {
			break
		}
		macField := fmt.Sprintf("pvt_hw_addr%s", map[int]string{0: "", 1: "2", 2: "3", 3: "4", 4: "5"}[i])
		buf.WriteString(`<value><string>` + c.xmlEscape(macField) + `</string></value>`)
	}
	for i, _ := range user.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		buf.WriteString(`<value><string>` + c.xmlEscape(accessName) + `</string></value>`)
	}
	if user.IPAddress != "" {
		buf.WriteString(`<value><string>conn_ip</string></value>`)
	}
	buf.WriteString(`</data></array></value></param>`)
	buf.WriteString(`</params></methodCall>`)

	return buf.String()
}

func (c *UserClient) makeSetPasswordRequest(username, password string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>SetLocalPassword</methodName>
<params>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
	<param>
		<value>
			<nil/>
		</value>
	</param>
	<param>
		<value>
			<boolean>1</boolean>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(username), c.xmlEscape(password))
}

func (c *UserClient) makeUserPropertyRequest(username, property, value string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>UserPropPut</methodName>
<params>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
	<param>
		<value>
			<struct>
				<member>
					<name>%s</name>
					<value>
						<string>%s</string>
					</value>
				</member>
			</struct>
		</value>
	</param>
	<param>
		<value>
			<boolean>0</boolean>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(username), property, c.xmlEscape(value))
}

func (c *UserClient) makeTOTPRequest(username string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>GoogleAuthenticatorRegenerate</methodName>
<params>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
	<param>
		<value>
			<int>0</int>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(username))
}

func (c *UserClient) makeGetAllUsersRequest() string {
	return `<?xml version="1.0"?><methodCall>
<methodName>UserPropMultiGet</methodName>
<params>
	<param>
		<value>
			<nil/>
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

// Response parsers
func (c *UserClient) parseUserResponse(username string, body []byte) (*entities.User, error) {
	// Check if response contains error
	if strings.Contains(string(body), "<fault>") || strings.Contains(string(body), "User not found") {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	var userData struct {
		Members []struct {
			Name  string `xml:"name"`
			Value string `xml:"value>string"`
		} `xml:"params>param>value>struct>member>value>struct>member"`
	}

	err := xml.NewDecoder(bytes.NewReader(body)).Decode(&userData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	// If no members found, user doesn't exist
	if len(userData.Members) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	user := &entities.User{
		Username:   username,
		DenyAccess: "false",
		Role:       entities.UserRoleUser,
	}

	for _, member := range userData.Members {
		switch {
		case member.Name == "type":
			if member.Value != "user_compile" && member.Value != "user_connect" {
				return nil, fmt.Errorf("not a user entity")
			}
		case strings.HasPrefix(member.Name, "pvt_hw_addr"):
			if member.Value != "" {
				user.MacAddresses = append(user.MacAddresses, member.Value)
			}
		case member.Name == "user_auth_type":
			user.AuthMethod = member.Value
		case member.Name == "conn_group":
			user.GroupName = member.Value
		case member.Name == "prop_google_auth":
			user.MFA = member.Value
		case member.Name == "prop_deny":
			user.DenyAccess = member.Value
		case member.Name == "email":
			user.Email = member.Value
		case member.Name == "user_expiration":
			user.UserExpiration = member.Value
		case member.Name == "conn_ip":
			user.IPAddress = member.Value
		case member.Name == "prop_superuser":
			if member.Value == "true" {
				user.Role = entities.UserRoleAdmin
			}
		case strings.HasPrefix(member.Name, "access_to"):
			user.AccessControl = append(user.AccessControl, strings.TrimPrefix(member.Value, "+NAT:"))
		}
	}
	return user, nil
}

func (c *UserClient) parseAllUsersResponse(body []byte) ([]*entities.User, error) {
	var xmlUserData struct {
		Members []struct {
			UserName string `xml:"name"`
			Members  []struct {
				Name  string `xml:"name"`
				Value string `xml:"value>string"`
			} `xml:"value>struct>member"`
		} `xml:"params>param>value>struct>member"`
	}

	err := xml.NewDecoder(bytes.NewReader(body)).Decode(&xmlUserData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	users := make([]*entities.User, 0)
	for _, userMember := range xmlUserData.Members {
		username := userMember.UserName
		if username == "" {
			continue
		}

		user := &entities.User{
			Username:   username,
			DenyAccess: "false",
			Role:       entities.UserRoleUser,
		}

		// Check if this is actually a user (not a group)
		isUser := false
		for _, data := range userMember.Members {
			if data.Name == "type" && (data.Value == "user_connect" || data.Value == "user_compile") {
				isUser = true
				break
			}
		}

		if !isUser {
			continue
		}

		// Parse user data
		for _, data := range userMember.Members {
			switch {
			case strings.HasPrefix(data.Name, "pvt_hw_addr"):
				if data.Value != "" {
					user.MacAddresses = append(user.MacAddresses, data.Value)
				}
			case data.Name == "user_auth_type":
				user.AuthMethod = data.Value
			case data.Name == "conn_group":
				user.GroupName = data.Value
			case data.Name == "prop_google_auth":
				user.MFA = data.Value
			case data.Name == "prop_deny":
				user.DenyAccess = data.Value
			case data.Name == "email":
				user.Email = data.Value
			case data.Name == "user_expiration":
				user.UserExpiration = data.Value
			case data.Name == "conn_ip":
				user.IPAddress = data.Value
			case data.Name == "prop_superuser":
				if data.Value == "true" {
					user.Role = entities.UserRoleAdmin
				}
			case strings.HasPrefix(data.Name, "access_to"):
				user.AccessControl = append(user.AccessControl, strings.TrimPrefix(data.Value, "+NAT:"))
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func (c *UserClient) parseExpiringUsers(body io.Reader, days int) ([]string, error) {
	var xmlUserData struct {
		Members []struct {
			UserName string `xml:"name"`
			Members  []struct {
				Name  string `xml:"name"`
				Value string `xml:"value>string"`
			} `xml:"value>struct>member"`
		} `xml:"params>param>value>struct>member"`
	}

	expirationDate := time.Now().AddDate(0, 0, days).Format("02/01/2006")

	err := xml.NewDecoder(body).Decode(&xmlUserData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	var userEmails []string
	for _, user := range xmlUserData.Members {
		var userExpirationTime time.Time
		var userEmail string

		for _, data := range user.Members {
			switch data.Name {
			case "email":
				userEmail = data.Value
			case "user_expiration":
				userExpirationTime, err = time.Parse("02/01/2006", data.Value)
				if err != nil {
					continue
				}
			}
		}

		if userExpirationTime.Format("02/01/2006") == expirationDate && userEmail != "" {
			userEmails = append(userEmails, userEmail)
		}
	}

	return userEmails, nil
}
