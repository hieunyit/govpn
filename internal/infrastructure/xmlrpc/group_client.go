package xmlrpc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"govpn/internal/domain/entities"
	"io"
	"net/http"
	"strings"
)

type GroupClient struct {
	*Client
}

func NewGroupClient(client *Client) *GroupClient {
	return &GroupClient{Client: client}
}

func (c *GroupClient) CreateGroup(group *entities.Group) error {
	xmlRequest := c.makeCreateGroupRequest(group)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
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
		return fmt.Errorf("create group failed: %s", string(body))
	}

	return nil
}

func (c *GroupClient) GetGroup(groupName string) (*entities.Group, error) {
	xmlRequest := c.makeGetGroupRequest(groupName)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseGroupResponse(groupName, body)
}

func (c *GroupClient) GetAllGroups() ([]*entities.Group, error) {
	xmlRequest := c.makeGetAllGroupsRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get all groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseAllGroupsResponse(body)
}

func (c *GroupClient) UpdateGroup(group *entities.Group) error {
	xmlRequest := c.makeUpdateGroupRequest(group)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
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
		return fmt.Errorf("update group failed: %s", string(body))
	}

	return nil
}

func (c *GroupClient) EnableGroup(groupName string) error {
	return c.setGroupDenyAccess(groupName, false)
}

func (c *GroupClient) DisableGroup(groupName string) error {
	return c.setGroupDenyAccess(groupName, true)
}

func (c *GroupClient) DeleteGroup(groupName string) error {
	xmlRequest := c.makeDeleteGroupRequest(groupName)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
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
		return fmt.Errorf("delete group failed: %s", string(body))
	}

	return nil
}

// Response parsers
func (c *GroupClient) parseGroupResponse(groupName string, body []byte) (*entities.Group, error) {
	// Check if response contains error
	if strings.Contains(string(body), "<fault>") || strings.Contains(string(body), "not found") {
		return nil, fmt.Errorf("group not found: %s", groupName)
	}

	var groupData struct {
		Members []struct {
			Name  string `xml:"name"`
			Value string `xml:"value>string"`
		} `xml:"params>param>value>struct>member>value>struct>member"`
	}

	err := xml.NewDecoder(bytes.NewReader(body)).Decode(&groupData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	// If no members found, group doesn't exist
	if len(groupData.Members) == 0 {
		return nil, fmt.Errorf("group not found: %s", groupName)
	}

	group := &entities.Group{
		GroupName:   groupName,
		DenyAccess:  "false",
		Role:        entities.UserRoleUser,
		MFA:         "true",
		GroupSubnet: []string{},
		GroupRange:  []string{},
	}

	for _, member := range groupData.Members {
		switch {
		case member.Name == "type":
			if member.Value != "group" {
				return nil, fmt.Errorf("not a group entity")
			}
		case strings.HasPrefix(member.Name, "access_to"):
			group.AccessControl = append(group.AccessControl, strings.TrimPrefix(member.Value, "+SUBNET:"))
		case member.Name == "user_auth_type":
			group.AuthMethod = member.Value
		case member.Name == "prop_google_auth":
			group.MFA = member.Value
		case member.Name == "prop_deny":
			group.DenyAccess = member.Value
		case member.Name == "prop_superuser":
			if member.Value == "true" {
				group.Role = entities.UserRoleAdmin
			}
		case strings.HasPrefix(member.Name, "group_subnets"):
			group.GroupSubnet = append(group.GroupSubnet, member.Value)
		case strings.HasPrefix(member.Name, "group_range"):
			group.GroupRange = append(group.GroupRange, member.Value)
		}
	}

	return group, nil
}

func (c *GroupClient) setGroupDenyAccess(groupName string, deny bool) error {
	denyValue := "false"
	if deny {
		denyValue = "true"
	}

	xmlRequest := c.makeGroupPropertyRequest(groupName, "prop_deny", denyValue)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to set group access: %w", err)
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
		return fmt.Errorf("set group access failed: %s", string(body))
	}

	return nil
}
func (c *GroupClient) ClearAccessControl(group *entities.Group) error {
	xmlRequest := c.makeClearAccessControlRequest(group)

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return fmt.Errorf("failed to clear access control: %w", err)
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
		return fmt.Errorf("clear access control failed: %s", string(body))
	}

	return nil
}
func (c *GroupClient) parseAllGroupsResponse(body []byte) ([]*entities.Group, error) {
	var xmlGroupData struct {
		Members []struct {
			GroupName string `xml:"name"`
			Members   []struct {
				Name  string `xml:"name"`
				Value string `xml:"value>string"`
			} `xml:"value>struct>member"`
		} `xml:"params>param>value>struct>member"`
	}

	err := xml.NewDecoder(bytes.NewReader(body)).Decode(&xmlGroupData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML: %w", err)
	}

	groups := make([]*entities.Group, 0)
	for _, groupMember := range xmlGroupData.Members {
		groupName := groupMember.GroupName
		if groupName == "" {
			continue
		}

		group := &entities.Group{
			GroupName:   groupName,
			DenyAccess:  "false",
			Role:        entities.UserRoleUser,
			MFA:         "true",
			GroupSubnet: []string{},
			GroupRange:  []string{},
		}

		// Check if this is actually a group (not a user)
		isGroup := false
		for _, data := range groupMember.Members {
			if data.Name == "type" && data.Value == "group" {
				isGroup = true
				break
			}
		}

		if !isGroup {
			continue
		}

		// Parse group data
		for _, data := range groupMember.Members {
			switch {
			case strings.HasPrefix(data.Name, "access_to"):
				group.AccessControl = append(group.AccessControl, strings.TrimPrefix(data.Value, "+SUBNET:"))
			case data.Name == "user_auth_type":
				group.AuthMethod = data.Value
			case data.Name == "prop_google_auth":
				group.MFA = data.Value
			case data.Name == "prop_deny":
				group.DenyAccess = data.Value
			case data.Name == "prop_superuser":
				if data.Value == "true" {
					group.Role = entities.UserRoleAdmin
				}
			case strings.HasPrefix(data.Name, "group_subnets"):
				group.GroupSubnet = append(group.GroupSubnet, data.Value)
			case strings.HasPrefix(data.Name, "group_range"):
				group.GroupRange = append(group.GroupRange, data.Value)
			}
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// Request builders
func (c *GroupClient) makeCreateGroupRequest(group *entities.Group) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropPut</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(group.GroupName) + `</string></value></param>`)
	buf.WriteString(`<param><value><struct>`)

	if group.AuthMethod != "" {
		buf.WriteString(`<member><name>user_auth_type</name><value><string>` + c.xmlEscape(group.AuthMethod) + `</string></value></member>`)
	}

	// Access control
	for i, accessControl := range group.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		accessValue := "+SUBNET:" + accessControl
		buf.WriteString(`<member><name>` + c.xmlEscape(accessName) + `</name><value><string>` + c.xmlEscape(accessValue) + `</string></value></member>`)
	}

	// Group subnet
	for i, subnet := range group.GroupSubnet {
		subnetName := fmt.Sprintf("group_subnets.%d", i)
		buf.WriteString(`<member><name>` + c.xmlEscape(subnetName) + `</name><value><string>` + c.xmlEscape(subnet) + `</string></value></member>`)
	}

	// Group range
	for i, ipRange := range group.GroupRange {
		rangeName := fmt.Sprintf("group_range.%d", i)
		buf.WriteString(`<member><name>` + c.xmlEscape(rangeName) + `</name><value><string>` + c.xmlEscape(ipRange) + `</string></value></member>`)
	}

	buf.WriteString(`<member><name>type</name><value><string>group</string></value></member>`)
	buf.WriteString(`<member><name>group_declare</name><value><string>true</string></value></member>`)

	// MFA setting
	mfaValue := group.MFA
	if mfaValue == "" {
		mfaValue = "true" // Default to true
	}
	buf.WriteString(`<member><name>prop_google_auth</name><value><string>` + c.xmlEscape(mfaValue) + `</string></value></member>`)

	// Role setting
	if group.Role == entities.UserRoleAdmin {
		buf.WriteString(`<member><name>prop_superuser</name><value><string>true</string></value></member>`)
	} else {
		buf.WriteString(`<member><name>prop_superuser</name><value><string>false</string></value></member>`)
	}

	buf.WriteString(`</struct></value></param>`)
	buf.WriteString(`<param><value><boolean>0</boolean></value></param>`)
	buf.WriteString(`</params></methodCall>`)

	return buf.String()
}

func (c *GroupClient) makeUpdateGroupRequest(group *entities.Group) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropPut</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(group.GroupName) + `</string></value></param>`)
	buf.WriteString(`<param><value><struct>`)

	// Access control
	for i, accessControl := range group.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		accessValue := "+SUBNET:" + accessControl
		buf.WriteString(`<member><name>` + c.xmlEscape(accessName) + `</name><value><string>` + c.xmlEscape(accessValue) + `</string></value></member>`)
	}

	// Group subnet
	for i, subnet := range group.GroupSubnet {
		subnetName := fmt.Sprintf("group_subnets.%d", i)
		buf.WriteString(`<member><name>` + c.xmlEscape(subnetName) + `</name><value><string>` + c.xmlEscape(subnet) + `</string></value></member>`)
	}

	// Group range
	for i, ipRange := range group.GroupRange {
		rangeName := fmt.Sprintf("group_range.%d", i)
		buf.WriteString(`<member><name>` + c.xmlEscape(rangeName) + `</name><value><string>` + c.xmlEscape(ipRange) + `</string></value></member>`)
	}

	// MFA setting
	if group.MFA != "" {
		buf.WriteString(`<member><name>prop_google_auth</name><value><string>` + c.xmlEscape(group.MFA) + `</string></value></member>`)
	}

	// Role setting
	if group.Role == entities.UserRoleAdmin {
		buf.WriteString(`<member><name>prop_superuser</name><value><string>true</string></value></member>`)
	} else {
		buf.WriteString(`<member><name>prop_superuser</name><value><string>false</string></value></member>`)
	}

	// Deny access
	if group.DenyAccess != "" {
		buf.WriteString(`<member><name>prop_deny</name><value><string>` + c.xmlEscape(group.DenyAccess) + `</string></value></member>`)
	}

	buf.WriteString(`</struct></value></param>`)
	buf.WriteString(`<param><value><boolean>0</boolean></value></param>`)
	buf.WriteString(`</params></methodCall>`)
	return buf.String()
}

func (c *GroupClient) makeGetGroupRequest(groupName string) string {
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
</methodCall>`, c.xmlEscape(groupName))
}

func (c *GroupClient) makeGetAllGroupsRequest() string {
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

func (c *GroupClient) makeDeleteGroupRequest(groupName string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><methodCall>
<methodName>UserPropDel</methodName>
<params>
	<param>
		<value>
			<string>%s</string>
		</value>
	</param>
	<param>
		<value>
			<array>
				<data>
					<value>
						<string>type</string>
					</value>
				</data>
			</array>
		</value>
	</param>
</params>
</methodCall>`, c.xmlEscape(groupName))
}

func (c *GroupClient) GroupPropDel(group *entities.Group) error {
	xmlRequest := c.makeGroupPropDelRequest(group)

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

func (c *GroupClient) makeGroupPropDelRequest(group *entities.Group) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropDel</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(group.GroupName) + `</string></value></param>`)
	buf.WriteString(`<param><value><array><data>`)

	// Delete access control properties
	for i := range group.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		buf.WriteString(`<value><string>` + c.xmlEscape(accessName) + `</string></value>`)
	}

	// Delete group subnet properties
	for i := range group.GroupSubnet {
		subnetName := fmt.Sprintf("group_subnets.%d", i)
		buf.WriteString(`<value><string>` + c.xmlEscape(subnetName) + `</string></value>`)
	}

	// Delete group range properties
	for i := range group.GroupRange {
		rangeName := fmt.Sprintf("group_range.%d", i)
		buf.WriteString(`<value><string>` + c.xmlEscape(rangeName) + `</string></value>`)
	}

	buf.WriteString(`</data></array></value></param>`)
	buf.WriteString(`</params></methodCall>`)
	return buf.String()
}

func (c *GroupClient) makeGroupPropertyRequest(groupName, property, value string) string {
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
</methodCall>`, c.xmlEscape(groupName), property, c.xmlEscape(value))
}

func (c *GroupClient) makeClearAccessControlRequest(group *entities.Group) string {
	var buf bytes.Buffer

	buf.WriteString(`<?xml version="1.0"?><methodCall>`)
	buf.WriteString(`<methodName>UserPropDel</methodName><params>`)
	buf.WriteString(`<param><value><string>` + c.xmlEscape(group.GroupName) + `</string></value></param>`)
	buf.WriteString(`<param><value><array>`)

	for i := range group.AccessControl {
		accessName := fmt.Sprintf("access_to.%d", i)
		buf.WriteString(`<data><value><string>` + c.xmlEscape(accessName) + `</string></value></data>`)
	}

	buf.WriteString(`</array></value></param>`)
	buf.WriteString(`</params></methodCall>`)

	return buf.String()
}
