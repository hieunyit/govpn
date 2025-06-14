package xmlrpc

import (
	"encoding/json"
	"fmt"
	"govpn/internal/domain/entities"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type VPNStatusClient struct {
	*Client
}

func NewVPNStatusClient(client *Client) *VPNStatusClient {
	return &VPNStatusClient{
		Client: client,
	}
}

// GeoIPResponse - response từ IP geolocation service
type GeoIPResponse struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	Query   string `json:"query"`
}

// GetVPNStatus - lấy status của tất cả VPN servers
func (c *VPNStatusClient) GetVPNStatus() (*entities.VPNStatusSummary, error) {
	xmlRequest := c.makeGetVPNStatusRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get VPN status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseVPNStatusResponse(body)
}

// makeGetVPNStatusRequest - tạo XML-RPC request
func (c *VPNStatusClient) makeGetVPNStatusRequest() string {
	return `<?xml version="1.0"?>
<methodCall>
	<methodName>GetVPNStatus</methodName>
	<params></params>
</methodCall>`
}

// parseVPNStatusResponse - parse XML response và trả về summary
func (c *VPNStatusClient) parseVPNStatusResponse(body []byte) (*entities.VPNStatusSummary, error) {
	bodyStr := string(body)

	summary := &entities.VPNStatusSummary{
		TotalConnectedUsers: 0,
		ConnectedUsers:      []*entities.ConnectedUser{},
		Timestamp:           time.Now(),
	}

	// Extract tất cả connected users từ các VPN servers
	allUsers := c.extractAllConnectedUsers(bodyStr)

	// Lấy country cho tất cả users
	for _, user := range allUsers {
		country := c.getCountryFromIP(user.RealAddress)
		user.Country = country

		// Tính thời gian connection duration
		duration := time.Since(user.ConnectedSince)
		user.ConnectionDuration = c.formatDuration(duration)

		summary.ConnectedUsers = append(summary.ConnectedUsers, user)
	}

	summary.TotalConnectedUsers = len(summary.ConnectedUsers)

	return summary, nil
}

// extractAllConnectedUsers - extract tất cả connected users từ tất cả servers
func (c *VPNStatusClient) extractAllConnectedUsers(body string) []*entities.ConnectedUser {
	var allUsers []*entities.ConnectedUser

	// Tìm tất cả openvpn servers (openvpn_0, openvpn_1, ...)
	serverNames := c.findAllServerNames(body)

	for _, serverName := range serverNames {
		// Extract users từ server này
		users := c.extractUsersFromServerSection(body, serverName)
		allUsers = append(allUsers, users...)
	}

	return allUsers
}

// extractUsersFromServerSection - extract users từ một server section
func (c *VPNStatusClient) extractUsersFromServerSection(body, serverName string) []*entities.ConnectedUser {
	// Tìm section của server này
	sectionStart := fmt.Sprintf("<n>%s</n>", serverName)
	startIdx := strings.Index(body, sectionStart)
	if startIdx == -1 {
		return nil
	}

	// Tìm end của section (member tiếp theo hoặc end struct)
	endIdx := c.findSectionEnd(body, startIdx)
	if endIdx == -1 {
		endIdx = len(body)
	}

	sectionData := body[startIdx:endIdx]

	// Extract connected users từ section này
	return c.extractConnectedUsers(sectionData)
}

// findAllServerNames - tìm tất cả server names trong response
func (c *VPNStatusClient) findAllServerNames(body string) []string {
	var serverNames []string

	// Pattern: <n>openvpn_X</n>
	idx := 0
	for {
		start := strings.Index(body[idx:], "<n>openvpn_")
		if start == -1 {
			break
		}
		start += idx + 3 // Skip "<n>"

		end := strings.Index(body[start:], "</n>")
		if end == -1 {
			break
		}

		serverName := body[start : start+end]
		serverNames = append(serverNames, serverName)

		idx = start + end + 1
	}

	return serverNames
}

// extractServerData - bỏ function này vì không cần nữa
// extractGlobalStats - bỏ function này vì không cần nữa
// extractServerTitle - bỏ function này vì không cần nữa
// extractServerTime - bỏ function này vì không cần nữa

// findSectionEnd - tìm end của section hiện tại
func (c *VPNStatusClient) findSectionEnd(body string, startIdx int) int {
	// Tìm </member> tương ứng với member hiện tại
	memberCount := 1
	idx := startIdx

	for idx < len(body) && memberCount > 0 {
		if nextMember := strings.Index(body[idx+1:], "<member>"); nextMember != -1 {
			nextMember += idx + 1
			if endMember := strings.Index(body[idx+1:], "</member>"); endMember != -1 {
				endMember += idx + 1
				if nextMember < endMember {
					memberCount++
					idx = nextMember
				} else {
					memberCount--
					idx = endMember
				}
			} else {
				break
			}
		} else if endMember := strings.Index(body[idx+1:], "</member>"); endMember != -1 {
			memberCount--
			idx += endMember + 1
		} else {
			break
		}
	}

	return idx
}

// extractServerTitle - extract server title
func (c *VPNStatusClient) extractServerTitle(section string) string {
	return c.extractStringValue(section, "title")
}

// extractServerTime - extract server time
func (c *VPNStatusClient) extractServerTime(section string) time.Time {
	timeStr := c.extractStringValue(section, "time")
	if timeStr != "" {
		if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
			return t
		}
	}
	return time.Now()
}

// extractGlobalStats - extract global statistics
func (c *VPNStatusClient) extractGlobalStats(section string) *entities.GlobalStats {
	maxQueue := c.extractStringValue(section, "Max bcast/mcast queue length")
	dcoEnabled := c.extractStringValue(section, "dco_enabled") == "1"

	return &entities.GlobalStats{
		MaxBcastMcastQueueLength: maxQueue,
		DCOEnabled:               dcoEnabled,
	}
}

// extractConnectedUsers - extract tất cả connected users từ section
func (c *VPNStatusClient) extractConnectedUsers(section string) []*entities.ConnectedUser {
	var users []*entities.ConnectedUser

	// Tìm client_list
	clientListStart := strings.Index(section, "<n>client_list</n>")
	if clientListStart == -1 {
		return users
	}

	// Tìm array chứa client data
	arrayStart := strings.Index(section[clientListStart:], "<array>")
	if arrayStart == -1 {
		return users
	}
	arrayStart += clientListStart

	arrayEnd := strings.Index(section[arrayStart:], "</array>")
	if arrayEnd == -1 {
		return users
	}
	arrayEnd += arrayStart

	clientSection := section[arrayStart:arrayEnd]

	// Parse từng client entry
	users = c.parseClientEntries(clientSection)

	return users
}

// parseClientEntries - parse individual client entries
func (c *VPNStatusClient) parseClientEntries(clientSection string) []*entities.ConnectedUser {
	var users []*entities.ConnectedUser

	// Tìm tất cả data arrays (mỗi array là 1 user)
	dataIdx := 0
	for {
		dataStart := strings.Index(clientSection[dataIdx:], "<data>")
		if dataStart == -1 {
			break
		}
		dataStart += dataIdx

		dataEnd := strings.Index(clientSection[dataStart:], "</data>")
		if dataEnd == -1 {
			break
		}
		dataEnd += dataStart

		dataContent := clientSection[dataStart:dataEnd]

		// Parse values trong data array
		values := c.extractStringValues(dataContent)
		if len(values) >= 12 { // Đảm bảo có đủ fields
			user := c.createUserFromValues(values)
			if user != nil {
				users = append(users, user)
			}
		}

		dataIdx = dataEnd + 1
	}

	return users
}

// extractStringValues - extract string values từ data array
func (c *VPNStatusClient) extractStringValues(dataContent string) []string {
	var values []string

	idx := 0
	for {
		stringStart := strings.Index(dataContent[idx:], "<string>")
		if stringStart == -1 {
			break
		}
		stringStart += idx + 8

		stringEnd := strings.Index(dataContent[stringStart:], "</string>")
		if stringEnd == -1 {
			break
		}

		value := dataContent[stringStart : stringStart+stringEnd]
		values = append(values, value)

		idx = stringStart + stringEnd + 1
	}

	return values
}

// createUserFromValues - tạo ConnectedUser từ array values
func (c *VPNStatusClient) createUserFromValues(values []string) *entities.ConnectedUser {
	if len(values) < 12 {
		return nil
	}

	// Parse connect time
	connectTime, _ := time.Parse("2006-01-02 15:04:05", values[6])
	connectUnix, _ := strconv.ParseInt(values[7], 10, 64)

	// Parse bytes
	bytesReceived, _ := strconv.ParseInt(values[4], 10, 64)
	bytesSent, _ := strconv.ParseInt(values[5], 10, 64)

	return &entities.ConnectedUser{
		CommonName:         values[0],
		RealAddress:        c.extractIPFromAddress(values[1]),
		VirtualAddress:     values[2],
		VirtualIPv6Address: values[3],
		BytesReceived:      bytesReceived,
		BytesSent:          bytesSent,
		ConnectedSince:     connectTime,
		ConnectedSinceUnix: connectUnix,
		Username:           values[8],
		ClientID:           values[9],
		PeerID:             values[10],
		DataChannelCipher:  values[11],
	}
}

// extractStringValue - helper để extract string value theo name
func (c *VPNStatusClient) extractStringValue(section, name string) string {
	searchStr := fmt.Sprintf("<n>%s</n>", name)
	if start := strings.Index(section, searchStr); start != -1 {
		if valueStart := strings.Index(section[start:], "<string>"); valueStart != -1 {
			valueStart += start + 8
			if valueEnd := strings.Index(section[valueStart:], "</string>"); valueEnd != -1 {
				return section[valueStart : valueStart+valueEnd]
			}
		}
	}
	return ""
}

// extractIPFromAddress - extract IP từ "IP:Port" format
func (c *VPNStatusClient) extractIPFromAddress(address string) string {
	if colonIdx := strings.LastIndex(address, ":"); colonIdx != -1 {
		return address[:colonIdx]
	}
	return address
}

// getCountryFromIP - lấy quốc gia từ IP address
func (c *VPNStatusClient) getCountryFromIP(ip string) string {
	// Skip nếu là IP local/private
	if c.isPrivateIP(ip) {
		return "Local"
	}

	// Sử dụng free service ip-api.com
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "Unknown"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var geoResp GeoIPResponse
	if err := json.Unmarshal(body, &geoResp); err != nil {
		return "Unknown"
	}

	if geoResp.Status == "success" {
		return geoResp.Country
	}

	return "Unknown"
}

// isPrivateIP - check nếu IP là private/local
func (c *VPNStatusClient) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
		"127.", "169.254.",
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// formatDuration - format duration thành string dễ đọc
func (c *VPNStatusClient) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}
