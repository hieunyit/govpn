package xmlrpc

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
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
	return &VPNStatusClient{Client: client}
}

// GeoIPResponse - response từ IP geolocation service
type GeoIPResponse struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	Query   string `json:"query"`
}

// XMLVPNResponse - cấu trúc XML response từ OpenVPN XML-RPC
type XMLVPNResponse struct {
	XMLName xml.Name `xml:"methodResponse"`
	Params  struct {
		Param struct {
			Value struct {
				Struct struct {
					Members []VPNServerMember `xml:"member"`
				} `xml:"struct"`
			} `xml:"value"`
		} `xml:"param"`
	} `xml:"params"`
}

type VPNServerMember struct {
	Name  string `xml:"name"`
	Value struct {
		Struct struct {
			Members []ServerDataMember `xml:"member"`
		} `xml:"struct"`
	} `xml:"value"`
}

type ServerDataMember struct {
	Name  string `xml:"name"`
	Value struct {
		String string          `xml:"string"`
		Array  ClientListArray `xml:"array"`
	} `xml:"value"`
}

// ClientListArray - array chứa các user data entries
type ClientListArray struct {
	Data []ClientDataEntry `xml:"data>value"`
}

type ClientDataEntry struct {
	Values []string `xml:"array>data>value>string"`
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

func (c *VPNStatusClient) makeGetVPNStatusRequest() string {
	return `<?xml version="1.0"?>
<methodCall>
    <methodName>GetVPNStatus</methodName>
    <params></params>
</methodCall>`
}

func (c *VPNStatusClient) parseVPNStatusResponse(body []byte) (*entities.VPNStatusSummary, error) {
	var xmlResp XMLVPNResponse
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&xmlResp); err != nil {
		return nil, fmt.Errorf("failed to decode VPN status XML: %w", err)
	}

	summary := &entities.VPNStatusSummary{
		TotalConnectedUsers: 0,
		ConnectedUsers:      []*entities.ConnectedUser{},
		Timestamp:           time.Now(),
	}

	for _, serverMember := range xmlResp.Params.Param.Value.Struct.Members {
		if !strings.HasPrefix(serverMember.Name, "openvpn_") {
			continue
		}
		fmt.Printf("Processing server: %s\n", serverMember.Name)
		users := c.extractUsersFromServer(serverMember)
		for _, user := range users {
			user.Country = c.getCountryFromIP(user.RealAddress)
			user.ConnectionDuration = c.formatDuration(time.Since(user.ConnectedSince))
			summary.ConnectedUsers = append(summary.ConnectedUsers, user)
		}
	}

	summary.TotalConnectedUsers = len(summary.ConnectedUsers)
	fmt.Printf("Total connected users: %d\n", summary.TotalConnectedUsers)
	return summary, nil
}

func (c *VPNStatusClient) extractUsersFromServer(serverMember VPNServerMember) []*entities.ConnectedUser {
	for _, dataMember := range serverMember.Value.Struct.Members {
		if dataMember.Name == "client_list" {
			fmt.Printf("Found client_list in server\n")
			return c.parseClientListArray(dataMember.Value.Array)
		}
	}
	return nil
}

func (c *VPNStatusClient) parseClientListArray(clientArray ClientListArray) []*entities.ConnectedUser {
	var users []*entities.ConnectedUser
	fmt.Printf("Client array has %d entries\n", len(clientArray.Data))
	for i, entry := range clientArray.Data {
		fmt.Printf("Processing client entry %d: got %d values\n", i, len(entry.Values))
		if len(entry.Values) < 12 {
			fmt.Printf("  Skip: need 12 values, got %d\n", len(entry.Values))
			continue
		}
		if user := c.createUserFromValues(entry.Values); user != nil {
			users = append(users, user)
			fmt.Printf("Created user: %s from %s\n", user.Username, user.RealAddress)
		}
	}
	return users
}

func (c *VPNStatusClient) createUserFromValues(values []string) *entities.ConnectedUser {
	connectTime, err := time.Parse("2006-01-02 15:04:05", values[6])
	if err != nil {
		connectTime = time.Now()
	}
	connectUnix, _ := strconv.ParseInt(values[7], 10, 64)
	bytesReceived, _ := strconv.ParseInt(values[4], 10, 64)
	bytesSent, _ := strconv.ParseInt(values[5], 10, 64)

	user := &entities.ConnectedUser{
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
	return user
}

func (c *VPNStatusClient) extractIPFromAddress(address string) string {
	if i := strings.LastIndex(address, ":"); i != -1 {
		return address[:i]
	}
	return address
}

func (c *VPNStatusClient) getCountryFromIP(ip string) string {
	if c.isPrivateIP(ip) {
		return "Local"
	}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country", ip)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "Unknown"
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}
	var geo GeoIPResponse
	if err := json.Unmarshal(data, &geo); err != nil {
		return "Unknown"
	}
	if geo.Status == "success" {
		return geo.Country
	}
	return "Unknown"
}

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

func (c *VPNStatusClient) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
