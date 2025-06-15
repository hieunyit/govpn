package xmlrpc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ConfigClient struct {
	*Client
}

func NewConfigClient(client *Client) *ConfigClient {
	return &ConfigClient{
		Client: client,
	}
}

// XMLConfigResponse - cấu trúc để parse XML response của config
type XMLConfigResponse struct {
	XMLName xml.Name `xml:"methodResponse"`
	Params  struct {
		Param struct {
			Value struct {
				Struct struct {
					Members []ConfigMember `xml:"member"`
				} `xml:"struct"`
			} `xml:"value"`
		} `xml:"param"`
	} `xml:"params"`
}

type ConfigMember struct {
	Name  string `xml:"name"`
	Value struct {
		String string      `xml:"string"`
		Int    string      `xml:"int"`
		Array  ConfigArray `xml:"array"`
	} `xml:"value"`
}

type ConfigArray struct {
	Data []ConfigArrayData `xml:"data"`
}

type ConfigArrayData struct {
	Value struct {
		String string      `xml:"string"`
		Array  ConfigArray `xml:"array"`
	} `xml:"value"`
}

// GetConfig - lấy tất cả configuration từ OpenVPN Access Server
func (c *ConfigClient) GetConfig() (map[string]string, error) {
	xmlRequest := c.makeGetConfigRequest()

	resp, err := c.Call(xmlRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return c.parseConfigResponse(body)
}

// makeGetConfigRequest - tạo XML-RPC request để lấy config
func (c *ConfigClient) makeGetConfigRequest() string {
	return `<?xml version="1.0"?>
<methodCall>
	<methodName>ConfigDefaults</methodName>
	<params>
		<param>
			<value>
				<nil/>
			</value>
		</param>
	</params>
</methodCall>`
}

// parseConfigResponse - parse XML response thành map[string]string
func (c *ConfigClient) parseConfigResponse(body []byte) (map[string]string, error) {
	var xmlResp XMLConfigResponse
	err := xml.NewDecoder(bytes.NewReader(body)).Decode(&xmlResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config XML: %w", err)
	}

	configMap := make(map[string]string)
	// Parse từng member trong struct
	for _, member := range xmlResp.Params.Param.Value.Struct.Members {
		key := member.Name
		fmt.Print("Parsing key: ", key, "\n")
		// Handle different value types
		if member.Value.String != "" {
			configMap[key] = member.Value.String
		} else if member.Value.Int != "" {
			configMap[key] = member.Value.Int
		} else {
			// Handle array values (convert to string representation)
			arrayValue := c.parseArrayValue(member.Value.Array)
			if arrayValue != "" {
				configMap[key] = arrayValue
			}
		}
	}
	return configMap, nil
}

// parseArrayValue - parse array values thành string representation
func (c *ConfigClient) parseArrayValue(array ConfigArray) string {
	if len(array.Data) == 0 {
		return ""
	}

	var values []string
	for _, data := range array.Data {
		if data.Value.String != "" {
			values = append(values, data.Value.String)
		} else if len(data.Value.Array.Data) > 0 {
			// Handle nested arrays
			nestedValues := c.parseArrayValue(data.Value.Array)
			if nestedValues != "" {
				values = append(values, nestedValues)
			}
		}
	}

	return strings.Join(values, ",")
}
