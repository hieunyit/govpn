package validator

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validations
	validate.RegisterValidation("username", validateUsername)
	validate.RegisterValidation("date", validateDate)
	validate.RegisterValidation("mac_address", validateMACAddress)
	validate.RegisterValidation("ipv4_protocol", validateIPProtocol)
	validate.RegisterValidation("password_if_local", validatePasswordIfLocal)
	validate.RegisterValidation("ip_range", validateIPRange) // ← NEW: Add IP range validation
}

func Validate(s interface{}) error {
	return validate.Struct(s)
}

// NEW: Custom validation for IP range format "IP1-IP2"
func validateIPRange(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Allow empty for optional fields
	}

	// Expected format: "10.10.10.10-10.10.10.100"
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false
	}

	startIP := strings.TrimSpace(parts[0])
	endIP := strings.TrimSpace(parts[1])

	// Validate both IPs
	if net.ParseIP(startIP) == nil {
		return false
	}
	if net.ParseIP(endIP) == nil {
		return false
	}

	// Optional: Check if start <= end (convert to uint32 for comparison)
	startBytes := net.ParseIP(startIP).To4()
	endBytes := net.ParseIP(endIP).To4()

	if startBytes == nil || endBytes == nil {
		return false // Not IPv4
	}

	// Convert to uint32 for comparison
	startInt := uint32(startBytes[0])<<24 + uint32(startBytes[1])<<16 + uint32(startBytes[2])<<8 + uint32(startBytes[3])
	endInt := uint32(endBytes[0])<<24 + uint32(endBytes[1])<<16 + uint32(endBytes[2])<<8 + uint32(endBytes[3])

	return startInt <= endInt
}

func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()
	for _, char := range username {
		if !unicode.IsLower(char) && !unicode.IsDigit(char) && char != '.' && char != '_' {
			return false
		}
	}
	return true
}

func validateDate(fl validator.FieldLevel) bool {
	dateStr := fl.Field().String()
	if dateStr == "" {
		return true // Allow empty dates for optional fields
	}
	date, err := time.Parse("02/01/2006", dateStr)
	if err != nil {
		return false
	}
	return date.After(time.Now())
}

// Updated MAC address validation to support multiple formats
func validateMACAddress(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	// Remove common separators and convert to lowercase
	cleanMAC := strings.ToLower(value)
	cleanMAC = strings.ReplaceAll(cleanMAC, ":", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, "-", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, ".", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, " ", "")

	// Check if it's exactly 12 hex characters
	if len(cleanMAC) != 12 {
		return false
	}

	// Check if all characters are hex
	hexPattern := regexp.MustCompile("^[0-9a-f]{12}$")
	return hexPattern.MatchString(cleanMAC)
}

func validateIPProtocol(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}

	ip := parts[0]
	if !isValidIP(ip) {
		return false
	}

	portProtocolList := strings.Split(parts[1], ",")
	for _, portProtocol := range portProtocolList {
		subParts := strings.Split(portProtocol, "/")

		if len(subParts) < 1 || len(subParts) > 2 {
			return false
		}

		protocol := subParts[0]
		if !isValidProtocol(protocol) {
			return false
		}

		if len(subParts) == 2 {
			portRange := strings.Split(subParts[1], "-")
			if len(portRange) == 2 {
				startPort, err := strconv.Atoi(portRange[0])
				if err != nil || startPort < 1 || startPort > 65535 {
					return false
				}
				endPort, err := strconv.Atoi(portRange[1])
				if err != nil || endPort < 1 || endPort > 65535 {
					return false
				}
				if endPort < startPort {
					return false
				}
			} else {
				port := subParts[1]
				if !isValidPort(port) {
					return false
				}
			}
		}
	}
	return true
}

// Custom validation for password requirement based on auth method
func validatePasswordIfLocal(fl validator.FieldLevel) bool {
	// Get the struct containing this field
	parent := fl.Parent()

	// Get the authMethod field
	authMethodField := parent.FieldByName("AuthMethod")
	if !authMethodField.IsValid() {
		return true // If authMethod not found, skip validation
	}

	authMethod := authMethodField.String()
	password := fl.Field().String()

	// If auth method is local, password is required
	if authMethod == "local" && password == "" {
		return false
	}

	// If password is provided, it should meet minimum requirements
	if password != "" && len(password) < 8 {
		return false
	}

	return true
}

func isValidIP(ip string) bool {
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		if net.ParseIP(ip) == nil {
			return false
		}
	}
	return true
}

func isValidProtocol(protocol string) bool {
	return protocol == "tcp" || protocol == "udp" || protocol == "icmp-echo-request"
}

func isValidPort(port string) bool {
	num, err := strconv.Atoi(port)
	if err != nil || num < 1 || num > 65535 {
		return false
	}
	return true
}

func ValidateAndFixIPs(ips []string) ([]string, error) {
	var resultIPs []string

	for _, ip := range ips {
		if strings.HasSuffix(ip, "/") {
			return nil, fmt.Errorf("%s has a trailing '/' character", ip)
		}
		if !strings.Contains(ip, "/") {
			ip = ip + "/32"
		}
		resultIPs = append(resultIPs, ip)
	}
	return resultIPs, nil
}

// Updated MAC address conversion to handle multiple formats
func ConvertMAC(macAddresses []string) []string {
	var result []string
	for _, mac := range macAddresses {
		// Remove all separators and convert to lowercase
		cleanMAC := strings.ToLower(mac)
		cleanMAC = strings.ReplaceAll(cleanMAC, ":", "")
		cleanMAC = strings.ReplaceAll(cleanMAC, "-", "")
		cleanMAC = strings.ReplaceAll(cleanMAC, ".", "")
		cleanMAC = strings.ReplaceAll(cleanMAC, " ", "")

		// Convert to standard format XX:XX:XX:XX:XX:XX
		if len(cleanMAC) == 12 {
			standardMAC := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
				cleanMAC[0:2], cleanMAC[2:4], cleanMAC[4:6],
				cleanMAC[6:8], cleanMAC[8:10], cleanMAC[10:12])
			result = append(result, standardMAC)
		} else {
			// If invalid format, keep original
			result = append(result, mac)
		}
	}
	return result
}

// Normalize MAC address to standard format
func NormalizeMACAddress(mac string) string {
	// Remove all separators and convert to lowercase
	cleanMAC := strings.ToLower(mac)
	cleanMAC = strings.ReplaceAll(cleanMAC, ":", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, "-", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, ".", "")
	cleanMAC = strings.ReplaceAll(cleanMAC, " ", "")

	// Convert to standard format XX:XX:XX:XX:XX:XX
	if len(cleanMAC) == 12 {
		return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			cleanMAC[0:2], cleanMAC[2:4], cleanMAC[4:6],
			cleanMAC[6:8], cleanMAC[8:10], cleanMAC[10:12])
	}

	return mac // Return original if invalid
}
