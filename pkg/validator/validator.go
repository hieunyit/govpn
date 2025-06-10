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
	validate.RegisterValidation("hex16", validateHex16)
	validate.RegisterValidation("ipv4_protocol", validateIPProtocol)
}

func Validate(s interface{}) error {
	return validate.Struct(s)
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
	date, err := time.Parse("02/01/2006", dateStr)
	if err != nil {
		return false
	}
	return date.After(time.Now())
}

func validateHex16(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	hexPattern := regexp.MustCompile("^[0-9a-fA-F]{16}$")
	return hexPattern.MatchString(value)
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

func ConvertMAC(macAddresses []string) []string {
	var result []string
	for _, str := range macAddresses {
		lowerCaseStr := strings.ToLower(str)
		convertedStr := strings.ReplaceAll(lowerCaseStr, "-", ":")
		result = append(result, convertedStr)
	}
	return result
}
