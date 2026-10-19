package provider

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/anishchenkoivan/go-dns/dns"
)

type config struct {
	Records []record `json:"records"`
}

type record struct {
	Type     string `json:"type"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

type FileProvider struct {
	records map[string][]dns.AnswerRecord
}

func NewFileProvider(path string) (*FileProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file %q: %w", path, err)
	}

	records := make(map[string][]dns.AnswerRecord)
	for _, r := range cfg.Records {
		queryType, err := parseType(r.Type)
		if err != nil {
			return nil, fmt.Errorf("config file %q: %w", path, err)
		}
		response, err := parseResponse(queryType, r.Response)
		if err != nil {
			return nil, fmt.Errorf("config file %q: %w", path, err)
		}

		key := normalizeName(r.Request)
		records[key] = append(records[key], dns.AnswerRecord{
			QueryType: queryType,
			Response:  response,
			Ttl:       6000,
		})
	}

	return &FileProvider{records: records}, nil
}

func (p *FileProvider) GetRecord(question dns.Question) []dns.AnswerRecord {
	var result []dns.AnswerRecord
	for _, r := range p.records[normalizeName(question.Qname)] {
		if r.QueryType == question.Qtype {
			result = append(result, r)
		}
	}
	return result
}

func parseType(t string) (uint16, error) {
	switch t {
	case "A":
		return 0x0001, nil
	case "NS":
		return 0x0002, nil
	case "CNAME":
		return 0x0005, nil
	case "AAAA":
		return 0x001C, nil
	default:
		return 0, fmt.Errorf("unsupported record type %q", t)
	}
}

func parseResponse(queryType uint16, response string) ([]byte, error) {
	switch queryType {
	case 0x0001: // A
		ip := net.ParseIP(response)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address %q", response)
		}
		return ip.To4(), nil
	default:
		return []byte(response), nil
	}
}

func normalizeName(name string) string {
	return strings.ToLower(name)
}
