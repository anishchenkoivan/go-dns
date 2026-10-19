package provider

import "github.com/anishchenkoivan/go-dns/dns"

type StaticProvider struct {
	records map[string]dns.AnswerRecord
}

func NewStaticProvider() *StaticProvider {
	return &StaticProvider{
		records: map[string]dns.AnswerRecord{
			"yandex.ru": dns.AnswerRecord{
				QueryType: 0x0001,
				Response:  []byte{127, 0, 0, 1},
				Ttl:       6000,
			},
		},
	}
}

func (p *StaticProvider) GetRecord(question dns.Question) []dns.AnswerRecord {
	return []dns.AnswerRecord{p.records[question.Qname]}
}
