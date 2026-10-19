package dns

type AnswerRecord struct {
	QueryType uint16
	Response  []byte
	Ttl       uint32
}

type ResourceProvider interface {
	GetRecord(question Question) []AnswerRecord
}
