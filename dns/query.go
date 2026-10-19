package dns

type Header struct {
	id uint16

	qr     bool
	opcode uint8
	aa     bool
	tc     bool
	rd     bool
	ra     bool
	rcode  uint8

	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
}

type Question struct {
	qname  string
	qtype  uint16 // TODO: add an alternative type
	qclass uint16
}

type ResourceRecord struct {
	name       string
	recordType uint16
	class      uint16
	ttl        uint32
	rdlength   uint16
	rdata      string
}

type Answer struct {
	content []ResourceRecord
}

type Authority struct {
	content []ResourceRecord
}

type Additional struct {
	content []ResourceRecord
}

type Query struct {
	header     Header
	questions  []Question
	answer     Answer
	authority  Authority
	additional Additional
}
