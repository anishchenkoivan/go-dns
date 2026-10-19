package dns

import (
	"bytes"
	"encoding/binary"
)

// ParseQuery parses a DNS message from its wire representation into a Query.
func ParseQuery(data *[]byte) Query {
	query := Query{}
	if data == nil || len(*data) < 12 {
		return query
	}

	buf := *data
	offset := 0

	// Header (12 bytes).
	query.header.id = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2

	flags := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	query.header.qr = flags&0x8000 != 0
	query.header.opcode = uint8((flags >> 11) & 0x0F)
	query.header.aa = flags&0x0400 != 0
	query.header.tc = flags&0x0200 != 0
	query.header.rd = flags&0x0100 != 0
	query.header.ra = flags&0x0080 != 0
	query.header.rcode = uint8(flags & 0x000F)

	query.header.qdcount = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	query.header.ancount = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	query.header.nscount = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2
	query.header.arcount = binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2

	// Question section.
	query.questions = make([]Question, 0, int(query.header.qdcount))
	for i := 0; i < int(query.header.qdcount); i++ {
		q, next, ok := parseQuestion(buf, offset)
		if !ok {
			break
		}
		offset = next
		query.questions = append(query.questions, q)
	}

	query.answer.content = parseRecords(buf, &offset, int(query.header.ancount))
	query.authority.content = parseRecords(buf, &offset, int(query.header.nscount))
	query.additional.content = parseRecords(buf, &offset, int(query.header.arcount))

	return query
}

// SerializeQuery serializes a Query into the DNS wire representation. Section
// counts are derived from the actual contents rather than the stored header
// counts, so the emitted message is always internally consistent.
func SerializeQuery(query *Query) []byte {
	if query == nil {
		return nil
	}

	buf := make([]byte, 0, 512)

	buf = binary.BigEndian.AppendUint16(buf, query.header.id)

	flags := uint16(query.header.rcode & 0x0F)
	if query.header.ra {
		flags |= 0x0080
	}
	if query.header.rd {
		flags |= 0x0100
	}
	if query.header.tc {
		flags |= 0x0200
	}
	if query.header.aa {
		flags |= 0x0400
	}
	flags |= uint16(query.header.opcode&0x0F) << 11
	if query.header.qr {
		flags |= 0x8000
	}
	buf = binary.BigEndian.AppendUint16(buf, flags)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(query.questions)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(query.answer.content)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(query.authority.content)))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(query.additional.content)))

	for _, q := range query.questions {
		buf = appendQuestion(buf, q)
	}
	for _, rr := range query.answer.content {
		buf = appendResourceRecord(buf, rr)
	}
	for _, rr := range query.authority.content {
		buf = appendResourceRecord(buf, rr)
	}
	for _, rr := range query.additional.content {
		buf = appendResourceRecord(buf, rr)
	}

	return buf
}

func parseQuestion(data []byte, offset int) (Question, int, bool) {
	var q Question
	name, next, ok := parseName(data, offset)
	if !ok {
		return q, 0, false
	}
	if next+4 > len(data) {
		return q, 0, false
	}

	q.Qname = string(name)
	q.Qtype = binary.BigEndian.Uint16(data[next : next+2])
	q.Qclass = binary.BigEndian.Uint16(data[next+2 : next+4])
	return q, next + 4, true
}

func parseRecords(data []byte, offset *int, count int) []ResourceRecord {
	records := make([]ResourceRecord, 0, count)
	for i := 0; i < count; i++ {
		name, next, ok := parseName(data, *offset)
		if !ok {
			break
		}
		*offset = next
		if *offset+10 > len(data) {
			break
		}

		recordType := binary.BigEndian.Uint16(data[*offset : *offset+2])
		class := binary.BigEndian.Uint16(data[*offset+2 : *offset+4])
		ttl := binary.BigEndian.Uint32(data[*offset+4 : *offset+8])
		rdlength := int(binary.BigEndian.Uint16(data[*offset+8 : *offset+10]))
		*offset += 10

		if *offset+rdlength > len(data) {
			break
		}

		records = append(records, ResourceRecord{
			name:       name,
			recordType: recordType,
			class:      class,
			ttl:        ttl,
			rdlength:   uint16(rdlength),
			rdata:      append([]byte(nil), data[*offset:*offset+rdlength]...),
		})
		*offset += rdlength
	}
	return records
}

// parseName reads a possibly-compressed domain name starting at offset and
// returns the name as dotted bytes, the offset immediately after the name, and
// whether parsing succeeded.
func parseName(data []byte, offset int) ([]byte, int, bool) {
	var name []byte
	pos := offset
	endOffset := -1
	visited := make(map[int]bool)

	for {
		if pos < 0 || pos >= len(data) {
			return nil, 0, false
		}
		length := int(data[pos])

		if length&0xC0 == 0xC0 {
			// Compression pointer (top two bits set).
			if pos+1 >= len(data) {
				return nil, 0, false
			}
			target := int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF)
			if visited[target] {
				return nil, 0, false // pointer loop
			}
			visited[target] = true
			if endOffset == -1 {
				endOffset = pos + 2
			}
			pos = target
			continue
		}

		if length&0xC0 != 0 {
			return nil, 0, false // reserved label type
		}

		pos++
		if length == 0 {
			break // root / end of name
		}
		if pos+length > len(data) {
			return nil, 0, false
		}
		if len(name)+1+length > 255 {
			return nil, 0, false // name would exceed the 255-octet limit
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, data[pos:pos+length]...)
		pos += length
	}

	if endOffset == -1 {
		endOffset = pos
	}
	return name, endOffset, true
}

func appendQuestion(buf []byte, q Question) []byte {
	buf = appendName(buf, []byte(q.Qname))
	buf = binary.BigEndian.AppendUint16(buf, q.Qtype)
	buf = binary.BigEndian.AppendUint16(buf, q.Qclass)
	return buf
}

func appendResourceRecord(buf []byte, rr ResourceRecord) []byte {
	buf = appendName(buf, rr.name)
	buf = binary.BigEndian.AppendUint16(buf, rr.recordType)
	buf = binary.BigEndian.AppendUint16(buf, rr.class)
	buf = binary.BigEndian.AppendUint32(buf, rr.ttl)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rr.rdata)))
	buf = append(buf, rr.rdata...)
	return buf
}

// appendName encodes a dotted name (as bytes) into DNS wire format.
func appendName(buf []byte, name []byte) []byte {
	if len(name) == 0 {
		return append(buf, 0)
	}
	for _, label := range bytes.Split(name, []byte(".")) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}
