package dns

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// --- test helpers -----------------------------------------------------------

// nameBytes encodes a dotted name into DNS wire format (uncompressed).
func nameBytes(name string) []byte {
	var b []byte
	if name == "" {
		return []byte{0}
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(len(name[start:i])))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	return append(b, 0)
}

// namePtr builds a 2-byte compression pointer to the given offset.
func namePtr(offset uint16) []byte {
	return []byte{0xC0 | byte(offset>>8), byte(offset)}
}

// testHeader builds a 12-byte DNS header.
func testHeader(id, flags, qd, an, ns, ar uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], qd)
	binary.BigEndian.PutUint16(b[6:8], an)
	binary.BigEndian.PutUint16(b[8:10], ns)
	binary.BigEndian.PutUint16(b[10:12], ar)
	return b
}

// rrBytes encodes a resource record.
func rrBytes(name string, typ, class uint16, ttl uint32, rdata []byte) []byte {
	b := nameBytes(name)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, class)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// --- header -----------------------------------------------------------------

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		want  Header
	}{
		{
			name:  "all flags set",
			flags: 0xFFFF,
			want: Header{
				id: 0xABCD, qr: true, opcode: 15, aa: true, tc: true,
				rd: true, ra: true, rcode: 15,
				qdcount: 1, ancount: 2, nscount: 3, arcount: 4,
			},
		},
		{
			name:  "all flags clear",
			flags: 0x0000,
			want:  Header{id: 0xABCD, qdcount: 1, ancount: 2, nscount: 3, arcount: 4},
		},
		{
			name:  "mixed flags",
			flags: 0x8183, // QR, RD, RA, rcode=3
			want: Header{
				id: 0xABCD, qr: true, rd: true, ra: true, rcode: 3,
				qdcount: 1, ancount: 2, nscount: 3, arcount: 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := testHeader(0xABCD, tt.flags, 1, 2, 3, 4)
			q := ParseQuery(&msg)
			if q.header != tt.want {
				t.Fatalf("header = %+v, want %+v", q.header, tt.want)
			}
		})
	}
}

// --- names ------------------------------------------------------------------

func TestParseName(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantEnd int
		wantOK  bool
	}{
		{"root", []byte{0x00}, nil, 1, true},
		{
			"multiple labels",
			[]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			[]byte("www.example.com"), 17, true,
		},
		{"reserved label type", []byte{0x40, 0x00}, nil, 0, false},
		{"truncated label", []byte{5, 'a', 'b'}, nil, 0, false},
		{"empty input", nil, nil, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, end, ok := parseName(tt.input, 0)
			if !bytes.Equal(got, tt.want) || end != tt.wantEnd || ok != tt.wantOK {
				t.Fatalf("parseName = (%q, %d, %v), want (%q, %d, %v)",
					got, end, ok, tt.want, tt.wantEnd, tt.wantOK)
			}
		})
	}
}

func TestParseNameCompression(t *testing.T) {
	// "www" at offset 0, then a pointer to it at offset 5.
	msg := append([]byte{0x03, 'w', 'w', 'w', 0x00}, namePtr(0)...)

	got, end, ok := parseName(msg, 5)
	if !ok || !bytes.Equal(got, []byte("www")) || end != 7 {
		t.Fatalf("parseName = (%q, %d, %v), want (%q, 7, true)", got, end, ok, "www")
	}
}

func TestParseNamePointerLoop(t *testing.T) {
	// A pointer that points to itself.
	if _, _, ok := parseName([]byte{0xC0, 0x00}, 0); ok {
		t.Fatal("expected self-referential pointer to be rejected")
	}

	// A two-pointer cycle: A -> B -> A.
	cycle := append(namePtr(2), namePtr(0)...)
	if _, _, ok := parseName(cycle, 0); ok {
		t.Fatal("expected pointer cycle to be rejected")
	}
}

// --- questions --------------------------------------------------------------

func TestParseQuestions(t *testing.T) {
	msg := testHeader(0x0001, 0x0100, 2, 0, 0, 0)
	msg = append(msg, nameBytes("example.com")...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN
	msg = append(msg, nameBytes("example.org")...)
	msg = append(msg, 0x00, 0x1C, 0x00, 0x01) // AAAA IN

	q := ParseQuery(&msg)

	want := []Question{
		{Qname: "example.com", Qtype: 1, Qclass: 1},
		{Qname: "example.org", Qtype: 28, Qclass: 1},
	}
	if !reflect.DeepEqual(q.questions, want) {
		t.Fatalf("questions = %+v, want %+v", q.questions, want)
	}
}

// --- resource records -------------------------------------------------------

func TestParseRecords(t *testing.T) {
	nsRdata := nameBytes("ns.example.com")

	msg := testHeader(0, 0x8180, 0, 1, 1, 1)
	msg = append(msg, rrBytes("example.com", 1, 1, 300, []byte{192, 0, 2, 1})...) // answer A
	msg = append(msg, rrBytes("example.com", 2, 1, 60, nsRdata)...)               // authority NS
	msg = append(msg, rrBytes("example.org", 1, 1, 30, []byte{192, 0, 2, 2})...)  // additional A

	q := ParseQuery(&msg)

	wantAnswer := ResourceRecord{name: []byte("example.com"), recordType: 1, class: 1, ttl: 300, rdlength: 4, rdata: []byte{192, 0, 2, 1}}
	if len(q.answer.content) != 1 || !reflect.DeepEqual(q.answer.content[0], wantAnswer) {
		t.Fatalf("answer = %+v, want %+v", q.answer.content, wantAnswer)
	}

	wantAuth := ResourceRecord{name: []byte("example.com"), recordType: 2, class: 1, ttl: 60, rdlength: uint16(len(nsRdata)), rdata: nsRdata}
	if len(q.authority.content) != 1 || !reflect.DeepEqual(q.authority.content[0], wantAuth) {
		t.Fatalf("authority = %+v, want %+v", q.authority.content, wantAuth)
	}

	wantAdd := ResourceRecord{name: []byte("example.org"), recordType: 1, class: 1, ttl: 30, rdlength: 4, rdata: []byte{192, 0, 2, 2}}
	if len(q.additional.content) != 1 || !reflect.DeepEqual(q.additional.content[0], wantAdd) {
		t.Fatalf("additional = %+v, want %+v", q.additional.content, wantAdd)
	}
}

// --- serialization ----------------------------------------------------------

func TestSerializeEmptyQuery(t *testing.T) {
	got := SerializeQuery(&Query{})
	want := make([]byte, 12)
	if !bytes.Equal(got, want) {
		t.Fatalf("SerializeQuery(empty) = % x, want 12 zero bytes", got)
	}

	if got := SerializeQuery(nil); got != nil {
		t.Fatalf("SerializeQuery(nil) = %v, want nil", got)
	}
}

func TestRoundTrip(t *testing.T) {
	q := Query{
		header: Header{
			id: 0xBEEF, qr: true, rd: true, ra: true,
			qdcount: 1, ancount: 1, nscount: 1, arcount: 1,
		},
		questions: []Question{
			{Qname: "example.com", Qtype: 1, Qclass: 1},
		},
		answer: Answer{content: []ResourceRecord{
			{name: []byte("example.com"), recordType: 1, class: 1, ttl: 300, rdlength: 4, rdata: []byte{192, 0, 2, 1}},
		}},
		authority: Authority{content: []ResourceRecord{
			{name: []byte("example.com"), recordType: 2, class: 1, ttl: 60, rdlength: 14, rdata: []byte("ns.example.com")},
		}},
		additional: Additional{content: []ResourceRecord{
			{name: nil, recordType: 41, class: 4096, ttl: 0, rdlength: 0, rdata: nil},
		}},
	}

	out := SerializeQuery(&q)
	parsed := ParseQuery(&out)

	if !reflect.DeepEqual(parsed, q) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", parsed, q)
	}
}

// --- robustness -------------------------------------------------------------

func TestParseTruncatedInputs(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"short header":     make([]byte, 11),
		"qd without body":  testHeader(0, 0, 1, 0, 0, 0),
		"an without body":  testHeader(0, 0, 0, 1, 0, 0),
		"all without body": testHeader(0, 0, 1, 1, 1, 1),
		"truncated qname":  append(testHeader(0, 0, 1, 0, 0, 0), 3, 'w', 'w'),
		"truncated rdata": func() []byte {
			b := testHeader(0, 0, 0, 1, 0, 0)
			b = append(b, nameBytes("example.com")...)
			b = binary.BigEndian.AppendUint16(b, 1)   // type A
			b = binary.BigEndian.AppendUint16(b, 1)   // class IN
			b = binary.BigEndian.AppendUint32(b, 300) // ttl
			b = binary.BigEndian.AppendUint16(b, 4)   // rdlength 4
			return append(b, 1, 2)                    // only 2 rdata bytes
		}(),
	}

	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseQuery panicked: %v", r)
				}
			}()
			_ = ParseQuery(&msg)
		})
	}
}

func TestParseNilInputs(t *testing.T) {
	if got := ParseQuery(nil); got.header != (Header{}) || got.questions != nil {
		t.Fatalf("ParseQuery(nil) = %+v, want zero Query", got)
	}

	var nilSlice []byte
	if got := ParseQuery(&nilSlice); got.header != (Header{}) || got.questions != nil {
		t.Fatalf("ParseQuery(&nilSlice) = %+v, want zero Query", got)
	}
}
