package dns

import "log"

type Server struct {
	providers []ResourceProvider
}

func NewServer(providers ...ResourceProvider) *Server {
	return &Server{
		providers: providers,
	}
}

func (q *Server) HandleRequest(request Query) Query {
	answers := make([]ResourceRecord, 0)
	for _, question := range request.questions {
		answer := q.getAnswers(question)
		answers = append(answers, answer...)
	}
	response := Query{
		header: Header{
			id:      request.header.id,
			qr:      true,
			aa:      true,
			ra:      true,
			qdcount: request.header.qdcount,
			ancount: uint16(len(answers)),
		},
		questions: request.questions,
		answer: Answer{
			content: answers,
		},
	}
	return response
}

func (q *Server) getAnswers(question Question) []ResourceRecord {
	var answers []ResourceRecord
	log.Println("Question type:", question.Qtype)
	switch question.Qtype {
	case 0x0001:
		answers = q.getARecords(question)
	}
	return answers
}

func (q *Server) getARecords(question Question) []ResourceRecord {
	log.Println("Handling A Record")
	answers := make([]AnswerRecord, 0)
	for _, provider := range q.providers {
		answers = append(answers, provider.GetRecord(question)...)
	}
	converter := func(answerRecord AnswerRecord) ResourceRecord {
		return ResourceRecord{
			name:       []byte(question.Qname),
			recordType: 0x0001,
			class:      0x0001,
			ttl:        answerRecord.Ttl,
			rdlength:   uint16(len(answerRecord.Response)),
			rdata:      answerRecord.Response,
		}
	}

	resources := make([]ResourceRecord, len(answers))
	for i, answer := range answers {
		resources[i] = converter(answer)
	}

	return resources
}
