package dns

type Server struct {
}

func NewServer() *Server {
	return &Server{}
}

func (q *Server) HandleRequest(request Query) Query {
	var r = request
	if len(r.answer.content) > 0 {
		println("Non-Zero answer")
	}
	panic("Not implemented HandleRequest")
}
