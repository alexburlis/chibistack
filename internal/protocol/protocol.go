// Package protocol is the contract between the unprivileged hostmcp and the root
// hostctl helper: the operations, the identifier grammar and one bounded JSON
// frame each way.
package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
)

const (
	Status           = "status"
	DeploymentStatus = "deployment_status"
	Logs             = "logs"
	Health           = "health"
	Deploy           = "deploy"
	Rollback         = "rollback"
)

type Op struct {
	Name         string
	ReadOnly     bool
	TakesRelease bool
}

var Ops = []Op{
	{Name: Status, ReadOnly: true},
	{Name: DeploymentStatus, ReadOnly: true},
	{Name: Logs, ReadOnly: true},
	{Name: Health, ReadOnly: true},
	{Name: Deploy, TakesRelease: true},
	{Name: Rollback},
}

func Lookup(name string) (Op, bool) {
	i := slices.IndexFunc(Ops, func(op Op) bool { return op.Name == name })
	if i < 0 {
		return Op{}, false
	}
	return Ops[i], true
}

// NamePattern is the grammar of application names and of release identifiers.
const NamePattern = `^[a-z][a-z0-9-]{0,31}$`

var name = regexp.MustCompile(NamePattern)

func ValidName(s string) bool { return name.MatchString(s) }

const MaxFrame = 4096

type Request struct {
	Op      string `json:"op"`
	App     string `json:"app"`
	Release string `json:"release,omitempty"`
}

type Response struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

var ErrNotPermitted = errors.New("operation is not permitted")

func (q Request) Validate() error {
	op, ok := Lookup(q.Op)
	if !ok {
		return ErrNotPermitted
	}
	if !ValidName(q.App) {
		return errors.New("invalid application name")
	}
	if !op.TakesRelease && q.Release != "" {
		return errors.New("unexpected release argument")
	}
	if op.TakesRelease && !ValidName(q.Release) {
		return errors.New("invalid release identifier")
	}
	return nil
}

func DecodeStrict(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func WriteRequest(w io.Writer, q Request) error {
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxFrame {
		return errors.New("request exceeds frame bound")
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func ReadRequest(r io.Reader) (Request, error) {
	var q Request
	line, err := bufio.NewReaderSize(r, MaxFrame+1).ReadSlice('\n')
	if err != nil || len(line) > MaxFrame {
		return q, errors.New("helper requires one bounded newline-terminated JSON request")
	}
	err = DecodeStrict(line, &q)
	return q, err
}

func WriteResponse(w io.Writer, result any, err error) error {
	response := Response{OK: err == nil}
	if err != nil {
		response.Error = err.Error()
	} else if response.Data, err = json.Marshal(result); err != nil {
		return err
	}
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxFrame {
		b, _ = json.Marshal(Response{Error: "response exceeds frame bound"})
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadResponse reads until the helper closes the stream after its one frame.
func ReadResponse(r io.Reader) (Response, error) {
	var response Response
	b, err := io.ReadAll(io.LimitReader(r, MaxFrame+1))
	if err != nil {
		return response, err
	}
	if len(b) > MaxFrame {
		return response, errors.New("response exceeds frame bound")
	}
	err = DecodeStrict(b, &response)
	return response, err
}
