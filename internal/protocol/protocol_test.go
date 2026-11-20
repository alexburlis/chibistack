package protocol

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadRequestAcceptsOneStrictBoundedFrame(t *testing.T) {
	q, err := ReadRequest(strings.NewReader(`{"op":"deploy","app":"demo","release":"r-1"}` + "\n"))
	if err != nil || q != (Request{Op: Deploy, App: "demo", Release: "r-1"}) {
		t.Fatal(q, err)
	}
	for name, frame := range map[string]string{
		"unterminated":  `{"op":"status","app":"demo"}`,
		"unknown field": `{"op":"status","app":"demo","shell":"id"}` + "\n",
		"trailing data": `{"op":"status","app":"demo"}{}` + "\n",
		"oversized":     `{"op":"status","app":"demo","release":"` + strings.Repeat("a", MaxFrame) + `"}` + "\n",
	} {
		if _, err := ReadRequest(strings.NewReader(frame)); err == nil {
			t.Fatal(name, "request accepted")
		}
	}
}

func TestWriteResponseKeepsFramesWithinBound(t *testing.T) {
	var w bytes.Buffer
	if err := WriteResponse(&w, map[string]string{"event": strings.Repeat("x", MaxFrame)}, nil); err != nil {
		t.Fatal(err)
	}
	response, err := ReadResponse(&w)
	if err != nil || response.OK || response.Error != "response exceeds frame bound" {
		t.Fatal("oversized result left the helper", response, err)
	}
	w.Reset()
	if err = WriteResponse(&w, nil, errors.New("busy; no mutation started")); err != nil {
		t.Fatal(err)
	}
	if response, err = ReadResponse(&w); err != nil || response.OK || response.Error != "busy; no mutation started" {
		t.Fatal(response, err)
	}
}

func TestRequestValidateAppliesTheOperationTable(t *testing.T) {
	for _, q := range []Request{{Op: Status, App: "demo"}, {Op: Deploy, App: "demo", Release: "r-42"}, {Op: Rollback, App: "sample-landing-trial"}} {
		if err := q.Validate(); err != nil {
			t.Fatal(q, err)
		}
	}
	for _, q := range []Request{{Op: "shell", App: "demo"}, {Op: Status, App: "Demo"}, {Op: Rollback, App: "demo", Release: "r-1"}, {Op: Deploy, App: "demo"}, {Op: Deploy, App: "demo", Release: "../r-1"}} {
		if q.Validate() == nil {
			t.Fatal("invalid request accepted", q)
		}
	}
}
