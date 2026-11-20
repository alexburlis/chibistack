package main

import "testing"

func TestHTTPContract(t *testing.T) {
	if err := selfTest(); err != nil {
		t.Fatal(err)
	}
}
