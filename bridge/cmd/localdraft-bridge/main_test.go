package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestWriteStartupURL(t *testing.T) {
	var output bytes.Buffer
	if err := writeStartupURL(&output, "https://127.0.0.1:4782/api/session?token=abc_DEF-123"); err != nil {
		t.Fatal(err)
	}

	const expected = "https://127.0.0.1:4782/api/session?token=abc_DEF-123\n"
	if output.String() != expected {
		t.Fatalf("startup URL output = %q, want %q", output.String(), expected)
	}
}

func TestRemovedOpenFlagsAreRejected(t *testing.T) {
	for _, removedFlag := range []string{"--open", "--no-open"} {
		t.Run(removedFlag, func(t *testing.T) {
			readEnd, writeEnd, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			originalStdout := os.Stdout
			os.Stdout = writeEnd
			err = run([]string{"serve", "--listen", "127.0.0.1:0", removedFlag})
			os.Stdout = originalStdout
			if closeErr := writeEnd.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			output, readErr := io.ReadAll(readEnd)
			if closeErr := readEnd.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if err == nil {
				t.Fatalf("run accepted removed flag %s", removedFlag)
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") || !strings.Contains(err.Error(), strings.TrimLeft(removedFlag, "-")) {
				t.Fatalf("run error = %q, want undefined flag error for %s", err, removedFlag)
			}
			if len(output) != 0 {
				t.Fatalf("run wrote stdout for removed flag %s: %q", removedFlag, output)
			}
		})
	}
}

type errorWriter struct {
	err error
}

func (writer errorWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func TestWriteStartupURLReturnsWriterError(t *testing.T) {
	expected := errors.New("stdout unavailable")
	err := writeStartupURL(errorWriter{err: expected}, "https://127.0.0.1:4782/api/session?token=abc_DEF-123")
	if !errors.Is(err, expected) {
		t.Fatalf("writeStartupURL error = %v, want %v", err, expected)
	}
}
