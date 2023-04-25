package runner

import (
	"encoding/json"
	"io"
	"sync"
)

type OutputWriter struct {
	writers []io.Writer
	sync.RWMutex
}

func NewOutputWriter() (*OutputWriter, error) {
	return &OutputWriter{}, nil
}

func (o *OutputWriter) AddWriters(writers ...io.Writer) {
	o.writers = append(o.writers, writers...)
}

func (o *OutputWriter) Write(data []byte) {
	o.Lock()
	defer o.Unlock()
	for _, writer := range o.writers {
		_, _ = writer.Write(data)
		_, _ = writer.Write([]byte("\n"))
	}
}

func (o *OutputWriter) WriteString(data string) {
	o.Write([]byte(data))
}
func (o *OutputWriter) WriteJSON(data Output) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}
	o.Write(jsonData)
}

func (o *OutputWriter) Close() {
	for _, writer := range o.writers {
		if wr, ok := writer.(io.Closer); ok {
			wr.Close()
		}
	}
}
