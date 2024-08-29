package test

import (
	"errors"
	"net"
	"net/http"

	"github.com/go-resty/resty/v2"
)

// getFreePort asks the kernel for a free open port that is ready to use.
func getFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

// waitServer waits (backoff algorithm, 10 attempts) until the server is ready to serve.
func waitServer(address string) error {
	client := resty.New().SetRetryCount(10)
	resp, err := client.R().
		Get(address + "/buildinfo") // wait server ready
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return errors.New("http server returned non-200 status: " + resp.Status())
	}

	return nil
}
