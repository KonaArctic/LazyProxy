package main

import "bufio"
import "errors"
import "golang.org/x/net/proxy"
import "io"
import "net"
import "net/http"
import "net/url"

// Oddly, x/net/proxy doesnt support HTTP proxies
func init() {
	proxy.RegisterDialerType("http", func(proxyUrl *url.URL, dialer proxy.Dialer) (proxy.Dialer, error) {
		return httpProxy{
			proxyUrl: *proxyUrl,
			dialer:   dialer,
		}, nil
	})
}

type httpProxy struct {
	proxyUrl url.URL
	dialer   proxy.Dialer
}

func (self httpProxy) Dial(network string, address string) (net.Conn, error) {
	var err error
	var stream io.ReadWriteCloser
	stream, err = self.dialer.Dial("tcp", self.proxyUrl.Host)
	if err != nil {
		return nil, err
	}
	var reader bufio.Reader
	reader = *bufio.NewReader(stream)
	err = (&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: address,
		},
		Header: map[string][]string{},
	}).WriteProxy(stream)
	if err != nil {
		return nil, err
	}
	var respon *http.Response
	respon, err = http.ReadResponse(&reader, nil)
	if err != nil {
		return nil, err
	}
	if respon.StatusCode/100 != 2 {
		return nil, errors.New(respon.Status)
	}
	return fakeConn{
		Reader: &reader,
		Writer: stream,
		Closer: stream,
	}, nil
}
