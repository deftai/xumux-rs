// Command interop-peer is libxumux-go's side of xumux-rs's interop test.
//
//	interop-peer serve         listen on TCP, print the address, echo every channel
//	interop-peer dial ADDR     open an echo channel, check messages of many sizes, close
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	xumux "github.com/deftai/libxumux-go"
)

func echo(ch *xumux.Channel) {
	ctx := ch.Session().Context()
	for {
		m, err := ch.Receive(ctx)
		if err != nil {
			return
		}
		if err := ch.Send(ctx, m.Type, m.Payload); err != nil {
			return
		}
	}
}

func serve() error {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	fmt.Println(l.Addr())
	c, err := l.Accept()
	if err != nil {
		return err
	}
	opts := xumux.Options{PingInterval: -1, Acceptor: func(context.Context, xumux.ChannelRequest) (xumux.Handler, error) { return echo, nil }}
	s, _, err := xumux.Accept(context.Background(), xumux.NewStreamConn(c), xumux.ServerConfig{}, opts)
	if err != nil {
		return err
	}
	<-s.Done()
	return nil
}

func dial(addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	s, _, err := xumux.Connect(ctx, xumux.NewStreamConn(c), xumux.ClientConfig{}, xumux.Options{PingInterval: -1})
	if err != nil {
		return err
	}
	ch, err := s.OpenChannel(ctx, xumux.ChannelSpec{Name: "echo", Reliable: true, Ordered: true})
	if err != nil {
		return err
	}
	for _, n := range []int{0, 1, 16385, 65536, 200000} {
		data := bytes.Repeat([]byte{byte(n % 251)}, n)
		if err := ch.Send(ctx, 3, data); err != nil {
			return err
		}
		m, err := ch.Receive(ctx)
		if err != nil {
			return err
		}
		if m.Type != 3 || !bytes.Equal(m.Payload, data) {
			return fmt.Errorf("echo of %d bytes differs", n)
		}
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if err := ch.Send(ctx, 4, bytes.Repeat([]byte{7}, 200000)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 20; i++ {
		if _, err := ch.Receive(ctx); err != nil {
			return err
		}
	}
	if err := <-done; err != nil {
		return err
	}
	if _, err := ch.Ping(ctx); err != nil {
		return err
	}
	if err := ch.Close(ctx, 1000, ""); err != nil {
		return err
	}
	return s.Close(ctx, 1000, "")
}

func main() {
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "dial":
		err = dial(os.Args[2])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
