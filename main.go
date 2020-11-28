package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

func main() {
	ls, err := net.Listen("tcp", ":1080")
	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}

	for {
		conn, err := ls.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v\n", err)
			continue
		}
		go process(conn)
	}
}

func process(conn net.Conn) {
	if err := Socks5Auth(conn); err != nil {
		fmt.Println("Auth error: ", err)
		conn.Close()
		return
	}
	target, err := Socks5Connect(conn)
	if err != nil {
		fmt.Println("Connect error: ", err)
		conn.Close()
		return
	}

	Socks5Forward(conn, target)
}

func Socks5Auth(conn net.Conn) (err error) {
	buf := make([]byte, 256)
	n, err := io.ReadFull(conn, buf[:2])
	if n != 2 {
		return errors.New("read header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	n, err = io.ReadFull(conn, buf[:nMethods])
	if n != nMethods {
		return errors.New("read methods: " + err.Error())
	}

	n, err = conn.Write([]byte{0x05, 0x00})
	if n != 2 {
		return errors.New("write rsp err: " + err.Error())
	}
	return nil
}

func Socks5Connect(conn net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)
	n, err := io.ReadFull(conn, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}
	ver, cmd, _, atype := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := ""
	switch atype {
	case 1:
		n, err = io.ReadFull(conn, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid ipv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	case 3:
		n, err := io.ReadFull(conn, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])
		n, err = io.ReadFull(conn, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4:
		return nil, errors.New("ipv6: no supported yet")

	default:
		return nil, errors.New("invalid atype")
	}

	n, err = io.ReadFull(conn, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	n, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}
	return dest, nil
}

func Socks5Forward(conn, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}

	go forward(conn, target)
	go forward(target, conn)
}
