/*
 *
 * Copyright (c) 2012 J. Stuart McMurray. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package main

import (
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"github.com/pivotal-golang/bytefmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	defTransferChunk int = 1024 * 1024 /* Character printed every this */
)

/* Add the default port if need be */
func addPort(addr string) (string, error) {
	_, _, err := net.SplitHostPort(addr)
	if nil != err && strings.HasPrefix(err.Error(),
		"missing port in address") { /* Needs default port */
		return net.JoinHostPort(addr, strconv.Itoa(port)), nil
	} else if nil != err { /* May not be an IP address */
		return "", err
	}
	return addr, nil
}

/* Listen and get a TLS client */
func accept(tcpv, addr string, conf *tls.Config) (*tls.Conn, error) {
	debug("Attempting to %v listen on %v", tcpv, addr)
	l, err := tls.Listen(tcpv, addr, conf)
	if nil != err {
		return nil, fmt.Errorf("listen failed on %v: %v", addr, err)
	}
	log.Printf("Listening on %v for a connection", l.Addr())
	/* Close listener when we're done */
	defer func() {
		if err := l.Close(); nil != err {
			debug("Unable to close listener: %v", err)
		}
	}()
	/* Wait for a client */
	client, err := l.Accept()
	if nil != err {
		return nil, fmt.Errorf("error while waiting for "+
			"connection: %v", err)
	}
	log.Printf("Connection from %v", client.RemoteAddr())
	t, ok := client.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("unable to make connection an SSL " +
			"connection")
	}
	return t, nil
}

/* Write all the bytes to a writer */
func writeAll(c io.Writer, b []byte) error {
	nsent := 0    /* Bytes sent so far */
	tot := len(b) /* Total number of bytes to send */
	for nsent < tot {
		/* Try to send the rest of the message */
		n, err := c.Write(b[nsent:])
		if nil != err {
			return err
		}
		if n+nsent < tot {
			debug("Wrote %v+%v=%v/%v bytes.  May need to adjust "+
				"buffer size.", n, nsent, n+nsent, tot)
		}
		nsent += n
	}
	return nil
}

/* writeString writes an entire string to the network connection */
func writeString(c net.Conn, s string) error {
	return writeAll(c, []byte(s))
}

/* Send size bytes of f to c.  If size is -1, all of f is sent (i.e. if f is
stdin).  The returned string will be a success message. */
func sendFile(c net.Conn, f *os.File, size int) (string, error) {
	/* Send the file */
	hash, overall, err := xferBytes(c, f, size, 'S')
	if nil != err {
		return "", err
	}
	/* Send the SHA512 hash */
	if err := writeString(c,
		fmt.Sprintf("%X", hash)); nil != err {
		return "", err
	}
	return overall, nil
}

/* Receive at most max bytes into f from c */
func recvFile(c net.Conn, f *os.File, size int) (string, error) {
	/* Receive the file */
	xfhash, overall, err := xferBytes(f, c, size, 'R')
	if nil != err {
		return "", nil
	}
	/* Pull the hash off the wire */
	hchar := 2 * sha512.Size         /* Length of the hash in hex digits */
	rxhash := make([]byte, 0, hchar) /* Buffer to hold the hash */

	/* Read bytes until we have all the hash */
	for len(rxhash) < hchar {
		/* Make a buffer the size of the rest of the hash */
		buf := make([]byte, hchar-len(rxhash))
		/* Try to read the rest */
		if _, err := c.Read(buf); nil != err {
			return "", err
		}
		/* Save the bit we got */
		rxhash = append(rxhash, buf...)
	}

	/* If the hashes don't match, tell someone */
	debug("XF Hash: %v", string(xfhash)) /* DEBUG */
	debug("RX Hash: %v", string(rxhash)) /* DEBUG */
	if string(rxhash) != fmt.Sprintf("%X", xfhash) {
		return "", fmt.Errorf("hash mismatch (downloaded " +
			"incorrect/insufficient data)")
	}

	return overall, nil
}

/* xferBytes sends bytes from src to dest, and returns the sha256 hash of the
copied bytes.  Every 1/100th (or 1MB TODO: unhardcode this) pc
is printed to stderr.  Every 10th send, pc is printed to stderr
along with a friendly message indicating progress.  The SHA256 hash of the data
is returned, as well as a string giving the overall transfer size and rate.  No
more than size bytes will be transferred. */
func xferBytes(dst io.Writer, src io.Reader, size int,
	pc rune) (hash []byte,
	overall string, err error) {
	var cent int = 0    /* 1/100 of the size, used for reporting progress */
	nsent := 0          /* Number of bytes sent */
	sha := sha512.New() /* Hasher */
	var buf []byte      /* IO buffer */
	sizestr := ""       /* Pretty-printed size */

	/* Work out reporting number */
	if size < 0 {
		cent = defTransferChunk
	} else {
		cent = size / 100
		sizestr = bytefmt.ByteSize(uint64(size))
	}
	/* Make cent a multiple of the blocksize */
	cent = int(sha.BlockSize() * int(math.Ceil(
		(float64(cent) / float64(sha.BlockSize())))))
	debug("Will transfer (%c) in %v-byte chunks", pc, cent)

	/* Try to transfer cent bytes every time */
	buf = make([]byte, cent)

	/* Start time */
	start := time.Now()

	/* Send until we're done */
	for iter := 0; int(nsent) < size; iter++ {
		var n int
		/* Make sure buf won't read too much */
		if size-(nsent+len(buf)) < 0 {
			buf = make([]byte, size-nsent)
		}
		/* Read from the source */
		n, err = src.Read(buf)
		/* Expected end, not really an error */
		if io.EOF == err {
			err = nil
			break
		} else if nil != err {
			return
		}
		/* Update the hash */
		if _, err = sha.Write(buf[:n]); err != nil {
			return
		}
		/* Send to the dst */
		err = writeAll(dst, buf[:n])
		if nil != err {
			return
		}
		nsent += n
		/* Every 10th iteration, print an update */
		if 0 == iter%10 {
			/* If we know the size */
			if -1 != size {
				fmt.Fprintf(os.Stderr, "(%c-%v/%v-%.1f%%-%v)",
					pc,
					bytefmt.ByteSize(uint64(nsent)),
					sizestr,
					float64(nsent)/float64(size)*100,
					speed(start, nsent))
			} else { /* Unknown size */
				fmt.Fprintf(os.Stderr, "(%c-%v-%v)",
					pc, nsent, speed(start, nsent))
			}
		} else {
			fmt.Fprintf(os.Stderr, "%c", pc)
		}
	}
	end := time.Now()
	/* Overall transfer speed */
	finalSpeed := calcSpeed(start, end, nsent)
	if nsent < 0 {
		err = fmt.Errorf("cannot have transferred a negative "+
			"number of bytes (%v)", nsent)
		return
	}
	overall = fmt.Sprintf("%v (%v) in %v (%v)",
		bytefmt.ByteSize(uint64(nsent)), nsent,
		end.Sub(start), finalSpeed)
	hash = sha.Sum([]byte{})

	return
}

/* Pretty-print the speed of transfer */
func speed(start time.Time, nsent int) string {
	return calcSpeed(start, time.Now(), nsent)
}

/* Calculate a speed from two times and a size */
func calcSpeed(start, end time.Time, nsent int) string {
	return bytefmt.ByteSize(uint64(
		float64(nsent)/
			end.Sub(start).Seconds())) + "/s"
}
