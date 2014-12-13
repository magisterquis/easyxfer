/*
 * easyxfer.go
 * program to catch files sent to a port and save them.
 * by J. Stuart McMurray
 * created 20141206
 * last modified 20141210
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
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
)

var (
	port         int               = 4567 /* Default port */
	cert         []byte                   /* SSL cert */
	key          []byte                   /* SSL key */
	knownHashes  map[string]string        /* Known peer hashes */
	printVerbose *bool                    /* Verbose output */
	printDebug   *bool                    /* Debug output */
	rcfile       *string                  /* Config file */
)

func main() { os.Exit(mymain()) }
func mymain() int {
	/* Better usage() */
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %v [flags] [address] [file]\n",
			os.Args[0])
		fmt.Fprintf(os.Stderr, `
Listen on address, or if that fails connect to address, or if that fails,
listen on the default port (%v) and wait for a file to be sent.  If file is
specified, or if not but data is provided on the standard input, send that
to the remote end.

Examples:
	Send a file named README to foo.com: %v foo.com README
	Wait for a connection, send an SSH key: %v ~/.ssh/id_rsa.pub
	Send the current time to localhost: date | %v -c localhost
	Listen on a specific address: %v 192.168.1.33:31337

`, port, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags are as follows: \n")
		flag.PrintDefaults()
	}

	/* Default RC file */
	if r, err := homedir.Expand("~/.easyxferrc"); nil != err {
		fmt.Fprintf(os.Stderr, "Unable to determine default config "+
			"file name: %v", err)
		f := ""
		rcfile = &f
	} else {
		rcfile = &r
	}

	/* Command-line flags */
	max := flag.Int("m", 1024*1024*1024, "Max receive file size in bytes")
	printVerbose = flag.Bool("v", false, "Print informational output")
	printDebug = flag.Bool("d", false, "Print more output than -v.  "+
		"Implies -v")
	listen := flag.Bool("l", false, "Force listening (or exit if "+
		"listening fails.")
	connect := flag.Bool("c", false, "Force connection (or exit if "+
		"connecting fails")
	rcfile := flag.String("conf", *rcfile, "Config file")
	tcp4 := flag.Bool("4", false, "Force IPv4")
	tcp6 := flag.Bool("6", false, "Force IPv6")

	/* TODO: Clean up string */
	flag.Parse()

	/* Can't listen and connect */
	if *listen && *connect {
		fmt.Fprintf(os.Stderr, "Cannot use both -l and -c.\n")
		flag.Usage()
		return -3
	}
	/* Can't connect without a host */
	if *connect && 0 == flag.NArg() {
		fmt.Fprintf(os.Stderr, "Can't forceably connect without a "+
			"specified host.")
		return -5
	}

	/* Work out the IP version to use */
	tcpv := "tcp"
	switch {
	case true == *tcp4 && true == *tcp6:
		debug("Use of -4 and -6 constitutes an excessive use of " +
			"force")
		break
	case *tcp4:
		tcpv = "tcp4"
	case *tcp6:
		tcpv = "tcp6"
	}

	/* Load the RC file */
	debug("Loading config file %v", *rcfile)
	if err := loadRC(*rcfile); err != nil {
		log.Printf("Unable to load config file: %v\n", err)
		log.Printf("Generating temporary keypair")
		cert, key, err = generateCert()
		if nil != err {
			log.Printf("Unable to generate temporary keypair: %v",
				err)
			return -2
		}
	} else {
		verbose("Read %v", *rcfile)
	}

	/* TLS config */
	conf := &tls.Config{
		Certificates:       make([]tls.Certificate, 1),
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	if err := ioutil.WriteFile("cert", cert, 0600); nil != err {
		log.Printf("Could not output cert") /* DEBUG */
	}
	if err := ioutil.WriteFile("key", key, 0600); nil != err {
		log.Printf("Could not output key") /* DEBUG */
	}
	/* TLS KeyPair */
	if keypair, err := tls.X509KeyPair(cert, key); nil != err {
		log.Printf("Unable to parse keypair: %v", err)
		return -1
	} else {
		conf.Certificates[0] = keypair
		xCert, err := x509.ParseCertificate(
			keypair.Certificate[len(keypair.Certificate)-1])
		if err != nil {
			log.Printf("Unable to parse own certificate: %v", err)
			return -11
		}
		mhash, shash, cname := extractInfo(xCert)
		log.Printf("Local Common Name: %v", cname)
		log.Printf("   Local MD5 Hash: %v", mhash)
		log.Printf("Local SHA512 Hash: %v", shash)
		log.Printf("These should match what the other end sees " +
			"as the remote hashes after the connection is " +
			"established")
	}

	/* The other end */
	var peer *tls.Conn
	/* True if we ended up using the argument as an address */
	usedArg := false

	/* Make a connection */
	if flag.NArg() > 0 {
		var err error
		/* Make sure we have a port */
		addr, err := addPort(flag.Arg(0))
		/* If there's another argument, this must have been an
		address, so give up */
		if nil != err && 1 != flag.NArg() {
			log.Printf("Unable to parse %v as an address: %v",
				flag.Arg(0), err)
			return -6
		}
		/* If there's only one argument, assume it's a file */
		if nil != err {
			verbose("Unable to parse %v as an address, "+
				"assuming it's a file name: %v",
				flag.Arg(0), err)
			goto ListenDefault
		}
		/* Try to listen if we're allowed */
		if !*connect {
			peer, err = accept(tcpv, addr, conf)
			if nil != err {
				debug("Unable to get connection on %v: %v",
					addr, err)
			} else { /* It worked */
				usedArg = true
				goto GotPeer
			}

		}
		/* Try to connect if we're allowed */
		if !*listen {
			debug("Attempting to connect to %v", addr)
			peer, err = tls.Dial(tcpv, addr, conf)
			if nil == err {
				log.Printf("Connected to %v",
					peer.RemoteAddr())
				usedArg = true
				goto GotPeer
			}
			debug("Unable to connect to %v", err)
		}

	}
ListenDefault:
	/* At this point, if we've failed and there's two arguments (i.e. an
	address was given, give up */
	if flag.NArg() > 1 {
		log.Printf("Unable to listen on or connect to %v", flag.Arg(0))
		return -7
	}
	if *connect {
		log.Printf("Unable to connect to %v, and -c specified.",
			flag.Arg(0))
		return -8
	}
	if p, err := accept(tcpv, net.JoinHostPort("", strconv.Itoa(port)),
		conf); nil != err {
		log.Printf("Unable to listen and accept connection on "+
			"default port (%v): %v", port, err)
		return -9
	} else {
		peer = p
	}

GotPeer:
	/* At this point, we have a connection with someone.  Handshake. */
	if err := peer.Handshake(); nil != err {
		log.Printf("Unable to perform TLS handshake with %v: %v",
			peer.RemoteAddr(), err)
		return -4
	}
	/* Make sure the peer has a certificate */
	if len(peer.ConnectionState().PeerCertificates) < 1 {
		log.Printf("Peer did not present a certificate.")
		return -10
	}
	/* Get Peer's certificate, hash it */
	nPeerCert := len(peer.ConnectionState().PeerCertificates)
	peerCert := peer.ConnectionState().PeerCertificates[nPeerCert-1]

	mhash, shash, cname := extractInfo(peerCert)
	/* Check if the hash is already known */
	if mhash+shash == knownHashes[cname] {
		/* If so we're good */
		log.Printf("Found known hash for %v", cname)
	} else {
		/* If not, print the details */
		log.Printf("Unknown remote end")
		log.Printf("Remote Common Name: %v", cname)
		log.Printf("   Remote MD5 Hash: %v", mhash)
		log.Printf("Remote SHA512 Hash: %v", shash)
		/* If stdin is a terminal, ask if it's ok */
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			log.Printf("Unable to ask permission to continue.  "+
				"Please use the following line to add the "+
				"above hashes to %v:", *rcfile)
			fmt.Fprintf(os.Stderr, "\necho %v=%v%v >> %v\n\n",
				cname, mhash, shash, *rcfile)
			return -13
		}
		fmt.Fprintf(os.Stderr, "Would you like to continue (and add "+
			"this to %v)? [no] ", *rcfile)
		/* Get a line from stdin */
		l, p, e := bufio.NewReader(os.Stdin).ReadLine()
		if nil != e { /* Can't read stdin? */
			log.Printf("Unable to read from stdin: %v", e)
			return -12
		} else if (0 == len(l) && !p) /* Default */ ||
			strings.HasPrefix(strings.ToLower(string(l)), "y") {
			/* Write it */
			f, err := os.OpenFile(*rcfile,
				os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
			if nil != err {
				log.Printf("Unable to open %v to add %v: %v",
					*rcfile, cname, err)
				goto OpenTXFile
			}
			h := []byte(fmt.Sprintf("\n%v=%v%v\n",
				cname, mhash, shash))
			if n, err := f.Write(h); err != nil {
				log.Printf("Error updating %v: %v",
					*rcfile, err)
			} else if n < len(h) {
				log.Printf("Only wrote %v/%v bytes to %v", n,
					len(h), *rcfile)
			}
			if err := f.Close(); nil != err {
				verbose("Error closing %v: %v", *rcfile, err)
			}
		} else { /* No */
			return -14
		}
	}

OpenTXFile:
	txfname := ""             /* Name of file to send */
	var txfile *os.File = nil /* File struct representing file to send */
	var txsize int64 = 0      /* Size of file to transmit */
	var err error = nil
	ttyIn := terminal.IsTerminal(int(os.Stdin.Fd())) /* Terminal input */

	/* Debugging message for whether input is a terminal */
	if ttyIn {
		debug("Stdin is a terminal")
	} else {
		debug("Stdin is not a terminal")
	}

	/* Open the file to send, if we have one */
	if 0 == flag.NArg() || /* No filename or address given */
		(1 == flag.NArg() && usedArg) { /* Only address given */
		/* Don't send terminal input */
		if ttyIn {
			debug("No filename given and no data to read from " +
				"standard input.")
			txfile = nil
			goto Handshake
		} else {
			log.Printf("Sending data from standard input")
			txfile = os.Stdin
		}
	} else if 1 == flag.NArg() && !usedArg {
		txfname = flag.Arg(0)
		txfile, err = os.Open(flag.Arg(0))
	} else if flag.NArg() > 1 {
		txfname = flag.Arg(1)
		txfile, err = os.Open(flag.Arg(1))
	}
	if nil != err {
		log.Printf("Will not send %v because opening file failed: %v",
			txfname, err)
		txfile = nil /* For just in case */
		goto Handshake
	}
	verbose("File to send: %v", txfile.Name())

	/* Get file size */
	/* TODO: Function this */
	txsize, err = txfile.Seek(0, os.SEEK_END)
	if nil != err {
		verbose("Unable to determine size of %v: %v",
			txfile.Name(), err)
		txsize = -1
	} else {
		/* Put the pointer back at the beginning */
		if _, err := txfile.Seek(0, os.SEEK_SET); nil != err {
			log.Printf("Unable to rewind %v: err", txfile.Name(),
				err)
			return -24
		}
	}
Handshake:
	/* Tell the other end what to expect */
	/* Format: Filesize filename [message] */
	if nil == txfile {
		if err := writeString(peer, "NO\n"); nil != err {
			log.Printf("Unable to handshake with NO: %v", err)
			return -16
		}
	} else {
		if err := writeString(peer, fmt.Sprintf("%v %v\n", txsize,
			path.Base(txfile.Name()))); nil != err {
			log.Printf("Unableto send handshake: %v", err)
			return -17
		}
	}

	rxfname := ""                        /* Received filename */
	rxsize := 0                          /* Received filesize */
	rxmessage := ""                      /* Message from peer */
	var peerLineReader *textproto.Reader /* Read from peer by lines */
	/* Make a linewise reader from the peer */
	peerLineReader = textproto.NewReader(bufio.NewReader(peer))
	/* Read a string from the input */
	rxinfo, err := peerLineReader.ReadLine()
	debug("Handshake: %v", rxinfo)
	if nil != err {
		log.Printf("Error reading handshake: %v", err)
		return -18
	}
	/* If we got a blank line assume something funny is happening */
	if 0 == len(rxinfo) {
		log.Printf("Empty handshake received")
		return -19
	}
	/* Extract size and filename */
	rxinfoparts := strings.SplitN(rxinfo, " ", 3)
	/* Nothing to receive */
	if "NO" == rxinfoparts[0] {
		/* Maybe a message? */
		if len(rxinfoparts) > 1 {
			rxmessage = strings.Join(rxinfoparts[1:], " ")
		}
		goto PrepareOutput
	}
	/* Make sure we at least have a name and length */
	if len(rxinfoparts) < 2 {
		/* Don't print more than 80 characters */
		rs := []rune(rxinfo)
		if len(rs) > 80 {
			rs = rs[:80]
		}
		verbose("Handshake too short: %v", strconv.Quote(string(rs)))
		return -20
	}
	/* Get file size */
	rxsize, err = strconv.Atoi(rxinfoparts[0])
	if nil != err {
		log.Printf("File size of incoming file unparseable: %v", err)
		return -21
	}
	/* If file size to receive is too large, bail */
	if rxsize > *max {
		log.Printf("Incoming file (%v bytes) is larger than %v "+
			"(see -max).", rxsize, *max)
		return -25
	}
	/* Sanitize the file name */
	rxfname = strings.Map(func(r rune) rune {
		/* Whitelist some characters */
		if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
			"abcdefghijklmnopqrstuvwxyz"+
			"01234567890-_+.,", r) {
			return r
		}
		/* Unsafe characters are converted to . */
		return '.'
	}, path.Base(rxinfoparts[1]))
	/* Save the message, if there is one */
	if 3 == len(rxinfoparts) {
		rxmessage = rxinfoparts[2]
	}

	/* Process
	/* Print a message, if we have one */
	if 0 != len(rxmessage) {
		log.Printf("Received message: %v", rxmessage)
	}

PrepareOutput:
	var rxfile *os.File = nil /* Output file */
	if "" == rxfname {
		goto WaitForReady
	}
	/* Write to stdout if it's not a tty */
	if !terminal.IsTerminal(int(os.Stdout.Fd())) {
		rxfile = os.Stdout
	}
	/* Try the given name first */
	rxfile, err = os.OpenFile(rxfname,
		os.O_CREATE|os.O_APPEND|os.O_RDWR|os.O_EXCL, 0644)
	if nil != err {
		log.Printf("Unable to create %v: %v", rxfname, err)
	}
	/* Try different filenames until we have a new one */
	/* TODO: Unhardcode this */
	for ext := 0; nil == rxfile && ext < 1000; ext++ {
		/* Append a number to prevent extension-based attacks */
		ofname := fmt.Sprintf("%v.%03v", rxfname, ext)
		if _, err := os.Stat(ofname); os.IsNotExist(err) {
			/* Create the file */
			var err error
			rxfile, err = os.OpenFile(ofname,
				os.O_CREATE|os.O_APPEND|os.O_RDWR|os.O_EXCL,
				0644)
			if nil != err {
				log.Printf("Unable to create %v: %v", err)
				return -15
			}
		}
	}
	/* If we've still failed, give up */
	if nil == rxfile {
		log.Printf("Gave up after trying 1000 different names")
		return -26
	}

WaitForReady:
	/* Give up if we're both NOs */
	if nil == txfile && nil == rxfile {
		log.Printf("No files to send or receive")
		return 0
	}
	/* Tell peer we're ready */
	writeString(peer, "READY\n")
	verbose("Waiting for the remote end to be ready")

	/* Wait for the peer to be ready */
	if false { /* DEBUG */
		buf := make([]byte, 100)
		n, err := peer.Read(buf)
		if nil != err {
			log.Printf("DEBUG Error: %v", err)
		} else {
			log.Printf("Got %v bytes: %v", n, string(buf))
		}
	}
	if ready, err := peerLineReader.ReadLine(); nil != err {
		log.Printf("Error waiting for the ready message: %v", err)
		return -22
	} else if "READY" != ready { /* Make sure it's the right message */
		/* Shorten to 80 characters */
		rs := []rune(ready)
		if len(rs) > 80 {
			rs = rs[:80]
		}
		log.Printf("Got a bad ready message: %v", string(rs))
		return -23
	}
	debug("Everybody's ready")

	/* Channels to get results of sending and receiving */
	var txout chan string = nil
	var txerr chan error = nil

	/* Send file if we have one */
	if nil != txfile {
		txout = make(chan string, 1)
		txerr = make(chan error, 1)
		go func() {
			defer close(txout)
			defer close(txerr)
			/* Send the file */
			txspeed, err := sendFile(peer, txfile, int(txsize))
			/* If there was an error, send it back */
			if err != nil {
				txerr <- err
				return
			}
			/* Send the speed back otherwise */
			txout <- txspeed
		}()
	}

	/* Receive file if we didn't get a NO */
	if "" != rxfname {
		/* Receive the file */
		rxspeed, err := recvFile(peer, rxfile, rxsize)
		fmt.Printf("\n")

		/* Tell the user how it went */
		if nil != err {
			log.Printf("Error receiving %v: %v", rxfile.Name(), err)
		} else {
			log.Printf("Received %v", rxspeed)
		}
	} else {
		fmt.Printf("\n")
	}

	/* If we're also sending, print a message about that, too */
	if nil != txfile {
		/* Wait for the error channel to have something to read or
		to be closed, indicating no error */
		err, ok := <-txerr
		/* If we got an error, print that */
		if ok {
			log.Printf("Error sending %v: %v", txfile.Name(), err)
		} else { /* If not, print the speed */
			txspeed := <-txout
			log.Printf("Sent %v", txspeed)
		}
	}

	log.Printf("All done.  Thank you for using easyxfer.")
	return 0
}

/* loadRC loads the file that has the cert, key, and list of known hosts */
func loadRC(fname string) error {
	/* Make knownHashes if needed */
	if nil == knownHashes {
		knownHashes = make(map[string]string)
	}
	/* Open the file */
	f, err := os.OpenFile(fname, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("unable to open file: %v", err)
	}

	scanner := bufio.NewScanner(f)
	/* Read lines from the file */
	for scanner.Scan() {

		/* Trim whitespace */
		line := strings.TrimSpace(scanner.Text())
		/* Ignore comments and empty lines */
		if 0 == len(line) || strings.HasPrefix(line, "#") {
			continue
		}

		/* Split into key/value pairs */
		kv := strings.SplitN(scanner.Text(), "=", 2)
		if len(kv) < 2 {
			verbose("Erroneous line in config file: %v", line)
			continue
		}

		/* Save line */
		debug("Read %v from %v", kv[0], fname)
		switch kv[0] {
		case "ezx_cert":
			/* TODO: Check that data is parseable */
			data, err := base64.StdEncoding.DecodeString(kv[1])
			if nil != err {
				log.Printf("Unparsable ezx_cert line in "+
					"config file: %v", err)
				continue
			}
			/* Warn on multiples */
			if 0 != len(cert) {
				verbose("Extra cert found in %v.  Will use "+
					"the last one in the file.", fname)
			}
			cert = data
		case "ezx_key":
			/* TODO: Check that data is parseable */
			data, err := base64.StdEncoding.DecodeString(kv[1])
			if nil != err {
				log.Printf("Unparsable ezx_key line in "+
					"config file: %v", err)
				continue
			}
			/* Warn on multiples */
			if 0 != len(key) {
				verbose("Extra key found in %v.  Will use "+
					"the last one in the file.", fname)
			}
			key = data
		default:
			/* TODO: Check size of kv[1] */
			knownHashes[kv[0]] = kv[1]
		}
	}
	/* If we have neither a cert nor a key, generate them */
	if 0 == len(cert) && 0 == len(key) {
		verbose("No keypair found, generating and saving to %v", fname)
		cert, key, err = generateCert()
		if nil != err {
			return fmt.Errorf("unable to generate keypair: %v",
				err)
		}
		fmt.Fprintf(f, "\nezx_cert=%v\n",
			base64.StdEncoding.EncodeToString(cert))
		fmt.Fprintf(f, "ezx_key=%v\n",
			base64.StdEncoding.EncodeToString(key))
	}

	/* Give up if we still lack a key or cert */
	if 0 == len(key) {
		return fmt.Errorf("no key found")
	}
	if 0 == len(cert) {
		return fmt.Errorf("no cert found")
	}

	return nil
}

/* Print an informational message */
func verbose(f string, a ...interface{}) {
	if *printVerbose || *printDebug {
		log.Printf(f, a...)
	}
}

/* Print a debugging message */
func debug(f string, a ...interface{}) {
	if *printDebug {
		log.Printf(f, a...)
	}
}
