// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa-vault is a two-factor authentication agent using vault as a backend. It allows
// you to share a OTP codes to shared accounts with others in your organization.
// It is based on 2fa by rsc (https://github.com/rsc/2fa)
//
// Usage:
//
//	2fa-vault -add [-7] [-8] [-hotp] name
//	2fa-vault -list
//	2fa-vault name
//
// “2fa-vault -add name” adds a new key to the 2fa-vault keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa-vault -list” lists the names of all the keys in the keychain.
//
// “2fa-vault name” prints a two-factor authentication code from the key with the
// given name.
//
// With no arguments, 2fa-vault prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa-vault.
//
// Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa-vault under the name github, typing the secret at the prompt:
//
//	$ 2fa-vault -add github
//	2fa-vault key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa-vault to obtain one:
//
//	$ 2fa-vault github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa-vault
//	268346	github
//	$
//
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	vault "github.com/hashicorp/vault/api"
)

const (
	vaultPath = "secret/2fa"
)

var (
	flagAdd  = flag.Bool("add", false, "add a key")
	flagList = flag.Bool("list", false, "list keys")
	flagHotp = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7    = flag.Bool("7", false, "generate 7-digit code")
	flag8    = flag.Bool("8", false, "generate 8-digit code")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t2fa -add [-7] [-8] [-hotp] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -list\n")
	fmt.Fprintf(os.Stderr, "\t2fa keyname\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	p := os.Getenv("2FA_PATH")
	if p == "" {
		p = vaultPath
	}
	k := readKeychain(p)

	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		k.add(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

const counterLen = 20

func getVaultLogical() (*vault.Logical, error) {
	vClient, err := vault.NewClient(nil)
	if err != nil {
		return nil, err
	}
	return vClient.Logical(), nil
}

func readKeychain(path string) *Keychain {
	c := &Keychain{
		file: path,
		keys: make(map[string]Key),
	}
	l, err := getVaultLogical()
	if err != nil {
		log.Fatalf("unable to connect to vault: %v", err)
	}

	secrets, err := l.List(path)
	if err != nil || secrets == nil {
		log.Fatalf("no secrets found for path %s: %v", path, err)
	}

	if keys, ok := secrets.Data["keys"]; ok {
		var k Key
		for _, n := range keys.([]interface{}) {
			name := n.(string)
			newPath := fmt.Sprintf("%s/%s", path, name)
			s, err := l.Read(newPath)
			if err != nil || s == nil {
				continue
			}
			valid := true
			for n, v := range s.Data {
				if n == "size" {
					d, err := strconv.Atoi(v.(string))
					if err != nil {
						valid = false
					}
					k.digits = d
				} else if n == "text" {
					raw, err := decodeKey(v.(string))
					if err != nil {
						valid = false
					}
					k.raw = raw
				}
			}
			if valid {
				c.keys[name] = k
			}
		}
	} else {
		log.Fatal("no 2fa keys found")
	}

	return c
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func (c *Keychain) add(name string) {
	size := "6"
	if *flag7 {
		size = "7"
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = "8"
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal("error reading key: %v", err)
	}
	text = text[:len(text)-1] // chop \n
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	l, err := getVaultLogical()
	if err != nil {
		log.Fatalf("unable to connect to vault: %v", err)
	}
	vals := make(map[string]interface{})
	vals["size"] = size
	vals["text"] = text

	path := fmt.Sprintf("%s/%s", c.file, name)

	_, err = l.Write(path, vals)
	if err != nil {
		log.Fatalf("error writing values to vault: %v", err)
	}
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if k.offset != 0 {
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterLen]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterLen])
		}
		n++
		code = hotp(k.raw, n, k.digits)
		f, err := os.OpenFile(c.file, os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("opening keychain: %v", err)
		}
		if _, err := f.WriteAt([]byte(fmt.Sprintf("%0*d", counterLen, n)), int64(k.offset)); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
		if err := f.Close(); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
	} else {
		// Time-based key.
		code = totp(k.raw, time.Now(), k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) show(name string) {
	fmt.Printf("%s\n", c.code(name))
}

func (c *Keychain) showAll() {
	var names []string
	max := 0
	maxDigits := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < len(name) {
			max = len(name)
		}
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.offset == 0 {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", maxDigits, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
