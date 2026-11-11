// Throwaway reader for the 2.3.5.5 prototype: lists Step-CA's x509_certs (and x509_certs_data) from a
// database directory, one JSON line per certificate. Uses smallstep/nosql, the library Step-CA itself uses.
package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/smallstep/nosql"
)

func main() {
	db, err := nosql.New("badgerv2", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(2)
	}
	defer db.Close()
	extra := map[string]json.RawMessage{}
	if rows, err := db.List([]byte("x509_certs_data")); err == nil {
		for _, e := range rows {
			extra[string(e.Key)] = json.RawMessage(e.Value)
		}
	} else {
		fmt.Fprintln(os.Stderr, "x509_certs_data:", err)
	}
	rows, err := db.List([]byte("x509_certs"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "x509_certs:", err)
		os.Exit(3)
	}
	for _, e := range rows {
		out := map[string]interface{}{"serial": fmt.Sprintf("%x", e.Key)}
		if c, err := x509.ParseCertificate(e.Value); err == nil {
			out["serial"] = c.SerialNumber.Text(16)
			out["subject"] = c.Subject.CommonName
			out["dns"] = c.DNSNames
			out["not_after"] = c.NotAfter
		}
		key := string(e.Key)
		if d, ok := extra[key]; ok {
			var parsed map[string]interface{}
			if json.Unmarshal(d, &parsed) == nil {
				out["provisioner"] = parsed["provisioner"]
			}
		}
		line, _ := json.Marshal(out)
		fmt.Println(string(line))
	}
}
