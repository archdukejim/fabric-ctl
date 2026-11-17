// fabric-certlist lists the certificates Step-CA signed, from a copy of its database (decision 2.1.5.13, manual
// 1.5.1.9.1): one JSON object per line, with the serial, names, validity and the provisioner that signed each.
//
//	fabric-certlist <database directory>
//
// It is built into fabric's Step-CA image (packaging/images/stepca/Dockerfile) on smallstep/nosql's badgerv2 driver, at
// the versions that image's step-ca uses (reader/README.md), and run by fabric's agent against a copy of the database:
// the live one is locked by step-ca.
// Exit status: 0 listed, 2 usage, 3 the database cannot be opened, 4 it cannot be read.
package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	badgerv2 "github.com/smallstep/nosql/badger/v2"
	"github.com/smallstep/nosql/database"
)

// certRow is one certificate as fabric reads it (fabriclib/pki/list_stepca_certs.py).
type certRow struct {
	Serial          string   `json:"serial"`
	Subject         string   `json:"subject"`
	CN              string   `json:"cn"`
	Issuer          string   `json:"issuer"`
	DNS             []string `json:"dns"`
	IPs             []string `json:"ips"`
	Emails          []string `json:"emails"`
	URIs            []string `json:"uris"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	IsCA            bool     `json:"is_ca"`
	Provisioner     string   `json:"provisioner"`
	ProvisionerType string   `json:"provisioner_type"`
}

// certData is the part of Step-CA's x509_certs_data record fabric uses.
type certData struct {
	Provisioner *struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"provisioner"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fabric-certlist <database directory>")
		os.Exit(2)
	}
	// only the badgerv2 driver Step-CA's database uses, not nosql's root package: that links every driver, MySQL's
	// (MPL-2.0) among them, and fabric ships permissive licences only (1.1.7.1)
	db := &badgerv2.DB{}
	if err := db.Open(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the database:", err)
		os.Exit(3)
	}
	defer db.Close()
	extra := map[string]certData{}
	if rows, err := db.List([]byte("x509_certs_data")); err == nil { // absent before any certificate had data
		for _, e := range rows {
			var d certData
			if json.Unmarshal(e.Value, &d) == nil {
				extra[string(e.Key)] = d
			}
		}
	}
	rows, err := db.List([]byte("x509_certs"))
	if err != nil {
		if database.IsErrNotFound(err) { // a CA that has signed nothing yet
			return
		}
		fmt.Fprintln(os.Stderr, "cannot read the certificates:", err)
		os.Exit(4)
	}
	out := json.NewEncoder(os.Stdout)
	for _, e := range rows {
		c, err := x509.ParseCertificate(e.Value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipped %x: not a certificate: %v\n", e.Key, err)
			continue
		}
		row := certRow{
			Serial: c.SerialNumber.Text(16), Subject: c.Subject.String(), CN: c.Subject.CommonName,
			Issuer: c.Issuer.String(), DNS: c.DNSNames, Emails: c.EmailAddresses, IsCA: c.IsCA,
			NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		}
		for _, ip := range c.IPAddresses {
			row.IPs = append(row.IPs, ip.String())
		}
		for _, u := range c.URIs {
			row.URIs = append(row.URIs, u.String())
		}
		if d, ok := extra[string(e.Key)]; ok && d.Provisioner != nil {
			row.Provisioner, row.ProvisionerType = d.Provisioner.Name, d.Provisioner.Type
		}
		if err := out.Encode(row); err != nil {
			fmt.Fprintln(os.Stderr, "cannot write:", err)
			os.Exit(4)
		}
	}
}
