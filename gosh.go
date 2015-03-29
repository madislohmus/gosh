package gosh

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"time"
)

const (
	KeyType = "RSA PRIVATE KEY"
	Timeout = 10 * time.Second
)

func GetSigner(keyFile, password string) (*ssh.Signer, error) {
	fp, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	var pk []byte
	pk, err = ioutil.ReadAll(fp)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pk)
	if block == nil {
		return nil, errors.New("No PEM data found")
	}

	if x509.IsEncryptedPEMBlock(block) {
		decPk, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
		pk = pem.EncodeToMemory(&pem.Block{Type: KeyType, Bytes: decPk})
	}

	signer, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		return nil, err
	}
	return &signer, nil
}

func Run(command, user, host, port string, signer *ssh.Signer) (string, error) {

	resChan := make(chan string)
	errChan := make(chan error)
	go func() {
		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(*signer)},
		}
		client, err := ssh.Dial("tcp", host+":"+port, config)
		if err != nil {
			errChan <- err
			return
		}

		session, err := client.NewSession()
		if err != nil {
			errChan <- err
			return
		}
		defer session.Close()
		var b bytes.Buffer
		session.Stdout = &b
		if err := session.Run(command); err != nil {
			errChan <- err
			return
		}
		resChan <- b.String()
	}()
	timeout := time.After(Timeout)
	select {
	case <-timeout:
		return "", errors.New("Timeout!")
	case err := <-errChan:
		return "", err
	case res := <-resChan:
		return res, nil
	}
}
