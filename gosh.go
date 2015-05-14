package gosh

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"time"
)

const (
	KeyType = "RSA PRIVATE KEY"
)

type (
	Config struct {
		User    string
		Host    string
		Port    string
		Timeout time.Duration
		Signer  *ssh.Signer
	}

	TimeoutError struct {
		timeout time.Duration
	}
)

func (te *TimeoutError) Error() string {
	return fmt.Sprintf("Timeout at %v", te.timeout)
}

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

func GetSession(cfg Config) (*ssh.Session, error) {
	config := &ssh.ClientConfig{
		User: cfg.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(*cfg.Signer)},
	}
	client, err := ssh.Dial("tcp", cfg.Host+":"+cfg.Port, config)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}

func RunOnSession(session *ssh.Session, command string) (string, error) {
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run(command); err != nil {
		return "", err
	}
	return b.String(), nil
}

func Run(command string, cfg Config) (string, error) {
	resChan := make(chan string)
	errChan := make(chan error)
	go func() {

		session, err := GetSession(cfg)
		if err != nil {
			errChan <- err
			return
		}
		defer session.Close()
		output, err := RunOnSession(session, command)
		if err != nil {
			errChan <- err
			return
		}
		resChan <- output
	}()
	timeout := time.After(cfg.Timeout)
	select {
	case <-timeout:
		return "", &TimeoutError{timeout: cfg.Timeout}
	case err := <-errChan:
		return "", err
	case res := <-resChan:
		return res, nil
	}
}
