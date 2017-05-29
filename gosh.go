package gosh

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
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
		Signers []ssh.Signer
	}

	TimeoutError struct {
		timeout time.Duration
	}
)

func (te *TimeoutError) Error() string {
	return fmt.Sprintf("Timeout at %v", te.timeout)
}

func GetSigner(keyFile, password string) (*ssh.Signer, error) {
	pk, err := ioutil.ReadFile(keyFile)
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

func GetClient(cfg Config, connectTimeout time.Duration) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: cfg.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cfg.Signers...)},
	}
	conn, err := net.DialTimeout("tcp", cfg.Host+":"+cfg.Port, connectTimeout)
	if err != nil {
		return nil, err
	}
	cliConn, newChan, requestChan, err := ssh.NewClientConn(conn, cfg.Host+":"+cfg.Port, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(cliConn, newChan, requestChan), nil
}

func RunOnClient(command string, client ssh.Client, timeout time.Duration) (string, error) {
	resChan := make(chan string)
	errChan := make(chan error)
	go func() {
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
	timeoutChan := time.After(timeout)
	select {
	case <-timeoutChan:
		return "", &TimeoutError{timeout: timeout}
	case err := <-errChan:
		return "", err
	case res := <-resChan:
		return res, nil
	}
}

func Run(command string, cfg Config, connectTimeout, runTimeout time.Duration) (string, error) {
	client, err := GetClient(cfg, connectTimeout)
	if err != nil {
		return "", err
	}
	return RunOnClient(command, *client, runTimeout)

}
