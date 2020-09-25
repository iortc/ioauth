package ioauth

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const KEY_BITS = 2048

type Client struct {
	UID     string
	kind    string
	config  string
	key     *rsa.PrivateKey
	client  *http.Client
	baseUrl string
	context string
	Token   string
}

func NewClient(kind string, config string, key *rsa.PrivateKey, client *http.Client, baseUrl string) (*Client, error) {
	c := &Client{kind: kind, config: config, key: key, client: client, baseUrl: baseUrl}
	err := c.init()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) init() error {
	if c.config == "" {
		return c.register()
	}
	if _, err := os.Stat(c.config); os.IsNotExist(err) {
		err := c.register()
		if err != nil {
			return err
		}
	} else {
		f, err := os.Open(c.config)
		if err != nil {
			log.Printf("Failed to open config file: %s", err.Error())
			return err
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		data := &struct {
			UID string `json:"uid"`
		}{}
		err = dec.Decode(data)
		if err != nil {
			log.Printf("Failed to decode config file: %s", err.Error())
			return err
		}
		c.UID = data.UID
		err = c.refreshToken()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) register() error {
	var err error
	if c.key == nil {
		c.key, err = rsa.GenerateKey(rand.Reader, KEY_BITS)
		if err != nil {
			log.Printf("Failed to generate key: %s", err.Error())
			return err
		}
	}
	pkix, err := x509.MarshalPKIXPublicKey(&c.key.PublicKey)
	if err != nil {
		log.Printf("Failed to marshal public key: %s", err.Error())
		return err
	}
	req := &struct {
		UID string `json:"uid,omitempty"`
		Key string `json:"key"`
	}{UID: c.UID, Key: hex.EncodeToString(pkix)}
	res := &struct {
		Error  int    `json:"error"`
		Reason string `json:"reason"`
		UID    string `json:"uid"`
		Token  string `json:"token"`
	}{}
	err = c.request("POST", fmt.Sprintf("/%s", c.kind), req, res)
	if err != nil {
		log.Printf("Failed to register: %s", err.Error())
		return err
	}
	c.UID = res.UID
	c.Token = res.Token
	c.writeConfig()
	return nil
}

func (c *Client) writeConfig() error {
	if c.config != "" {
		f, err := os.Create(c.config)
		if err != nil {
			log.Printf("Failed to open config file for write: %s", err.Error())
			return err
		}
		enc := json.NewEncoder(f)
		data := &struct {
			URL   string `json:"url"`
			UID   string `json:"uid"`
			Token string `json:"token"`
		}{URL: c.baseUrl, UID: c.UID, Token: c.Token}
		err = enc.Encode(data)
		if err != nil {
			log.Printf("Failed to encode config file: %s", err.Error())
			return err
		}
	}
	return nil
}

func (c *Client) request(method, uri string, jreq interface{}, jres interface{}) error {
	buf := new(bytes.Buffer)
	if jreq != nil {
		enc := json.NewEncoder(buf)
		err := enc.Encode(jreq)
		if err != nil {
			log.Printf("Failed to encode: %s", err.Error())
			return err
		}
	}
	url := fmt.Sprintf("%s%s", c.baseUrl, uri)
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		log.Printf("Failed to create request: %s", err.Error())
		return err
	}
	if jreq != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.client.Do(req)
	if err != nil {
		log.Printf("Failed to make request: %s", err.Error())
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = fmt.Errorf("Unexpected status code: %d", res.StatusCode)
		log.Printf("%s", err.Error())
		return err
	}
	if jres != nil {
		dec := json.NewDecoder(res.Body)
		err = dec.Decode(jres)
		if err != nil {
			log.Printf("Failed to decode: %s", err.Error())
			return err
		}
	}
	return nil
}

func (c *Client) authRequest(method, uri string, jreq interface{}, jres interface{}) error {
	buf := new(bytes.Buffer)
	if jreq != nil {
		enc := json.NewEncoder(buf)
		err := enc.Encode(jreq)
		if err != nil {
			log.Printf("Failed to encode: %s", err.Error())
			return err
		}
	}
	url := fmt.Sprintf("%s%s", c.baseUrl, uri)
	if c.Token == "" {
		err := c.refreshToken()
		if err != nil {
			log.Printf("Failed to refresh token: %s", err.Error())
			return err
		}
	}
	if strings.Index(url, "?") != -1 {
		url = fmt.Sprintf("%s&auth=%s", url, c.Token)
	} else {
		url = fmt.Sprintf("%s?auth=%s", url, c.Token)
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		log.Printf("Failed to create request: %s", err.Error())
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		log.Printf("Failed to make request: %s", err.Error())
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = fmt.Errorf("Unexpected status code: %d", res.StatusCode)
		log.Printf("%s", err.Error())
		return err
	}
	if jres != nil {
		bytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Printf("Failed to read body: %s", err.Error())
			return err
		}
		check := &struct {
			Error  int    `json:"error"`
			Reason string `json:"reason"`
		}{}
		err = json.Unmarshal(bytes, check)
		if err != nil {
			log.Printf("Failed to decode: %s", err.Error())
			return err
		}
		switch check.Error {
		case 0:
			err = json.Unmarshal(bytes, jres)
			if err != nil {
				log.Printf("Failed to decode: %s", err.Error())
				return err
			}
		case 401:
			err := c.refreshToken()
			if err != nil {
				log.Printf("Failed to refresh token: %s", err.Error())
				return err
			}
			return c.authRequest(method, uri, jreq, jres)
		default:
			return fmt.Errorf("RESTful error: %d %s", check.Error, check.Reason)
		}
	}
	io.Copy(ioutil.Discard, res.Body)
	return nil
}

func (c *Client) Get(uri string, jres interface{}) error {
	log.Printf("Getting %s", uri)
	return c.authRequest("GET", uri, nil, jres)
}

func (c *Client) Put(uri string, jreq interface{}, jres interface{}) error {
	log.Printf("Putting %s", uri)
	return c.authRequest("PUT", uri, jreq, jres)
}

func (c *Client) Post(uri string, jreq interface{}, jres interface{}) error {
	log.Printf("Posting %s", uri)
	return c.authRequest("POST", uri, jreq, jres)
}

func (c *Client) Del(uri string, jres interface{}) error {
	log.Printf("Deleting %s", uri)
	return c.authRequest("DELETE", uri, nil, jres)
}

func (c *Client) refreshToken() error {
	log.Printf("Requesting token...")
	res := &struct {
		Error  int    `json:"error,omitempty"`
		Reason string `json:"reason,omitempty"`
		Nonce  string `json:"nonce,omitempty"`
		Token  string `json:"token,omitempty"`
	}{}
	err := c.request("GET", fmt.Sprintf("/%s/%s/token", c.kind, c.UID), nil, res)
	if err != nil {
		return err
	}
	switch res.Error {
	case 0:
		break
	case 404:
		log.Printf("Not on server; registering...")
		return c.register()
	default:
		err = fmt.Errorf("Failed to request token: %d (%s)", res.Error, res.Reason)
		log.Printf("%s", err.Error())
		return err
	}
	nonce, err := hex.DecodeString(res.Nonce)
	if err != nil {
		log.Printf("Failed to decode nonce: %s", err.Error())
		return err
	}
	hashed := md5.Sum(nonce)
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.MD5, hashed[:])
	log.Printf("Submitting signature...")
	err = c.request("GET", fmt.Sprintf("/%s/%s/token?signature=%s", c.kind, c.UID, hex.EncodeToString(sig)), nil, res)
	if err != nil {
		return err
	}
	switch res.Error {
	case 0:
		c.Token = res.Token
		log.Printf("Token refreshed: %s", c.Token)
		c.writeConfig()
		return nil
	default:
		if res.Error == 406 {
			log.Printf("Key mismatch on server; resetting identity...")
			os.Remove(c.config)
		}
		err = fmt.Errorf("Failed to submit signature: %d (%s)", res.Error, res.Reason)
		log.Printf("%s", err.Error())
		return err
	}
}
