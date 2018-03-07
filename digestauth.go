// Package digestauth is a minimal implementation of the HTTP digest access
// authentication protocol.
//
// Basic example:
//
//  package main
//
//  import (
//      "fmt"
//      "github.com/cet001/digestauth"
//  )
//
//  client := digestauth.NewDigestAuthClient(nil)
//  response, err := client.Get("http://john:secret-passwd@example.com/some/resource")
//
// Some major limitations:
//
//   - Currently only supports HTTP GET
//   - Username and password must be provided as part of the URL
//     (e.g. "http://my-username:my-passwd@myhost.com")
//   - Does not support the "auth-int" QOP directive
//
package digestauth

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DigestAuthClient is an HTTP client that implements a subset of the HTTP
// Digest Access Authentication protocol.
//
// See:
//   - https://tools.ietf.org/html/rfc2617
//   - http://httpwg.org/specs/rfc7616.html
type DigestAuthClient struct {
	httpDo func(req *http.Request) (resp *http.Response, err error)
}

// Creates a new DigestAuthClient that uses the provided http.Client object to
// send HTTP requests.  If client is nil, a new http.Client is implicity created.
func NewDigestAuthClient(client *http.Client) *DigestAuthClient {
	if client == nil {
		client = &http.Client{}
	}
	return &DigestAuthClient{httpDo: client.Do}
}

func (me *DigestAuthClient) Get(url string) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := me.httpDo(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		return response, err
	}

	authHeader := response.Header.Get("Www-Authenticate")
	if authHeader == "" {
		return response, err
	}

	var realm, nonce, qop string
	for _, kv := range strings.Split(authHeader, ",") {
		k, v := parseKV(kv)
		switch k {
		case "Digest realm":
			realm = v
		case "qop":
			qop = v
		case "nonce":
			nonce = v
		}
	}

	isDigestAuth := (realm != "")
	if !isDigestAuth {
		return response, err
	}

	digestAuth, err := CalcDigestAuth(response.Request, realm, nonce, qop)
	if err != nil {
		return nil, fmt.Errorf("Error calculating 'Authorization' header: %v", err)
	}

	response.Body.Close()

	authorizedRequest, _ := http.NewRequest("GET", url, nil)
	authorizedRequest.Header.Set("Authorization", digestAuth)
	return me.httpDo(request)
}

// Calculates the digest authorization header value for the provided inputs.
// The URL within the provided http.Request object must contain the username and
// password credentials.
func CalcDigestAuth(request *http.Request, realm, nonce, qop string) (string, error) {
	return calcDigestAuth(request, realm, nonce, qop)
}

// Internal implementation defined as a global var so that it can be mocked out within unit tests.
var calcDigestAuth = func(request *http.Request, realm, nonce, qop string) (string, error) {
	uri := request.URL.RequestURI()
	userInfo := request.URL.User
	if userInfo == nil {
		return "", fmt.Errorf("Username or password not provided in request URL")
	}
	username := userInfo.Username()
	password, _ := userInfo.Password()
	if username == "" || password == "" {
		return "", fmt.Errorf("Username or password not provided in request URL")
	}

	ha1 := calcMD5(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := calcMD5(fmt.Sprintf("%s:%s", request.Method, uri))

	var nonceCount, cnonce, digestResponse string
	switch qop {
	case "":
		digestResponse = calcMD5(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	case "auth":
		nonceCount = "00000001"
		cnonce = calcCnonce()
		digestResponse = calcMD5(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nonceCount, cnonce, qop, ha2))
	default:
		return "", fmt.Errorf("Unsupported QOP directive: '%v'", qop)
	}

	// NOTE: Certain values are not wrapped in double-quotes intentionally.
	// See http://httpwg.org/specs/rfc7616.html.
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		username, realm, nonce, uri, qop, nonceCount, cnonce, digestResponse), nil
}

func calcMD5(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Parses a key/value pair having the form `<key>="<value>"` into its constituent parts.
func parseKV(kv string) (string, string) {
	parts := strings.SplitN(kv, "=", 2)
	key := strings.TrimSpace(parts[0])
	value := strings.Trim(parts[1], "\" ")
	return key, value
}

// Calculates a client nonce value.  NOTE: This function is declared as a var so
// that it can be overridden in unit tests.
var calcCnonce = func() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}
