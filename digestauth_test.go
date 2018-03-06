package digestauth

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewDigestAuthClient(t *testing.T) {
	targetClient := &http.Client{}
	digestAuthClient := NewDigestAuthClient(targetClient)
	assert.NotNil(t, digestAuthClient.httpGet)
	assert.NotNil(t, digestAuthClient.httpDo)
}

func TestGet_responseError(t *testing.T) {
	var receivedUrl string

	client := &DigestAuthClient{
		httpGet: func(url string) (resp *http.Response, err error) {
			receivedUrl = url
			return nil, fmt.Errorf("blah!")
		},
	}

	_, err := client.Get("http://some/url")
	assert.EqualError(t, err, "blah!")
}

// If server returns 'HTTP 401 UNAUTHORIZED' status code, but does not provide
// the 'Www-Authenticate' header (that tells the client how they should
// authenticate), expect the client to just pass through the response.
func TestGet_authHeaderNotProvided(t *testing.T) {
	fakeResponse := &http.Response{
		StatusCode: http.StatusUnauthorized,
	}
	client := &DigestAuthClient{
		httpGet: func(url string) (resp *http.Response, err error) {
			return fakeResponse, nil
		},
	}

	response, err := client.Get("http://some/url")
	assert.Nil(t, err)
	assert.Equal(t, fakeResponse, response)
}

// If server returns an HTTP 401 status code along with a 'Www-Authenticate'
// header, but the header doesn't contain a key called 'Digest realm', assume
// the server is asking for an authentication type other than Digest Auth, and
// simply pass through the original response.
func TestGet_notDigestAuth(t *testing.T) {
	fakeResponse := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{},
	}
	fakeResponse.Header.Add("Www-Authenticate", "foo=bar")
	client := &DigestAuthClient{
		httpGet: func(url string) (resp *http.Response, err error) {
			return fakeResponse, nil
		},
	}

	response, err := client.Get("http://some/url")
	assert.Nil(t, err)
	assert.Equal(t, fakeResponse, response)
}

func TestCalcDigestAuth_missingCredentials(t *testing.T) {
	// Each of these URLs has something wrong with it; either username or
	// password (or both) are missing.
	badUrls := []string{
		"http://john@example.com",         // username but no passwd
		"http://john.smith@example.com",   // username but no passwd
		"http://john:@example.com",        // username but empty passwd
		"http://:secret-pass@example.com", // passwd but empty username
		"http://example.com",              // both username and passwd missing
	}

	for _, badUrl := range badUrls {
		req := httptest.NewRequest("GET", badUrl, nil)
		_, err := CalcDigestAuth(req, "my_realm", "some_nonce", "auth")
		assert.EqualError(t, err, "Username or password not provided in request URL")
	}
}

func TestCalcDigestAuth_QOP_invalid(t *testing.T) {
	req := httptest.NewRequest("GET", "http://john:somepasswd@example.com", nil)
	_, err := CalcDigestAuth(req, "my_realm", "some_nonce", "INVALID_QOP_VALUE")
	assert.NotNil(t, err)
}

// Verifies that the digest auth returned by this implementation matches the sample
// calculations in https://en.wikipedia.org/wiki/Digest_access_authentication.
func TestCalcDigestAuth(t *testing.T) {
	// Define a mock calcCnonce() func that returns the cnonce from the Wikipedia example
	origCalcCnonce := calcCnonce
	calcCnonce = func() string {
		return "0a4f113b"
	}
	defer func() {
		calcCnonce = origCalcCnonce
	}()

	username := "Mufasa"
	password := url.PathEscape("Circle Of Life")
	uri := "/dir/index.html"
	realm := "testrealm@host.com"
	serverNonce := "dcd98b7102dd2f0e8b11d0f600bfb0c093"

	url := fmt.Sprintf("http://%v:%v@%v", username, password, uri)
	req := httptest.NewRequest("GET", url, nil)

	// Case 1: QOP=auth
	authHeader, err := CalcDigestAuth(req, realm, serverNonce, "auth")
	assert.Nil(t, err)
	expectedAuthHeader := []string{
		`Digest username="Mufasa"`,
		`realm="testrealm@host.com"`,
		fmt.Sprintf(`nonce="%v"`, serverNonce),
		fmt.Sprintf(`uri="%v"`, uri),
		`qop=auth`,
		`nc=00000001`,
		fmt.Sprintf(`cnonce="%v"`, calcCnonce()),
		`response="6629fae49393a05397450978507c4ef1"`, // MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
	}
	assert.Equal(t, strings.Join(expectedAuthHeader, ", "), authHeader)

	// Case 2: QOP unspecified
	authHeader, err = CalcDigestAuth(req, realm, serverNonce, "")
	assert.Nil(t, err)
	expectedAuthHeader = []string{
		`Digest username="Mufasa"`,
		`realm="testrealm@host.com"`,
		fmt.Sprintf(`nonce="%v"`, serverNonce),
		fmt.Sprintf(`uri="%v"`, uri),
		`qop=`,
		`nc=`,
		`cnonce=""`,
		`response="670fd8c2df070c60b045671b8b24ff02"`, // MD5(HA1:nonce:HA2)
	}
	assert.Equal(t, strings.Join(expectedAuthHeader, ", "), authHeader)
}

func TestCalcMD5(t *testing.T) {
	// Just a sanity check.  These expecations were grabbed from https://en.wikipedia.org/wiki/Digest_access_authentication
	assert.Equal(t, "939e7578ed9e3c518a452acee763bce9", calcMD5("Mufasa:testrealm@host.com:Circle Of Life"))
	assert.Equal(t, "39aff3a2bab6126f332b942af96d3366", calcMD5("GET:/dir/index.html"))

	const md5emptyStringHash = "d41d8cd98f00b204e9800998ecf8427e"
	assert.Equal(t, md5emptyStringHash, calcMD5(""))
}

// A "sanity check" test that verifies beyond  reasonable doubt that duplicate
// cnonce values are not generated.
func TestCalcCnonce(t *testing.T) {
	const n = 100000
	uniqueValues := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		uniqueValues[calcCnonce()] = true
	}
	assert.Equal(t, n, len(uniqueValues))
}

func TestParseKV(t *testing.T) {
	type TestCase struct {
		Input         string
		ExpectedKey   string
		ExpectedValue string
	}

	testCases := []TestCase{
		TestCase{`foo="bar"`, `foo`, `bar`},
		TestCase{`foo bar="baz"`, `foo bar`, `baz`},
		TestCase{`foo="bar=baz"`, `foo`, `bar=baz`},     // key/value separator present in value
		TestCase{`  foo =" barbaz  "`, `foo`, `barbaz`}, // verify extraneous whitespace is stripped
	}

	for i, testCase := range testCases {
		k, v := parseKV(testCase.Input)
		assert.Equal(t, testCase.ExpectedKey, k, fmt.Sprintf("Case %v failed", i))
		assert.Equal(t, testCase.ExpectedValue, v, fmt.Sprintf("Case %v failed", i))
	}
}
