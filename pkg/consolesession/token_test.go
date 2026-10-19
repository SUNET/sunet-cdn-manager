package consolesession

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5/pgtype"
)

var tokenFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$`)

// testToken returns a token with a random secret and a fixed id that
// contains letters, so changing their case is visible.
func testToken(t *testing.T) Token {
	t.Helper()
	secret, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	return Token{
		ID:     pgtype.UUID{Bytes: uuid.MustParse("0f8fad5b-d9cb-469f-a165-70867728950e"), Valid: true},
		secret: secret,
	}
}

func TestTokenRoundTrip(t *testing.T) {
	tok := testToken(t)

	s := tok.String()
	if !tokenFormat.MatchString(s) {
		t.Fatalf("token %q does not have the expected format", s)
	}

	parsed, err := ParseToken(s)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != tok {
		t.Fatal("parsed token differs from the original")
	}
}

func TestParseTokenRejects(t *testing.T) {
	valid := testToken(t).String()
	idPart, secretPart, found := strings.Cut(valid, ".")
	if !found {
		t.Fatal("token has no '.'")
	}

	// The all-zero secret is 43 'A's. 32 bytes in unpadded base64 leave two
	// unused low bits in the last character, setting one of them ('B')
	// gives a second spelling of the same secret that a non-strict decoder
	// would accept.
	zeroSecret := strings.Repeat("A", secretLen)
	if _, err := ParseToken(idPart + "." + zeroSecret); err != nil {
		t.Fatalf("the all-zero secret is rejected: %v", err)
	}
	nonCanonical := zeroSecret[:secretLen-1] + "B"

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "one character short", value: valid[:len(valid)-1]},
		{name: "one character long", value: valid + "A"},
		{name: "no dot", value: idPart + "A" + secretPart},
		{name: "extra dot", value: idPart + "." + secretPart[:len(secretPart)-1] + "."},
		{name: "id only", value: idPart},
		{name: "secret only", value: secretPart},
		{name: "upper case id", value: strings.ToUpper(idPart) + "." + secretPart},
		{name: "braced id", value: "{" + idPart + "}." + secretPart},
		{name: "urn id", value: "urn:uuid:" + idPart + "." + secretPart},
		{name: "id without dashes", value: strings.ReplaceAll(idPart, "-", "") + "." + secretPart},
		{name: "padding", value: idPart + "." + secretPart[:len(secretPart)-1] + "="},
		{name: "plus in secret", value: idPart + ".+" + secretPart[1:]},
		{name: "slash in secret", value: idPart + "./" + secretPart[1:]},
		{name: "newline in secret", value: idPart + "." + secretPart[:20] + "\n" + secretPart[21:]},
		{name: "carriage return in secret", value: idPart + "." + secretPart[:20] + "\r" + secretPart[21:]},
		{name: "non-canonical last character", value: idPart + "." + nonCanonical},
		{name: "31 byte secret", value: idPart + "." + secretEncoding.EncodeToString(make([]byte, 31))},
		{name: "33 byte secret", value: idPart + "." + secretEncoding.EncodeToString(make([]byte, 33))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseToken(test.value)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseToken(%q): want ErrMalformed, got %v", test.value, err)
			}
		})
	}
}

func TestTokenMatches(t *testing.T) {
	tok := testToken(t)
	if !tok.matches(tok.secretHash()) {
		t.Fatal("token does not match its own hash")
	}

	other := tok
	other.secret[0] ^= 0xff
	if other.matches(tok.secretHash()) {
		t.Fatal("a different secret matches")
	}

	if tok.matches(nil) {
		t.Fatal("an empty stored hash matches")
	}
}
