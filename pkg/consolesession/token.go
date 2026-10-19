// Package consolesession stores console login sessions in PostgreSQL.
//
// A session token is "<id>.<secret>". The id is the primary key of a
// console_sessions row, a random version 4 UUID that is safe to log. The
// secret is 32 random bytes in unpadded base64url. Only SHA-256(secret) is
// stored, and the id alone is never accepted as proof of a session. What
// the OWASP Session Management Cheat Sheet calls the session ID is the
// whole token, the id is only its public lookup part, which logs carry as
// session_id.
package consolesession

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	secretSize = 32
	// A canonical UUID, a '.' and 32 bytes in unpadded base64url, for
	// example:
	// 62dc0fd9-843b-45d1-8b77-6d3f3d3363f2.2qQ2kmiJmXINWimFDW4jRyfBUh10TyBpjvjw9t9_8rI
	idLen     = 36
	secretLen = 43
	tokenLen  = idLen + 1 + secretLen
)

// ErrMalformed is returned by ParseToken for anything that is not exactly
// a token as written by Token.String.
var ErrMalformed = errors.New("consolesession: malformed session token")

// Strict() rejects non-zero trailing bits, so every secret has exactly one
// valid spelling.
var secretEncoding = base64.RawURLEncoding.Strict()

// Token is the value of the console session cookie.
type Token struct {
	ID     pgtype.UUID
	secret [secretSize]byte
}

// String returns the cookie value. It contains the secret, never log it.
func (tok Token) String() string {
	return uuid.UUID(tok.ID.Bytes).String() + "." + secretEncoding.EncodeToString(tok.secret[:])
}

// ParseToken parses a cookie value. Everything that is not exactly in the
// form Token.String writes is rejected with ErrMalformed. It does not touch
// the database.
func ParseToken(s string) (Token, error) {
	if len(s) != tokenLen {
		return Token{}, ErrMalformed
	}

	idPart, secretPart, ok := strings.Cut(s, ".")
	if !ok || len(idPart) != idLen || len(secretPart) != secretLen {
		return Token{}, ErrMalformed
	}

	// uuid.Parse also accepts upper case, "{...}", "urn:uuid:..." and the
	// form without dashes, only accept the canonical form.
	id, err := uuid.Parse(idPart)
	if err != nil || id.String() != idPart {
		return Token{}, ErrMalformed
	}

	// The decoder silently skips '\r' and '\n', but a 43 character secret
	// containing either decodes to at most 31 bytes, which the length
	// check rejects. Any other character outside the alphabet is a decode
	// error.
	secret, err := secretEncoding.DecodeString(secretPart)
	if err != nil || len(secret) != secretSize {
		return Token{}, ErrMalformed
	}

	tok := Token{ID: pgtype.UUID{Bytes: id, Valid: true}}
	copy(tok.secret[:], secret)

	return tok, nil
}

// newSecret returns 32 bytes (256 bits) from crypto/rand.
func newSecret() ([secretSize]byte, error) {
	var secret [secretSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return secret, fmt.Errorf("consolesession: unable to generate session secret: %w", err)
	}
	return secret, nil
}

// secretHash returns the verifier stored in the database.
func (tok Token) secretHash() []byte {
	sum := sha256.Sum256(tok.secret[:])
	return sum[:]
}

// matches reports in constant time whether the secret of tok hashes to
// storedHash.
func (tok Token) matches(storedHash []byte) bool {
	return subtle.ConstantTimeCompare(tok.secretHash(), storedHash) == 1
}
