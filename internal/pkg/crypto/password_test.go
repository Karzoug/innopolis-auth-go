package crypto

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func FuzzPasswordHasher_ComparePasswords(f *testing.F) {
	ph := NewPasswordHasher()

	f.Fuzz(func(t *testing.T, psw string) {
		hash, err := ph.HashPassword(psw)

		// see bcrypt pkg for details
		if len(psw) > 72 && errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return
		}
		require.NoError(t, err)
		require.NotEqual(t, psw, string(hash))

		require.True(t, true, ph.ComparePasswords(psw, string(hash)))
	})
}
