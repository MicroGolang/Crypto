/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Thursday 26 September 2019 - 13:51:07
** @Filename:				UndecryptablePasswords.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Thursday 26 September 2019 - 13:52:33
*******************************************************************************/

package		crypto

import      password    "github.com/dwin/goSecretBoxPassword"

/******************************************************************************
**	VerifyHash
**	Verify a hash according to the masterKey
******************************************************************************/
func	VerifyHash(uncrypted, hash, masterKey string) bool {
	if (uncrypted == ``) {
		return false
	}

	err := password.Verify(uncrypted, masterKey, hash)
	if (err != nil) {
		return (false)
	}
	return (true)
}

/******************************************************************************
**	HashPassword
**	Hash a password according to the masterKey
******************************************************************************/
func	HashPassword(uncrypted, masterKey string) string {
	if (uncrypted == ``) {
		return ``
	}
	pwHash, err := password.Hash(uncrypted, masterKey, 0, password.ScryptParams{N: 32768, R: 16, P: 1}, password.DefaultParams)
	if (err != nil) {
		return err.Error()
	}
	return pwHash
}
