/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Thursday 26 September 2019 - 13:09:47
** @Filename:				DecryptablePasswords.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Monday 14 October 2019 - 12:26:40
*******************************************************************************/

package		crypto

import		"encoding/base64"
import		"github.com/funny/crypto/aes256cbc"
import		"github.com/microgolang/errors"

/*EncryptPassword *************************************************************
*	Encrypt a password according to the passPhrase and the token
******************************************************************************/
func	EncryptPassword(uncrypted, token, prependedMasterKey, appendedMasterKey string) (string, error) {
	if (uncrypted == `` || token == `` || prependedMasterKey == `` || appendedMasterKey == ``) {
		return ``, errors.New(`No encrypted, token or masterKeyPart`)
	}
	passPhrase := prependedMasterKey + token + appendedMasterKey
	enc, err := aes256cbc.EncryptString(passPhrase, uncrypted)
	if (errors.HasError(err)) {
		return ``, err
	}
	return enc, nil
}

/*DecryptPassword *************************************************************
*	Decrypt a password according to the passPhrase and the token
******************************************************************************/
func	DecryptPassword(crypted, token, prependedMasterKey, appendedMasterKey string) (string, error) {
	if (crypted == `` || token == `` || prependedMasterKey == `` || appendedMasterKey == ``) {
		return ``, errors.New(`No crypted, token or masterKeyPart`)
	}
	passPhrase := prependedMasterKey + token + appendedMasterKey
	dec, err := aes256cbc.DecryptString(passPhrase, crypted);
	if (errors.HasError(err)) {
		return dec, err
	}
	return dec, nil
}

/*EncryptBusinessesDbPassword *************************************************
*	Encrypt a password according to the passPhrase and the token
******************************************************************************/
func	EncryptPasswordWithBase64(uncrypted, token, prependedMasterKey, appendedMasterKey string) (string, error) {
	if (uncrypted == `` || token == `` || prependedMasterKey == `` || appendedMasterKey == ``) {
		return ``, errors.New(`No encrypted, token or masterKeyPart`)
	}

	passPhrase := prependedMasterKey + token + appendedMasterKey
	enc, err := aes256cbc.EncryptString(passPhrase, uncrypted);
	if (errors.HasError(err)) {
		return ``, err
	}
    data := base64.URLEncoding.EncodeToString([]byte(enc))
	return string(data), nil
}

/*DecryptBusinessesDbPassword *************************************************
*	Decrypt a password according to the passPhrase and the token
******************************************************************************/
func	DecryptPasswordWithBase64(crypted, token, prependedMasterKey, appendedMasterKey string) (string, error) {
	if (crypted == `` || token == `` || prependedMasterKey == `` || appendedMasterKey == ``) {
		return ``, errors.New(`No crypted, token or masterKeyPart`)
	}

	passPhrase := prependedMasterKey + token + appendedMasterKey
    data, _ := base64.StdEncoding.DecodeString(crypted)
	dec, err := aes256cbc.DecryptString(passPhrase, string(data));
	if (errors.HasError(err)) {
		return ``, err
	}
	return dec, nil
}
