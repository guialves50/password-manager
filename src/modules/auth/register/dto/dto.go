package dto

import prelogin "github.com/guialves50/password-manager/src/modules/auth/prelogin/dto"

type Input struct {
	Email    string
	Password []byte
	Confirm  []byte
}

type Output struct {
	RecoveryKey string
}

type Request struct {
	Email            string       `json:"email"`
	KDF              prelogin.KDF `json:"kdf"`
	MasterSalt       []byte       `json:"master_salt"`
	MasterBlob       []byte       `json:"master_blob"`
	AuthHash         []byte       `json:"auth_hash"`
	RecoverySalt     []byte       `json:"recovery_salt"`
	RecoveryBlob     []byte       `json:"recovery_blob"`
	RecoveryAuthHash []byte       `json:"recovery_auth_hash"`
}
