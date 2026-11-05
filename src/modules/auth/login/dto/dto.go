package dto

type Input struct {
	Email    string
	Password []byte
	Code     func() (string, error)
}

type Request struct {
	Email    string `json:"email"`
	AuthHash []byte `json:"auth_hash"`
	Code     string `json:"code,omitempty"`
}

type Response struct {
	Token      string `json:"token"`
	UserID     uint64 `json:"user_id"`
	MasterBlob []byte `json:"master_blob"`
}
