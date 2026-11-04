package dto

type Input struct {
	Email       string
	RecoveryKey []byte
	Password    []byte
	Confirm     []byte
}

type Output struct {
	RecoveryKey string
}

type StartRequest struct {
	Email            string `json:"email"`
	RecoveryAuthHash []byte `json:"recovery_auth_hash"`
}

type StartResponse struct {
	RecoveryBlob []byte `json:"recovery_blob"`
}

type FinishRequest struct {
	Email               string `json:"email"`
	RecoveryAuthHash    []byte `json:"recovery_auth_hash"`
	MasterSalt          []byte `json:"master_salt"`
	MasterBlob          []byte `json:"master_blob"`
	AuthHash            []byte `json:"auth_hash"`
	RecoverySalt        []byte `json:"recovery_salt"`
	RecoveryBlob        []byte `json:"recovery_blob"`
	NewRecoveryAuthHash []byte `json:"new_recovery_auth_hash"`
}
