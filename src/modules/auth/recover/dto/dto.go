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
