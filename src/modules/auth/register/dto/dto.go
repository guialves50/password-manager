package dto

type Input struct {
	Email    string
	Password []byte
	Confirm  []byte
}

type Output struct {
	RecoveryKey string
}
