package dto

type KDF struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

type Request struct {
	Email string `json:"email"`
}

type Response struct {
	KDF          KDF    `json:"kdf"`
	MasterSalt   []byte `json:"master_salt"`
	RecoverySalt []byte `json:"recovery_salt"`
}
