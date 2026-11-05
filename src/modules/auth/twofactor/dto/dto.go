package dto

type SetupResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type ConfirmRequest struct {
	Code string `json:"code"`
}
