package dto

// ponytail: fields are strings, so item secrets stay on the heap until GC; switch to []byte if memory scraping matters
type Item struct {
	ID       string `json:"-"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
}

type StoredItem struct {
	ID   string `json:"id"`
	Blob []byte `json:"blob"`
}
