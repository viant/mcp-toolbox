package service

type Config struct {
    ClientID string `json:"clientID"`
    StorageDir string `json:"storageDir,omitempty"`
    CallbackBaseURL string `json:"callbackBaseURL,omitempty"`
    UseData bool `json:"useData,omitempty"`
    UseText bool `json:"useText,omitempty"`
}
