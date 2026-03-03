package response

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	User    interface{} `json:"user,omitempty"`
	Message string      `json:"message,omitempty"`
}
