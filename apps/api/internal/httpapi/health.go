package httpapi

import "net/http"

type healthData struct {
	Status     string `json:"status"`
	APIVersion string `json:"apiVersion"`
}

// handleHealth serves GET /api/v1/health (openapi.yaml health tag). The shape
// matches the contract example exactly: success envelope with status + apiVersion.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, r, http.StatusOK, healthData{
		Status:     "ok",
		APIVersion: s.cfg.APIVersion,
	}, nil)
}
