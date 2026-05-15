package server

import (
	"encoding/json"
	"net/http"
)

// OCI error codes used in v0. Extend as needed.
const (
	CodeBlobUnknown       = "BLOB_UNKNOWN"
	CodeBlobUploadInvalid = "BLOB_UPLOAD_INVALID"
	CodeBlobUploadUnknown = "BLOB_UPLOAD_UNKNOWN"
	CodeDigestInvalid     = "DIGEST_INVALID"
	CodeManifestInvalid   = "MANIFEST_INVALID"
	CodeManifestUnknown   = "MANIFEST_UNKNOWN"
	CodeNameInvalid       = "NAME_INVALID"
	CodeNameUnknown       = "NAME_UNKNOWN"
	CodeSizeInvalid       = "SIZE_INVALID"
	CodeUnauthorized      = "UNAUTHORIZED"
	CodeDenied            = "DENIED"
	CodeUnsupported       = "UNSUPPORTED"
)

type ociError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ociErrors struct {
	Errors []ociError `json:"errors"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ociErrors{Errors: []ociError{{Code: code, Message: msg}}})
}
