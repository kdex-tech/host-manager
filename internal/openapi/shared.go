package openapi

import (
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	crdsopenapi "kdex.dev/crds/openapi"
)

// The document model and builder live in kdex.dev/crds/openapi so that
// in-cluster and client-side codegen render a function's one-off document from
// one implementation (FUNCTION_CONTRACT.md §2.1). They are aliased here so the
// rest of host-manager keeps addressing them through this package.

type (
	Builder  = crdsopenapi.Builder
	Filter   = crdsopenapi.Filter
	OpenAPI  = crdsopenapi.OpenAPI
	PathInfo = crdsopenapi.PathInfo
	PathItem = crdsopenapi.PathItem
	PathType = crdsopenapi.PathType
)

const (
	BackendPathType  = crdsopenapi.BackendPathType
	FunctionPathType = crdsopenapi.FunctionPathType
	PagePathType     = crdsopenapi.PagePathType
	SystemPathType   = crdsopenapi.SystemPathType
)

const (
	RespRefBadRequest          = crdsopenapi.RespRefBadRequest
	RespRefForbidden           = crdsopenapi.RespRefForbidden
	RespRefFound               = crdsopenapi.RespRefFound
	RespRefInternalServerError = crdsopenapi.RespRefInternalServerError
	RespRefNotFound            = crdsopenapi.RespRefNotFound
	RespRefSeeOther            = crdsopenapi.RespRefSeeOther
	RespRefUnauthorized        = crdsopenapi.RespRefUnauthorized
)

func FromKDexAPI(k *kdexv1alpha1.API) *OpenAPI {
	return crdsopenapi.FromKDexAPI(k)
}
