package sniffer

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
	openapi "github.com/getkin/kin-openapi/openapi3"
	kh "github.com/kdex-tech/host-manager/internal/http"
	"github.com/kdex-tech/host-manager/internal/mime"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/yuin/goldmark"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/linter"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TODO: support direct upload of JSON schema doc as the payload of a PUT request. This will
// be interpreted not as the litteral body but as the schema for the request body.
// TODO: Double check support for external schema references. (e.g. "Foo", "#/components/schemas/Foo" or a URL to an external schema)

const (
	docs = `
# KDex Request Sniffer Documentation

The KDex Request Sniffer automatically generates or updates KDexFunction resources by observing unhandled requests (404s).

## Supported Signals

### Custom HTTP Headers

- **X-KDex-Function-Comprehensive-Mode**: Set to "true" to enable Comprehensive API Modelling. This automatically generates a full suite of CRUD operations (GET, POST, PUT, PATCH, DELETE) for both collection and resource paths based on the pattern path.
- **X-KDex-Function-Deprecated**: Set to "true" to mark the operation as deprecated.
- **X-KDex-Function-Description**: Sets the OpenAPI operation description.
- **X-KDex-Function-Keep-Schema-Conflict**: Tells OpenAPI to keep conflicting under a special no-conflict key. Diagnostic feature.
- **X-KDex-Function-Name**: Specifies the name for the generated KDexFunction CR (standard Kubernetes naming rules apply).
- **X-KDex-Function-Operation-ID**: Sets a specific operationId in OpenAPI.
- **X-KDex-Function-Overwrite-Operation**: Set to "true" to overwrite an operation which is an exact match. Normally this would be rejected for satefy.
- **X-KDex-Function-Pattern-Path**: Specifies a net/http pattern path (e.g., "/users/{id}"). 
  - Must start with "/"
  - Must NOT contain a method (e.g. use "/users/{id}" not "GET /users/{id}")
  - Variables are supported: "{name}", "{path...}"
- **X-KDex-Function-Request-Schema-Ref**: Sets the OpenAPI operation request body schema reference. (e.g. "Foo", "#/components/schemas/Foo" or a URL to an external schema)
- **X-KDex-Function-Response-Schema-Ref**: Sets the OpenAPI operation response schema reference. (e.g. "Foo", "#/components/schemas/Foo" or a URL to an external schema)
- **X-KDex-Function-Security**: If present, the sniffer signals that the route requires authentication. It adds security requirements matching the semicolon deliminted (';') scheme names in the value and injects a "401 Unauthorized" response. Scopes can be included with the scheme name by appending a equal sign ('=') and a pipe delimited list or scopes. (e.g. "X-KDex-Function-Security: bearer=users:read|users:write;apiKey")
- **X-KDex-Function-Summary**: Sets the OpenAPI operation summary.
- **X-KDex-Function-Tags**: Comma-separated list of tags for the OpenAPI operation.

### Core Header Introspection

- **Accept**: If present and specific (not "*/*"), media types are used to populate the expected response "content" types in OpenAPI.
- **Content-Type**:
  - "application/json": The sniffer peeks at the body and infers a basic schema (types: string, number, boolean, object, array).
  - "application/x-www-form-urlencoded": The sniffer parses form fields and adds them as properties in the request body schema.

### Query Parameters

- Multi-value parameters (e.g., "?id=1&id=2") are detected and documented as "array" types in OpenAPI with "Explode: true".

---
*Note: The sniffer only processes non-internal paths (paths not starting with "/-/") that result in a 404.*
`
	TRUE = "true"
)

var jsonMimeRegex = regexp.MustCompile(`^application\/(.*\+)?json(;.*)?$`)
var urlSchemeRegex regexp.Regexp = *regexp.MustCompile("^https?://.*")

type AnalysisResult struct {
	OriginalRequest *http.Request
	Function        *kdexv1alpha1.KDexFunction
	Lints           []string
}

type RequestSniffer struct {
	BasePathRegex   regexp.Regexp
	CreateFunc      func(obj client.Object, f controllerutil.MutateFn) (controllerutil.OperationResult, error)
	Functions       func() []kdexv1alpha1.KDexFunction
	HostName        string
	ItemPathRegex   regexp.Regexp
	Namespace       string
	OpenAPIBuilder  func() *ko.Builder
	ReconcileTime   time.Time
	SecuritySchemes func() *openapi.SecuritySchemes
}

func (s *RequestSniffer) Analyze(r *http.Request) (*AnalysisResult, error) {
	res, err := s.analyze(r)
	if err != nil {
		return nil, err
	}
	fnMutated := res.Function
	if fnMutated == nil {
		// Nil function means sniff returned no result (e.g. internal path)
		return nil, nil
	}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fnMutated.Name,
			Namespace: fnMutated.Namespace,
		},
	}

	op, err := s.CreateFunc(
		fn,
		func() error {
			if fn.CreationTimestamp.IsZero() {
				fn.Annotations = make(map[string]string)
				fn.Labels = make(map[string]string)

				fn.Labels["app.kubernetes.io/name"] = "kdex-host"
				fn.Labels["kdex.dev/instance"] = s.HostName
			}

			fn.Spec = fnMutated.Spec

			if fn.CreationTimestamp.IsZero() {
				fn.Spec.HostRef = v1.LocalObjectReference{
					Name: s.HostName,
				}
			}

			return nil
		},
	)

	log := logf.FromContext(r.Context())

	log.V(2).Info(
		"sniffed function",
		"fnMutated", fnMutated,
		"op", op,
		"err", err,
	)

	return res, err
}

func (s *RequestSniffer) DocsHandler(w http.ResponseWriter, r *http.Request) {
	lastModified := s.ReconcileTime.UTC().Truncate(time.Second)
	etag := fmt.Sprintf(`"%d"`, lastModified.Unix())

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
	w.Header().Set("ETag", etag)

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		t, err := http.ParseTime(ifModifiedSince)
		if err == nil && !lastModified.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	var buf bytes.Buffer
	if err := goldmark.Convert([]byte(docs), &buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	htmlDoc := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>KDex Request Sniffer Documentation</title>
    <style>
        body { font-family: sans-serif; margin: 2rem; background-color: #333; color: #fff; line-height: 1.6; }
        code { background-color: #444; padding: 0.2rem 0.4rem; border-radius: 4px; }
        pre { background-color: #444; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        h1, h2, h3 { border-bottom: 1px solid #555; padding-bottom: 0.5rem; }
        li { margin-bottom: 0.5rem; }
    </style>
</head>
<body>
%s
</body>
</html>
`, buf.String())

	_, err := w.Write([]byte(htmlDoc))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *RequestSniffer) analyze(r *http.Request) (*AnalysisResult, error) {
	fn, err := s.sniff(r)
	if err != nil {
		return nil, err
	}

	res := &AnalysisResult{
		OriginalRequest: r,
		Function:        fn,
		Lints:           []string{},
	}

	if fn != nil {
		// Basic inference insights
		if r.Header.Get("X-KDex-Function-Security") != "" {
			res.Lints = append(res.Lints, "[inference] Detected 'X-KDex-Function-Security' header; secured endpoint inferred.")
		}
		if len(r.URL.Query()) > 0 {
			res.Lints = append(res.Lints, fmt.Sprintf("[inference] Detected %d query parameters.", len(r.URL.Query())))
		}

		// Run vacuum linter
		spec := s.OpenAPIBuilder().BuildOneOff(ko.Host(r), fn)
		specBytes, err := json.MarshalIndent(spec, "", "  ")
		if err == nil {
			lintResults, err := linter.LintSpec(specBytes)
			if err == nil {
				for _, result := range lintResults {
					res.Lints = append(res.Lints, fmt.Sprintf("[%s] %s (Line: %d)", result.RuleId, result.Message, result.StartNode.Line))
				}
			}
		}
	}

	return res, nil
}

func (s *RequestSniffer) calculatePaths(r *http.Request, patternPath string) (string, string, error) {
	requestPath := r.URL.Path

	if !s.BasePathRegex.MatchString(requestPath) {
		return "", "", fmt.Errorf("path %s must match %s", requestPath, s.BasePathRegex.String())
	}

	if patternPath == "" {
		return requestPath, requestPath, nil
	}

	if !s.ItemPathRegex.MatchString(patternPath) {
		return "", "", fmt.Errorf("pattern path %s must match %s", patternPath, s.ItemPathRegex.String())
	}

	match := s.ItemPathRegex.FindStringSubmatch(patternPath)
	namedGroups := make(map[string]string)
	if len(match) > 0 {
		for i, name := range s.ItemPathRegex.SubexpNames() {
			if i != 0 && name != "" {
				namedGroups[name] = match[i]
			}
		}
	}

	basePath := namedGroups["basePath"]

	if !strings.HasPrefix(patternPath, basePath) {
		return "", "", fmt.Errorf("pattern path %s must start with %s", patternPath, basePath)
	}

	// The pattern path must follow the net/http pattern rules
	if err := kh.ValidatePattern(patternPath, r); err != nil {
		return "", "", err
	}

	return basePath, patternPath, nil
}

func (s *RequestSniffer) matchExisting(
	items []kdexv1alpha1.KDexFunction,
	name string,
	basePath string,
	routePath string,
	method string,
	operationId string,
) (*kdexv1alpha1.KDexFunction, bool) {
	for i := range items {
		fn := &items[i]

		if basePath != fn.Spec.API.BasePath {
			continue
		}

		if len(fn.Spec.API.Paths) == 0 {
			// a function matching by name but no api.paths is an exact match
			return fn, true
		}

		for curPath, curPathItem := range fn.Spec.API.Paths {
			existingOp := curPathItem.GetOp(method)

			// names match, we must return it
			if name == fn.Name {
				if (routePath == curPath) &&
					(existingOp != nil) &&
					(operationId == existingOp.OperationID) {

					return fn, true
				}

				return fn, false
			}

			if (routePath == curPath) &&
				(existingOp != nil) &&
				(operationId == existingOp.OperationID) {

				return fn, false
			}
		}
	}

	return nil, false
}

func (s *RequestSniffer) mergeAPIIntoFunction(
	out *kdexv1alpha1.KDexFunction,
	in map[string]*openapi.PathItem,
	schemas map[string]*openapi.SchemaRef,
	overwriteOperation bool,
	keepConflictedSchemas bool,
) {
	if out.Spec.API.Paths == nil {
		out.Spec.API.Paths = map[string]kdexv1alpha1.PathItem{}
	}

	for inPath, inItem := range in {
		outItem := out.Spec.API.Paths[inPath]

		if overwriteOperation {
			outItem.Description = inItem.Description
			outItem.Summary = inItem.Summary
		}

		outParams := outItem.GetParameters()
		for _, inParam := range inItem.Parameters {
			if inParam.Ref != "" {
				continue
			}
			found := false
			for odx, outParam := range outParams {
				if inParam.Value.Name == outParam.Name &&
					inParam.Value.In == outParam.In {
					if overwriteOperation {
						outParams[odx] = *inParam.Value
					} else {
						found = true
					}
					break
				}
			}
			if !found {
				outParams = append(outParams, *inParam.Value)
			}
		}
		outItem.SetParameters(outParams)

		for _, method := range kh.Methods() {
			op := getOp(string(method), inItem)
			if op != nil {

				// If an op param is in shared (path) params, remove it from op
				for i := len(op.Parameters) - 1; i >= 0; i-- {
					if shouldDelete(outParams, op.Parameters[i]) {
						op.Parameters = append(op.Parameters[:i], op.Parameters[i+1:]...)
					}
				}

				outItem.SetOp(string(method), op)
			}
		}

		out.Spec.API.Paths[inPath] = outItem
	}

	// Merge schemas
	fnSchemas := out.Spec.API.GetSchemas()

	for key, schemaRef := range schemas {
		_, found := fnSchemas[key]
		if found && keepConflictedSchemas {
			key = key + ":conflict:" + rand.Text()[0:4]
		}

		fnSchemas[key] = schemaRef
	}

	out.Spec.API.SetSchemas(fnSchemas)
}

// nolint:gocyclo
func (s *RequestSniffer) parseRequestIntoAPI(
	r *http.Request,
	functionName string,
	routePath string,
	operationId string,
) (map[string]*openapi.PathItem, map[string]*openapi.SchemaRef, error) {
	pathItems := map[string]*openapi.PathItem{}
	schemas := map[string]*openapi.SchemaRef{}
	pathItem := &openapi.PathItem{
		Description: fmt.Sprintf("Auto-generated from request to %s", r.URL.Path),
	}

	op := &openapi.Operation{
		Deprecated:  strings.ToLower(r.Header.Get("X-KDex-Function-Deprecated")) == TRUE,
		OperationID: operationId,
		Parameters:  ko.ExtractParameters(routePath, r.URL.Query().Encode(), r.Header),
		Responses:   &openapi.Responses{},
	}

	tags := []string{}
	if tagsRaw := r.Header.Get("X-KDex-Function-Tags"); tagsRaw != "" {
		tags = strings.Split(tagsRaw, ",")
		for i := range tags {
			tags[i] = strings.TrimSpace(tags[i])
		}
	}
	tags = append(tags, functionName)
	op.Tags = tags

	op.Summary = r.Header.Get("X-KDex-Function-Summary")
	if op.Summary == "" {
		op.Summary = operationId
	}

	op.Description = r.Header.Get("X-KDex-Function-Description")
	if op.Description == "" {
		op.Description = fmt.Sprintf("%s %s", r.Method, routePath)
	}

	requestSchemaRef := ""
	requestSchemaIsExternal := false

	if r.Header.Get("X-KDex-Function-Request-Schema-Ref") != "" {
		ref := r.Header.Get("X-KDex-Function-Request-Schema-Ref")
		requestSchemaIsExternal = urlSchemeRegex.MatchString(ref)

		if !requestSchemaIsExternal &&
			!strings.HasPrefix(ref, "#/components/schemas/") {

			ref = "#/components/schemas/" + ref
		}
		requestSchemaRef = ref
	}

	responseSchemaRef := ""
	responseSchemaIsExternal := false

	if r.Header.Get("X-KDex-Function-Response-Schema-Ref") != "" {
		ref := r.Header.Get("X-KDex-Function-Response-Schema-Ref")
		responseSchemaIsExternal = urlSchemeRegex.MatchString(ref)

		if !responseSchemaIsExternal &&
			!strings.HasPrefix(ref, "http") && !strings.HasPrefix(ref, "#/components/schemas/") {

			ref = "#/components/schemas/" + ref
		}
		responseSchemaRef = ref
	}

	// Authentication signal
	if r.Header.Get("X-KDex-Function-Security") != "" {
		secValues := strings.Split(r.Header.Get("X-KDex-Function-Security"), ";")
		securityArgs := map[string][]string{}
		schemeNamesInOrder := []string{}
		for _, val := range secValues {
			secValue := strings.TrimSpace(val)
			var schemeName string
			var scopes []string
			if strings.Contains(secValue, "=") {
				parts := strings.SplitN(secValue, "=", 2)
				schemeName = strings.TrimSpace(parts[0])
				if strings.Contains(parts[1], "|") {
					for scope := range strings.SplitSeq(parts[1], "|") {
						scopes = append(scopes, strings.TrimSpace(scope))
					}
				} else {
					scopes = []string{strings.TrimSpace(parts[1])}
				}
			} else {
				schemeName = secValue
				scopes = []string{}
			}

			if schemeName != "" {
				securityArgs[schemeName] = scopes
				if !slices.Contains(schemeNamesInOrder, schemeName) {
					schemeNamesInOrder = append(schemeNamesInOrder, schemeName)
				}
			}
		}
		securitySchemes := s.SecuritySchemes()
		if securitySchemes != nil && len(*securitySchemes) > 0 && len(schemeNamesInOrder) > 0 {
			security := openapi.SecurityRequirements{}
			found := false
			for _, schemeName := range schemeNamesInOrder {
				if _, ok := (*securitySchemes)[schemeName]; ok {
					if args, ok := securityArgs[schemeName]; ok {
						security = append(security, openapi.NewSecurityRequirement().Authenticate(schemeName, args...))
						found = true
					}
				}
			}

			if found {
				op.Security = &security
				op.Responses.Set("401", &openapi.ResponseRef{
					Ref: ko.RespRefUnauthorized,
				})
			}
		}
	}

	// Process Request signals
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		// These methods are expected to have a body
		var body io.Reader = r.Body

		if r.ContentLength > 0 || r.Header.Get("Content-Type") != "" {
			contentType := strings.Split(r.Header.Get("Content-Type"), ";")[0]
			schema := openapi.NewSchema()
			var encoding map[string]*openapi.Encoding

			if !requestSchemaIsExternal {
				if contentType == "" {
					var err error
					var mt *mimetype.MIME
					mt, body, err = mime.Detect(body)

					if err != nil {
						return nil, nil, err
					}

					contentType = mt.String()
				}

				switch contentType {
				case "application/octet-stream":
					schema.Type = &openapi.Types{openapi.TypeString}
					schema.Format = "binary"
				case "multipart/form-data":
					mr, err := r.MultipartReader()
					if err != nil {
						return nil, nil, err
					}

					schema.Type = &openapi.Types{openapi.TypeObject}
					schema.Properties = openapi.Schemas{}
					encoding = map[string]*openapi.Encoding{}

					for {
						part, err := mr.NextPart()
						if err == io.EOF {
							break
						}
						if err != nil {
							return nil, nil, err
						}

						fieldName := part.FormName()

						_, isArray := schema.Properties[fieldName]

						if part.FileName() == "" {
							if isArray {
								schema.Properties[fieldName] = &openapi.SchemaRef{
									Value: &openapi.Schema{
										Type:  &openapi.Types{openapi.TypeArray},
										Items: openapi.NewStringSchema().NewRef(),
									},
								}
							} else {
								schema.Properties[fieldName] = openapi.NewStringSchema().NewRef()
							}
						} else {
							if isArray {
								schema.Properties[fieldName] = &openapi.SchemaRef{
									Value: &openapi.Schema{
										Type: &openapi.Types{openapi.TypeArray},
										Items: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Type:   &openapi.Types{openapi.TypeString},
												Format: "binary",
											},
										},
									},
								}
								continue // no need to parse out the content type again
							} else {
								schema.Properties[fieldName] = &openapi.SchemaRef{
									Value: &openapi.Schema{
										Format: "binary",
										Type:   &openapi.Types{openapi.TypeString},
									},
								}
							}

							partContentType := part.Header.Get("Content-Type")

							if partContentType == "" || partContentType == "application/octet-stream" {
								var err error
								var mt *mimetype.MIME
								mt, _, err = mime.Detect(part)

								if err != nil {
									return nil, nil, err
								}

								partContentType = mt.String()
							}

							encoding[fieldName] = &openapi.Encoding{
								ContentType: partContentType,
							}
						}
					}
				case "application/x-www-form-urlencoded":
					_ = r.ParseForm()
					schema.Type = &openapi.Types{openapi.TypeObject}
					schema.Properties = openapi.Schemas{}
					for name := range r.PostForm {
						schema.Properties[name] = &openapi.SchemaRef{
							Value: openapi.NewStringSchema(),
						}
					}
				}

				if isJSON(contentType) {
					bodyBytes, err := io.ReadAll(body)
					if err == nil {
						// Restore body for any subsequent uses
						// body = io.NopCloser(strings.NewReader(string(bodyBytes)))

						var data any
						if err := json.Unmarshal(bodyBytes, &data); err != nil {
							return nil, nil, err
						}

						schema = ko.InferSchema(data).Value
					}
				}
			}

			schema.Description = "Inferred from request body"

			op.RequestBody = &openapi.RequestBodyRef{
				Value: &openapi.RequestBody{
					Content:     openapi.NewContent(),
					Description: "The request body schema",
				},
			}

			var bodySchemaRef *openapi.SchemaRef

			if requestSchemaRef != "" {
				bodySchemaRef = &openapi.SchemaRef{
					Ref: requestSchemaRef,
				}

				schemaName, err := ko.ExtractSchemaName(requestSchemaRef)
				if err != nil {
					return nil, nil, err
				}

				if requestSchemaIsExternal {
					schemas[schemaName] = &openapi.SchemaRef{
						Ref: requestSchemaRef,
					}
				} else {
					schemas[schemaName] = &openapi.SchemaRef{
						Value: schema,
					}
				}
			} else {
				bodySchemaRef = &openapi.SchemaRef{
					Value: schema,
				}
			}

			op.RequestBody.Value.Content[contentType] = &openapi.MediaType{
				Schema:   bodySchemaRef,
				Encoding: encoding,
			}
		}
	default:
		// For GET, HEAD, etc., skip parsing.
		// You can optionally check if Content-Length > 0 to log a warning.
	}

	// Process Response signals

	resp := openapi.NewResponse().WithDescription("Successful response")
	accept := r.Header.Get("Accept")

	if r.Method == "HEAD" || r.Method == "CONNECT" {
		resp.Content = openapi.NewContent()
	} else if accept != "" {
		content := openapi.NewContent()

		var schemaRef *openapi.SchemaRef

		if responseSchemaRef != "" {
			schemaRef = &openapi.SchemaRef{
				Ref: responseSchemaRef,
			}

			schemaName, err := ko.ExtractSchemaName(responseSchemaRef)
			if err != nil {
				return nil, nil, err
			}

			if responseSchemaIsExternal {
				schemas[schemaName] = &openapi.SchemaRef{
					Ref: responseSchemaRef,
				}
			}
		}

		// Split by comma and handle types like application/json;q=0.9
		for t := range strings.SplitSeq(accept, ",") {
			mediaType := strings.TrimSpace(strings.Split(t, ";")[0])
			if mediaType == "" || mediaType == "*/*" {
				continue
			}
			content[mediaType] = &openapi.MediaType{
				Schema: schemaRef,
			}
		}

		if len(content) > 0 {
			resp.Content = content
		}
	}

	op.Responses.Set("200", &openapi.ResponseRef{
		Value: resp,
	})

	setOp(pathItem, r.Method, op)
	pathItems[routePath] = pathItem

	if strings.ToLower(r.Header.Get("X-KDex-Function-Comprehensive-Mode")) == TRUE {
		// Comprehensive Mode: Generate full CRUD suite
		// Determine base collection path and resource path
		var collectionPath, resourcePath string
		segments := strings.Split(routePath, "/")

		if len(segments) > 0 {
			lastSegment := segments[len(segments)-1]
			if strings.HasPrefix(lastSegment, "{") && strings.HasSuffix(lastSegment, "}") {
				// We are at a Resource Path (e.g., /v1/users/{id})
				resourcePath = routePath
				collectionPath = strings.Join(segments[:len(segments)-1], "/")
			} else {
				// We are at a Collection Path (e.g., /v1/users)
				collectionPath = routePath
				resourcePath = routePath + "/{id}"
			}

			// 1. Handle Collection Path (/resources)
			colItem, colExists := pathItems[collectionPath]
			if !colExists {
				colItem = &openapi.PathItem{
					Description: "Collection Operations",
				}
			}
			s.generateCollectionOperations(collectionPath, colItem, op, requestSchemaRef, responseSchemaRef)
			pathItems[collectionPath] = colItem

			// 2. Handle Resource Path (/resources/{id})
			resItem, resExists := pathItems[resourcePath]
			if !resExists {
				resItem = &openapi.PathItem{
					Description: "Resource Operations",
				}
			}
			s.generateResourceOperations(resourcePath, resItem, op, requestSchemaRef, responseSchemaRef)
			pathItems[resourcePath] = resItem
		}
	}

	return pathItems, schemas, nil
}

func (s *RequestSniffer) generateCollectionOperations(
	collectionPath string,
	item *openapi.PathItem,
	templateOp *openapi.Operation,
	reqRef, respRef string,
) {
	baseOperationID := ko.GenerateNameFromPath(collectionPath, "")

	// GET /resources (List)
	listOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "List Resources",
		Description: "List of resources.",
		OperationID: baseOperationID + "-get",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	// Add pagination params
	listOp.Parameters = append(listOp.Parameters,
		&openapi.ParameterRef{Value: &openapi.Parameter{Name: "limit", In: "query", Description: "Maximum number of items to return.", Schema: openapi.NewSchemaRef("", openapi.NewIntegerSchema().WithMin(1).WithMax(100))}},
		&openapi.ParameterRef{Value: &openapi.Parameter{Name: "offset", In: "query", Description: "Offset to start returning items from.", Schema: openapi.NewSchemaRef("", openapi.NewIntegerSchema().WithMin(0))}},
	)

	listResp := openapi.NewResponse().WithDescription("List of resources")
	if respRef != "" {
		listResp.Content = openapi.NewContent()
		listResp.Content["application/json"] = &openapi.MediaType{
			Schema: &openapi.SchemaRef{
				Value: &openapi.Schema{
					Type:  &openapi.Types{openapi.TypeArray},
					Items: &openapi.SchemaRef{Ref: respRef},
				},
			},
		}
	}
	listOp.Responses.Set("200", &openapi.ResponseRef{Value: listResp})
	item.Get = listOp

	// POST /resources (Create)
	postOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "Post Resource",
		Description: "Post a new resource.",
		OperationID: baseOperationID + "-post",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	if reqRef != "" {
		postOp.RequestBody = &openapi.RequestBodyRef{
			Value: &openapi.RequestBody{
				Content:     openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: reqRef}, []string{"application/json"}),
				Description: "The resource to create",
			},
		}
	}

	createResp := openapi.NewResponse().WithDescription("Resource created")
	if respRef != "" {
		createResp.Content = openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: respRef}, []string{"application/json"})
	}
	postOp.Responses.Set("201", &openapi.ResponseRef{Value: createResp})
	item.Post = postOp
}

func (s *RequestSniffer) generateResourceOperations(resourcePath string, item *openapi.PathItem, templateOp *openapi.Operation, reqRef, respRef string) {
	baseOperationID := ko.GenerateNameFromPath(resourcePath, "")

	// Extract path params from the resource path to ensure they are present
	pathParams := ko.ExtractParameters(resourcePath, "", http.Header{})

	// Add any non-path parameters from templateOp (e.g. headers, query from sniffed request)
	for _, p := range templateOp.Parameters {
		if p.Value != nil && p.Value.In != "path" {
			pathParams = append(pathParams, p)
		}
	}

	item.Parameters = pathParams

	// GET /resources/{id} (Get)
	getOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "Get Resource",
		Description: "Get a resource by ID.",
		OperationID: baseOperationID + "-get",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	getResp := openapi.NewResponse().WithDescription("Resource found")
	if respRef != "" {
		getResp.Content = openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: respRef}, []string{"application/json"})
	}
	getOp.Responses.Set("200", &openapi.ResponseRef{Value: getResp})
	item.Get = getOp

	// PUT /resources/{id} (Replace)
	putOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "Put Resource",
		Description: "Put a resource by ID.",
		OperationID: baseOperationID + "-put",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	if reqRef != "" {
		putOp.RequestBody = &openapi.RequestBodyRef{
			Value: &openapi.RequestBody{
				Content:     openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: reqRef}, []string{"application/json"}),
				Description: "The replaced resource",
			},
		}
	}
	putResp := openapi.NewResponse().WithDescription("Resource replaced")
	if respRef != "" {
		putResp.Content = openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: respRef}, []string{"application/json"})
	}
	putOp.Responses.Set("200", &openapi.ResponseRef{Value: putResp})
	item.Put = putOp

	// PATCH /resources/{id} (Update)
	patchOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "Patch Resource",
		Description: "Patch a resource by ID.",
		OperationID: baseOperationID + "-patch",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	if reqRef != "" {
		patchOp.RequestBody = &openapi.RequestBodyRef{
			Value: &openapi.RequestBody{
				Content:     openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: reqRef}, []string{"application/merge-patch+json"}),
				Description: "The patch to apply",
			},
		}
	}
	patchResp := openapi.NewResponse().WithDescription("Resource patched")
	if respRef != "" {
		patchResp.Content = openapi.NewContentWithSchemaRef(&openapi.SchemaRef{Ref: respRef}, []string{"application/json"})
	}
	patchOp.Responses.Set("200", &openapi.ResponseRef{Value: patchResp})
	item.Patch = patchOp

	// DELETE /resources/{id} (Delete)
	deleteOp := &openapi.Operation{
		Tags:        templateOp.Tags,
		Summary:     "Delete Resource",
		Description: "Delete a resource by ID.",
		OperationID: baseOperationID + "-delete",
		Responses:   &openapi.Responses{},
		Security:    templateOp.Security,
	}
	deleteOp.Responses.Set("204", &openapi.ResponseRef{Value: openapi.NewResponse().WithDescription("Resource deleted")})
	item.Delete = deleteOp
}

// Basic criteria: non-HTML GET/POST requests that are not found
// (This is called when HostHandler hits a 404)
func (s *RequestSniffer) sniff(r *http.Request) (*kdexv1alpha1.KDexFunction, error) {
	// Skip internal paths
	if strings.HasPrefix(r.URL.Path, "/-/") {
		return nil, nil
	}

	method := strings.ToUpper(r.Method)

	basePath, patternPath, err := s.calculatePaths(r, r.Header.Get("X-KDex-Function-Pattern-Path"))
	if err != nil {
		return nil, err
	}

	functionName := ko.GenerateNameFromPath(basePath, r.Header.Get("X-KDex-Function-Name"))
	patternName := ko.GenerateNameFromPath(patternPath, "")
	operationId := ko.GenerateOperationID(patternName, method, r.Header.Get("X-KDex-Function-Operation-ID"))

	// Check if a KDexFunction already exists for this path/method to avoid duplicates
	existing, exactMatch := s.matchExisting(s.Functions(), functionName, basePath, patternPath, method, operationId)
	if existing != nil && !existing.Spec.GetMetadata().AutoGenerated {
		return existing, fmt.Errorf("the function %s/%s can no longer be targeted for autogeneration: .spec.metadata.autoGenerated=false", existing.Name, existing.Namespace)
	}
	if exactMatch && r.Header.Get("X-KDex-Function-Overwrite-Operation") != TRUE {
		return existing, fmt.Errorf("found an exact match for the operation on function %s/%s %s that is being skipped for safety: set X-KDex-Function-Overwrite-Operation: true to overwrite", method, existing.Name, existing.Namespace)
	}

	if existing != nil {
		functionName = existing.Name
	}

	// Path-claim guard: matchExisting matches by basePath, so it misses the
	// case where a DIFFERENT function (different basePath, e.g. broader prefix
	// owned by a sibling function) declares the route path we're about to
	// claim. Creating a duplicate here produces a "duplicated path X" error
	// in KDexInternalHost.Reconcile that aborts every subsequent mux rebuild
	// on this host, taking down all routing. See kdex-tech/host-manager#31.
	if existing == nil {
		for i := range s.Functions() {
			fn := s.Functions()[i]
			if _, claimed := fn.Spec.API.Paths[patternPath]; claimed {
				return nil, nil
			}
			if patternPath != basePath {
				if _, claimed := fn.Spec.API.Paths[basePath]; claimed {
					return nil, nil
				}
			}
		}
	}

	pathItems, schemas, err := s.parseRequestIntoAPI(r, functionName, patternPath, operationId)

	if err != nil {
		return nil, err
	}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      functionName,
			Namespace: s.Namespace,
		},
	}

	if existing != nil {
		fn.Spec = existing.Spec
	} else {
		fn.Spec = kdexv1alpha1.KDexFunctionSpec{
			API: kdexv1alpha1.API{
				BasePath: basePath,
				Paths:    map[string]kdexv1alpha1.PathItem{},
			},
			Metadata: &kdexv1alpha1.KDexFunctionMetadata{
				AutoGenerated: true,
			},
		}
	}

	if fn.Spec.Metadata == nil {
		fn.Spec.Metadata = &kdexv1alpha1.KDexFunctionMetadata{}
	}

	found := false
	for _, tag := range fn.Spec.Metadata.Tags {
		if tag.Name == fn.Name {
			found = true
		}
	}
	if !found {
		fn.Spec.Metadata.Tags = append(fn.Spec.Metadata.Tags, kdexv1alpha1.Tag{
			Name: fn.Name,
		})
	}

	s.mergeAPIIntoFunction(
		fn,
		pathItems,
		schemas,
		r.Header.Get("X-KDex-Function-Overwrite-Operation") != TRUE,
		r.Header.Get("X-KDex-Function-Keep-Schema-Conflict") == TRUE)

	return fn, nil
}

func getOp(method string, calcItem *openapi.PathItem) *openapi.Operation {
	switch kh.MethodFromString(method) {
	case kh.Connect:
		return calcItem.Connect
	case kh.Delete:
		return calcItem.Delete
	case kh.Get:
		return calcItem.Get
	case kh.Head:
		return calcItem.Head
	case kh.Options:
		return calcItem.Options
	case kh.Patch:
		return calcItem.Patch
	case kh.Post:
		return calcItem.Post
	case kh.Put:
		return calcItem.Put
	case kh.Trace:
		return calcItem.Trace
	}
	return nil
}

func isJSON(mimeType string) bool {
	return jsonMimeRegex.MatchString(strings.ToLower(mimeType))
}

func setOp(item *openapi.PathItem, method string, op *openapi.Operation) {
	switch kh.MethodFromString(method) {
	case kh.Connect:
		item.Connect = op
	case kh.Delete:
		item.Delete = op
	case kh.Get:
		item.Get = op
	case kh.Head:
		item.Head = op
	case kh.Options:
		item.Options = op
	case kh.Patch:
		item.Patch = op
	case kh.Post:
		item.Post = op
	case kh.Put:
		item.Put = op
	case kh.Trace:
		item.Trace = op
	}
}

func shouldDelete(parameters []openapi.Parameter, parameterRef *openapi.ParameterRef) bool {
	if parameterRef.Value == nil {
		return false
	}
	for _, commonParam := range parameters {
		if parameterRef.Value.Name == commonParam.Name && parameterRef.Value.In == commonParam.In {
			return true
		}
	}
	return false
}
