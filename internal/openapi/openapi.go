package openapi

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	openapi "github.com/getkin/kin-openapi/openapi3"
)

func ArrayQueryParam(name string, description string) *openapi.ParameterRef {
	schema := openapi.NewArraySchema()
	schema.Items = openapi.NewSchemaRef("", openapi.NewStringSchema())
	return &openapi.ParameterRef{
		Value: &openapi.Parameter{
			Description: description,
			Explode:     new(true),
			In:          "query",
			Name:        name,
			Required:    false,
			Schema:      openapi.NewSchemaRef("", schema),
		},
	}
}

func ExtractParameters(routePath string, query string, header http.Header) openapi.Parameters {
	routePath = strings.ReplaceAll(routePath, "{$}", "")

	var params openapi.Parameters

	// Regular expression to match path parameters: {name} or {name...}
	paramRegex := regexp.MustCompile(`\{([^}]+)\}`)
	matches := paramRegex.FindAllStringSubmatch(routePath, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		paramName := match[1]
		isWildcard := strings.HasSuffix(paramName, "...")

		// Clean the parameter name
		cleanName := strings.TrimSuffix(paramName, "...")

		// Create parameter description based on name
		description := fmt.Sprintf("Path parameter: %s", cleanName)
		if isWildcard {
			description = fmt.Sprintf("Wildcard path parameter: %s (captures remaining path segments)", cleanName)
		}

		// Determine schema type
		schema := openapi.NewStringSchema()
		if isWildcard {
			// Wildcard parameters can contain slashes and multiple segments
			schema.Description = "May contain multiple path segments separated by slashes"
		}

		param := &openapi.Parameter{
			Description: description,
			In:          "path",
			Name:        cleanName,
			Required:    true,
			Schema:      openapi.NewSchemaRef("", schema),
		}

		if isWildcard {
			param.AllowReserved = true
		}

		params = append(params, &openapi.ParameterRef{
			Value: param,
		})
	}

	// Parse the query string for parameters
	if query != "" {
		// Track parameter occurrences to detect arrays
		paramCounts := make(map[string]int)

		// Parse query string manually to count occurrences
		for pair := range strings.SplitSeq(query, "&") {
			if pair == "" {
				continue
			}

			parts := strings.SplitN(pair, "=", 2)
			if len(parts) > 0 {
				key := parts[0]
				paramCounts[key]++
			}
		}

		// Create parameters for unique keys
		for paramName, count := range paramCounts {
			isArray := count > 1

			description := fmt.Sprintf("Query parameter: %s", paramName)
			if isArray {
				description = fmt.Sprintf("Query parameter: %s (array - multiple values supported)", paramName)
			}

			// Determine schema type
			var schema *openapi.Schema
			if isArray {
				schema = openapi.NewArraySchema()
				schema.Items = openapi.NewSchemaRef("", openapi.NewStringSchema())
			} else {
				schema = openapi.NewStringSchema()
			}

			param := &openapi.Parameter{
				Name:        paramName,
				In:          "query",
				Description: description,
				Required:    false, // Query parameters are typically optional
				Schema:      openapi.NewSchemaRef("", schema),
			}

			if isArray {
				param.Explode = new(true)
			}

			params = append(params, &openapi.ParameterRef{
				Value: param,
			})
		}
	}

	// Parse header parameters (Selective)
	skipHeaders := map[string]bool{
		"accept":                    true,
		"accept-encoding":           true,
		"accept-language":           true,
		"authorization":             true,
		"connection":                true,
		"content-length":            true,
		"content-type":              true,
		"cookie":                    true,
		"expect":                    true,
		"host":                      true,
		"if-match":                  true,
		"if-none-match":             true,
		"if-modified-since":         true,
		"if-unmodified-since":       true,
		"origin":                    true,
		"priority":                  true,
		"referer":                   true,
		"sec-ch-ua":                 true,
		"sec-ch-ua-mobile":          true,
		"sec-ch-ua-platform":        true,
		"sec-fetch-dest":            true,
		"sec-fetch-mode":            true,
		"sec-fetch-site":            true,
		"sec-fetch-user":            true,
		"upgrade-insecure-requests": true,
		"user-agent":                true,
		"x-forwarded-for":           true,
		"x-forwarded-host":          true,
		"x-forwarded-port":          true,
		"x-forwarded-proto":         true,
		"x-forwarded-server":        true,
		"x-real-ip":                 true,
	}

	for name := range header {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-kdex-") || skipHeaders[lowerName] {
			continue
		}
		schema := openapi.NewArraySchema()
		schema.Items = openapi.NewSchemaRef("", openapi.NewStringSchema())

		param := &openapi.Parameter{
			Name: name,
			In:   "header",
			Schema: &openapi.SchemaRef{
				Value: schema,
			},
		}
		params = append(params, &openapi.ParameterRef{
			Value: param,
		})
	}

	return params
}

func ExtractSchemaName(schemaString string) (string, error) {
	parsed, err := url.Parse(strings.TrimSuffix(schemaString, "/"))

	if err != nil {
		return "", err
	}

	base := parsed.Path

	if strings.Contains(base, "/") {
		base = path.Base(base)
	}

	if base == "" {
		base = parsed.Host
	}

	if base == "" && parsed.Fragment != "" {
		base = parsed.Fragment
	}

	base = strings.TrimPrefix(base, "#")
	base = strings.TrimPrefix(base, "/components/schemas/")

	return base, nil
}

func GenerateNameFromPath(routePath string, headerValue string) string {
	if headerValue != "" {
		return headerValue
	}

	cleanPath := strings.NewReplacer("{", "", "}", "", ".", "-", "$", "", " ", "-", "[", "", "]", "").Replace(routePath)
	name := strings.ToLower(cleanPath)
	name = strings.ReplaceAll(name, "/", "-")

	// Collapse multiple dashes and trim
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-'
	})
	name = strings.Join(parts, "-")

	if name == "" {
		return "gen-root"
	}
	return "gen-" + name
}

func GenerateOperationID(name string, method string, headerValue string) string {
	if headerValue != "" {
		return headerValue
	}
	return fmt.Sprintf("%s-%s", name, strings.ToLower(method))
}

func Host(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost" // Best effort
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func InferSchema(val any) *openapi.SchemaRef {
	schema := openapi.NewSchema()

	switch v := val.(type) {
	case string:
		schema.Type = &openapi.Types{openapi.TypeString}
	case bool:
		schema.Type = &openapi.Types{openapi.TypeBoolean}
	case float64:
		// JSON unmarshals all numbers as float64 by default
		schema.Type = &openapi.Types{openapi.TypeNumber}
	case map[string]any:
		schema.Type = &openapi.Types{openapi.TypeObject}
		schema.Properties = make(openapi.Schemas)
		for key, subVal := range v {
			schema.Properties[key] = InferSchema(subVal)
		}
	case []any:
		schema.Type = &openapi.Types{openapi.TypeArray}
		if len(v) > 0 {
			// Infer item type from the first element
			schema.Items = InferSchema(v[0])
		}
	case nil:
		schema.Nullable = true
	}

	return schema.NewRef()
}

func MergeOperations(dest, src *OpenAPI) {
	for srcPath, srcItem := range src.Paths {
		destItem, ok := dest.Paths[srcPath]

		if !ok {
			dest.Paths[srcPath] = srcItem
		} else {
			if srcItem.Connect != nil {
				destItem.Connect = srcItem.Connect
			}
			if srcItem.Delete != nil {
				destItem.Delete = srcItem.Delete
			}
			if srcItem.Get != nil {
				destItem.Get = srcItem.Get
			}
			if srcItem.Head != nil {
				destItem.Head = srcItem.Head
			}
			if srcItem.Options != nil {
				destItem.Options = srcItem.Options
			}
			if srcItem.Patch != nil {
				destItem.Patch = srcItem.Patch
			}
			if srcItem.Post != nil {
				destItem.Post = srcItem.Post
			}
			if srcItem.Put != nil {
				destItem.Put = srcItem.Put
			}
			if srcItem.Trace != nil {
				destItem.Trace = srcItem.Trace
			}

			dest.Paths[srcPath] = destItem
		}
	}
}

func PathParam(name string, description string) *openapi.ParameterRef {
	return &openapi.ParameterRef{
		Value: &openapi.Parameter{
			Description: description,
			In:          "path",
			Name:        name,
			Required:    true,
			Schema:      openapi.NewSchemaRef("", openapi.NewStringSchema()),
		},
	}
}

func QueryParam(name string, description string) *openapi.ParameterRef {
	return &openapi.ParameterRef{
		Value: &openapi.Parameter{
			Description: description,
			In:          "query",
			Name:        name,
			Required:    false,
			Schema:      openapi.NewSchemaRef("", openapi.NewStringSchema()),
		},
	}
}

func WildcardPathParam(name string, description string) *openapi.ParameterRef {
	schema := openapi.NewStringSchema()
	schema.Description = "May contain multiple path segments separated by slashes"
	return &openapi.ParameterRef{
		Value: &openapi.Parameter{
			AllowReserved: true,
			Description:   description,
			In:            "path",
			Name:          name,
			Required:      true,
			Schema:        openapi.NewSchemaRef("", schema),
		},
	}
}
