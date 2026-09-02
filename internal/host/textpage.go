/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

// contentTypeFor maps a KDexPage's spec.mimeType enum value to the
// Content-Type header a text-mime page is served with. spec.mimeType is
// kubebuilder-enum-restricted to txt/json/yaml/markdown/xml (see
// kdex-crds api/v1alpha1/kdexpage_types.go), so the default case below only
// ever fires for the zero value -- pageHandlerFunc's `ph.Page.MimeType != ""`
// gate never routes an unrecognised value here.
func contentTypeFor(mime string) string {
	switch mime {
	case "txt":
		return "text/plain; charset=utf-8"
	case "json":
		return "application/json"
	case "yaml":
		return "application/yaml"
	case "markdown":
		return "text/markdown; charset=utf-8"
	case "xml":
		return "application/xml"
	default:
		return "text/plain; charset=utf-8"
	}
}
