package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"golang.org/x/text/language"
	"golang.org/x/text/message/catalog"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func NewTranslations(defaultLanguage string, translations map[string]kdexv1alpha1.KDexTranslationSpec) (*Translations, error) {
	// Register defaultLanguage as the catalog's Fallback so that
	// Languages() returns it first instead of in alphabetical order. Without
	// this, a host with "de"/"en"/"fr" translations returns [de, en, fr],
	// and any matcher fallback (e.g. plain curl with no Accept-Language)
	// resolves to "de" rather than the configured default.
	defaultTag := language.Make(defaultLanguage)
	catalogBuilder := catalog.NewBuilder(catalog.Fallback(defaultTag))

	if err := catalogBuilder.SetString(defaultTag, "_", "_"); err != nil {
		return nil, fmt.Errorf("failed to set default translation %s %s", defaultLanguage, "_")
	}

	keys := []string{}
	for name, translation := range translations {
		for _, tr := range translation.Translations {
			for key, value := range tr.KeysAndValues {
				if err := catalogBuilder.SetString(language.Make(tr.Lang), key, value); err != nil {
					return nil, fmt.Errorf("failed to set translation %s %s %s %s", name, tr.Lang, key, value)
				}
				keys = append(keys, key)
			}
		}
	}

	return &Translations{
		catalog: catalogBuilder,
		keys:    keys,
	}, nil
}

func (hh *HostHandler) TranslationGet(w http.ResponseWriter, r *http.Request) {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// applyCachingHeadersWithLang folds the language tag into the ETag
	// so en-CA and fr-CA responses to this URL get distinct ETags.
	// See kdex-tech/host-manager#43.
	if hh.applyCachingHeadersWithLang(w, r, nil, hh.reconcileTime, l.String()) {
		return
	}

	// Get all the keys and values for the given language
	keys := hh.Translations.Keys()
	// check query parameters for array of keys
	queryParams := r.URL.Query()
	keyParams := queryParams["key"]
	if len(keyParams) > 0 {
		keys = keyParams
	}

	keysAndValues := map[string]string{}
	printer := hh.messagePrinter(&hh.Translations, l)

	for _, key := range keys {
		keysAndValues[key] = printer.Sprintf(key)
		// replace each occurrence of the string `%!s(MISSING)` with a placeholder `{{n}}` where `n` is the alphabetic index of the placeholder
		parts := strings.Split(keysAndValues[key], "%!s(MISSING)")
		if len(parts) > 1 {
			var builder strings.Builder
			for i, part := range parts {
				builder.WriteString(part)
				if i < len(parts)-1 {
					// Convert index to alphabetic character (0 -> a, 1 -> b, etc.)
					placeholder := 'a' + i
					if placeholder > 'z' {
						// Fallback or handle wrap if more than 26 placeholders are present
						fmt.Fprintf(&builder, "{{%d}}", i)
					} else {
						fmt.Fprintf(&builder, "{{%c}}", placeholder)
					}
				}
			}
			keysAndValues[key] = builder.String()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(keysAndValues)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
