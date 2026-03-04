package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func DomainsToMatcher(domains []string) string {
	var buffer bytes.Buffer
	var joiner rune

	for _, domain := range domains {
		domain = strings.ReplaceAll(domain, ".", "\\.")
		if strings.HasPrefix(domain, "*\\.") {
			domain = "." + domain
		}
		if joiner != 0 {
			buffer.WriteRune(joiner)
		}
		buffer.WriteString(domain)
		joiner = '|'
	}

	return buffer.String()
}

type Stringer interface {
	String() string
}

func Hash[T any](s ...T) string {
	var buf bytes.Buffer
	for _, v := range s {
		switch v := any(v).(type) {
		case string:
			buf.WriteString(v)
		case []byte:
			buf.Write(v)
		case Stringer:
			buf.WriteString(v.String())
		default:
			fmt.Fprintf(&buf, "%v", v)
		}
	}
	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:])
}

func IfElse[T any](predicate bool, trueVal T, elseVal T) T {
	if predicate {
		return trueVal
	}
	return elseVal
}

func MapSlice[T any, U any](slice []T, mapper func(T) U) []U {
	result := make([]U, len(slice))
	for i, v := range slice {
		result[i] = mapper(v)
	}
	return result
}
