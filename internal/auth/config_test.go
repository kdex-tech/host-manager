package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kdex.dev/crds/api/v1alpha1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestNewConfig(t *testing.T) {
	type testargs struct {
		auth      *kdexv1alpha1.Auth
		namespace string
		devMode   bool
		secrets   kdexv1alpha1.Secrets
	}

	tests := []struct {
		name       string
		args       testargs
		assertions func(t *testing.T, got *Config, goterr error)
	}{
		{
			name: "constructor, no auth",
			args: testargs{
				auth:      nil,
				namespace: "foo",
				devMode:   false,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.Equal(t, &Config{}, got)
			},
		},
		{
			name: "constructor, empty auth",
			args: testargs{
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.NotNil(t, got.KeyPairs)
				assert.Equal(t, 1*time.Hour, got.TokenTTL)
			},
		},
		{
			name: "constructor, empty auth, devMode enabled, default TTL",
			args: testargs{
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.NotNil(t, got.KeyPairs)
				assert.Equal(t, 1*time.Hour, got.TokenTTL)
			},
		},
		{
			name: "constructor, devMode enabled, invalid TTL",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{
						TokenTTL: "?",
					},
				},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), "time: invalid duration")
			},
		},
		{
			name: "OIDC - constructor, no client id",
			args: testargs{
				auth: &v1alpha1.Auth{
					OIDCProvider: &v1alpha1.OIDCProvider{
						OIDCProviderURL: "http://bad",
					},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "oidc-client",
							},
						},
						Data: map[string][]byte{
							"client_secret": []byte("bar"),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), `OIDC secret does not contain 'client_id' or 'client-id'`)
			},
		},
		{
			name: "constructor, devMode enabled, with JWTKeysSecrets, secret not found",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   false,
				secrets:   nil,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), "no key pairs found")
			},
		},

		{
			name: "constructor, devMode enabled, with JWTKeysSecrets, secret no matching key",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						StringData: map[string]string{
							"foo": "",
						},
					},
				},
			},

			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), `secret does not contain private-key`)
			},
		},
		{
			name: "OIDC - constructor, secret defined but missing key",
			args: testargs{
				auth: &v1alpha1.Auth{
					OIDCProvider: &v1alpha1.OIDCProvider{
						OIDCProviderURL: "http://bad",
					},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "oidc-client",
							},
						},
						StringData: map[string]string{
							"foo": "bar",
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), `OIDC secret does not contain 'client_secret' or 'client-secret'`)
			},
		},
		{
			name: "constructor, devMode enabled, with JWTKeysSecrets, secret with invalid key",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8Jf`),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), "failed to decode PEM block containing private key")
			},
		},
		{
			name: "constructor, devMode enabled, with JWTKeysSecrets, secret with matching key (ECDSA P-256)",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.Equal(t, 1, len(*got.KeyPairs))
			},
		},
		{
			name: "constructor, devMode enabled, with JWTKeysSecrets, secret with matching key (RSA)",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAodh9j2EDujZ699rsSiqqv9oCItPSacdVlvDW7bwrkL3MzG3v
P2RUoU8FCg8JKiuqEq416a/DjWKcFaNg2semYoJXLTlwn+4X3zTIYoHCdQFRQ6MH
iUxy++Ty/zRGSVArZ0WH1tP8L828BYPqa9ljXSKS4ykn0L5kCBe1p/QB8/T8B/y1
+zAEt2uc8EUZVlDTrKCLP6/zubJtAmNaQuilGMnKzuMZ6S8VrJfc62b1r3SGO2X8
V3FxL6/WrqWko3jKemavM+5mGe0X5BZ9gSPM8pqlQkGhwhfoZf84bHYaW2E/uMhP
K8heKYRZJz122/LAxlGINvJDO8ubocdhrJ5JhQIDAQABAoIBAAzv/Ygpb6ms3Y3p
mgDgbJoofF+PV4nCzZ84F7OVBVXX2O1bOQhJZhB8/MCjQg7KbcPPhETEGu7hkUDo
41RUfa2bO1/EmzGq+o01BB2yag/TWqJ8VPJkl5PLkfcqP8Ia3qqt3rV4Evfj9iHq
ESJXlCn877P+oA2qN9yDv1mH17jKCJJo1+dNhcNWSeOA/JknguCwU0zY2whA0HZN
hDG4wp1LL+KcnhLETPP6Qvl5/ff82G2yMqpK5W+5VROSzqC86D84Nbp6iT4QGjbA
f08uLWimFS7bStgmvsch1WNBRJIZeTaslR0CoT3bV5CRyBJGLyDA9UY6pG68Hdmx
ezxG9xECgYEAz4GV9KOvw4cEhPNb0lwv4KZd3DQ1o4K2/8tMjpRkWx0tZnf2djkI
OEPW1eTrSeSuZTXtaEu+XDF/VgV/kuXrlqDpPV7kBdbmPt0GoplbCtmvZRrPbCzN
AKFvAs+CeG/OB9a6L89srn4Cv+SG5StWv3KRQOLR17VPvzaDbM5KRikCgYEAx6sv
amkUfGexH2B3Fs4Dh8+oxfAtuNbg8F+f0uC2XCyyvUTYCI2HRDWW0V38tk6wLyZT
vYAtKYCoAW9asB7dvgk1qcx+DAU6KN+Tfyau77bFtqxKA/ZxEJv/zT9j83WYL/OP
IWzF+TBzJ43aFnKPzTkQ7inrNJLUBNtMckUfu/0CgYBziHn+eLiey+j3QSvppsw9
b0OpHCSVQm0zZHTemb56gHdLqxU9Y6mw8gyGkOtz+/Ahh/ID9NArMp/sPCl4l60g
87yJH/EjUzBk5dkQ5QOsueEPEOtWFmeZp0hQr0q8VbvH34VQo1Omn6BWSR3WMNge
xeIb123whRG+q9Jm3UC7aQKBgDkbRNxyYWGTZp1KwcTL90aIpgS2xNzw2DTnpJZz
nrSONDDd18vabq2bhh8renPJ3aoelCTG3CPaoDKI3q8wpMsNZ0PBMOvPMustxsm/
DpmQ9MtiS2kGux+8/lR9pOCk6XoNdwpgSd8TdFwDvjRdX7OadrUnWBYZSHp7Hkow
avshAoGBAMtIw1LXeHrm4x7ngdRPEsyRQ2yKfvbHtgpIWtl9rcEQPoFC+slOlvoA
xY164RiE6GkAlFI0HwC6Xidg9xRgxNzAC70PjxKS9r2SVOZlsSpN3QE88CBZx62F
ZMtAm8mrV+h0ef/lr6zdJffz/EmM5MZrRAu2/dcK6S6qSEkwCTZ4
-----END RSA PRIVATE KEY-----`),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.Equal(t, 1, len(*got.KeyPairs))
			},
		},
		{
			name: "constructor, with JWTKeysSecrets, multiple keys, none selected as active, newest selected",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "foo",
							Namespace:         "foo",
							CreationTimestamp: metav1.NewTime(time.Now().Add(-24 * time.Hour)),
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAodh9j2EDujZ699rsSiqqv9oCItPSacdVlvDW7bwrkL3MzG3v
P2RUoU8FCg8JKiuqEq416a/DjWKcFaNg2semYoJXLTlwn+4X3zTIYoHCdQFRQ6MH
iUxy++Ty/zRGSVArZ0WH1tP8L828BYPqa9ljXSKS4ykn0L5kCBe1p/QB8/T8B/y1
+zAEt2uc8EUZVlDTrKCLP6/zubJtAmNaQuilGMnKzuMZ6S8VrJfc62b1r3SGO2X8
V3FxL6/WrqWko3jKemavM+5mGe0X5BZ9gSPM8pqlQkGhwhfoZf84bHYaW2E/uMhP
K8heKYRZJz122/LAxlGINvJDO8ubocdhrJ5JhQIDAQABAoIBAAzv/Ygpb6ms3Y3p
mgDgbJoofF+PV4nCzZ84F7OVBVXX2O1bOQhJZhB8/MCjQg7KbcPPhETEGu7hkUDo
41RUfa2bO1/EmzGq+o01BB2yag/TWqJ8VPJkl5PLkfcqP8Ia3qqt3rV4Evfj9iHq
ESJXlCn877P+oA2qN9yDv1mH17jKCJJo1+dNhcNWSeOA/JknguCwU0zY2whA0HZN
hDG4wp1LL+KcnhLETPP6Qvl5/ff82G2yMqpK5W+5VROSzqC86D84Nbp6iT4QGjbA
f08uLWimFS7bStgmvsch1WNBRJIZeTaslR0CoT3bV5CRyBJGLyDA9UY6pG68Hdmx
ezxG9xECgYEAz4GV9KOvw4cEhPNb0lwv4KZd3DQ1o4K2/8tMjpRkWx0tZnf2djkI
OEPW1eTrSeSuZTXtaEu+XDF/VgV/kuXrlqDpPV7kBdbmPt0GoplbCtmvZRrPbCzN
AKFvAs+CeG/OB9a6L89srn4Cv+SG5StWv3KRQOLR17VPvzaDbM5KRikCgYEAx6sv
amkUfGexH2B3Fs4Dh8+oxfAtuNbg8F+f0uC2XCyyvUTYCI2HRDWW0V38tk6wLyZT
vYAtKYCoAW9asB7dvgk1qcx+DAU6KN+Tfyau77bFtqxKA/ZxEJv/zT9j83WYL/OP
IWzF+TBzJ43aFnKPzTkQ7inrNJLUBNtMckUfu/0CgYBziHn+eLiey+j3QSvppsw9
b0OpHCSVQm0zZHTemb56gHdLqxU9Y6mw8gyGkOtz+/Ahh/ID9NArMp/sPCl4l60g
87yJH/EjUzBk5dkQ5QOsueEPEOtWFmeZp0hQr0q8VbvH34VQo1Omn6BWSR3WMNge
xeIb123whRG+q9Jm3UC7aQKBgDkbRNxyYWGTZp1KwcTL90aIpgS2xNzw2DTnpJZz
nrSONDDd18vabq2bhh8renPJ3aoelCTG3CPaoDKI3q8wpMsNZ0PBMOvPMustxsm/
DpmQ9MtiS2kGux+8/lR9pOCk6XoNdwpgSd8TdFwDvjRdX7OadrUnWBYZSHp7Hkow
avshAoGBAMtIw1LXeHrm4x7ngdRPEsyRQ2yKfvbHtgpIWtl9rcEQPoFC+slOlvoA
xY164RiE6GkAlFI0HwC6Xidg9xRgxNzAC70PjxKS9r2SVOZlsSpN3QE88CBZx62F
ZMtAm8mrV+h0ef/lr6zdJffz/EmM5MZrRAu2/dcK6S6qSEkwCTZ4
-----END RSA PRIVATE KEY-----`),
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:              "bar",
							Namespace:         "foo",
							CreationTimestamp: metav1.NewTime(time.Now().Add(-5 * 24 * time.Hour)),
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.Equal(t, "foo", got.ActivePair.KeyId)
			},
		},
		{
			name: "constructor, with JWTKeysSecrets, multiple keys, one selected as active",
			args: testargs{
				auth: &kdexv1alpha1.Auth{
					JWT: kdexv1alpha1.JWT{},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAodh9j2EDujZ699rsSiqqv9oCItPSacdVlvDW7bwrkL3MzG3v
P2RUoU8FCg8JKiuqEq416a/DjWKcFaNg2semYoJXLTlwn+4X3zTIYoHCdQFRQ6MH
iUxy++Ty/zRGSVArZ0WH1tP8L828BYPqa9ljXSKS4ykn0L5kCBe1p/QB8/T8B/y1
+zAEt2uc8EUZVlDTrKCLP6/zubJtAmNaQuilGMnKzuMZ6S8VrJfc62b1r3SGO2X8
V3FxL6/WrqWko3jKemavM+5mGe0X5BZ9gSPM8pqlQkGhwhfoZf84bHYaW2E/uMhP
K8heKYRZJz122/LAxlGINvJDO8ubocdhrJ5JhQIDAQABAoIBAAzv/Ygpb6ms3Y3p
mgDgbJoofF+PV4nCzZ84F7OVBVXX2O1bOQhJZhB8/MCjQg7KbcPPhETEGu7hkUDo
41RUfa2bO1/EmzGq+o01BB2yag/TWqJ8VPJkl5PLkfcqP8Ia3qqt3rV4Evfj9iHq
ESJXlCn877P+oA2qN9yDv1mH17jKCJJo1+dNhcNWSeOA/JknguCwU0zY2whA0HZN
hDG4wp1LL+KcnhLETPP6Qvl5/ff82G2yMqpK5W+5VROSzqC86D84Nbp6iT4QGjbA
f08uLWimFS7bStgmvsch1WNBRJIZeTaslR0CoT3bV5CRyBJGLyDA9UY6pG68Hdmx
ezxG9xECgYEAz4GV9KOvw4cEhPNb0lwv4KZd3DQ1o4K2/8tMjpRkWx0tZnf2djkI
OEPW1eTrSeSuZTXtaEu+XDF/VgV/kuXrlqDpPV7kBdbmPt0GoplbCtmvZRrPbCzN
AKFvAs+CeG/OB9a6L89srn4Cv+SG5StWv3KRQOLR17VPvzaDbM5KRikCgYEAx6sv
amkUfGexH2B3Fs4Dh8+oxfAtuNbg8F+f0uC2XCyyvUTYCI2HRDWW0V38tk6wLyZT
vYAtKYCoAW9asB7dvgk1qcx+DAU6KN+Tfyau77bFtqxKA/ZxEJv/zT9j83WYL/OP
IWzF+TBzJ43aFnKPzTkQ7inrNJLUBNtMckUfu/0CgYBziHn+eLiey+j3QSvppsw9
b0OpHCSVQm0zZHTemb56gHdLqxU9Y6mw8gyGkOtz+/Ahh/ID9NArMp/sPCl4l60g
87yJH/EjUzBk5dkQ5QOsueEPEOtWFmeZp0hQr0q8VbvH34VQo1Omn6BWSR3WMNge
xeIb123whRG+q9Jm3UC7aQKBgDkbRNxyYWGTZp1KwcTL90aIpgS2xNzw2DTnpJZz
nrSONDDd18vabq2bhh8renPJ3aoelCTG3CPaoDKI3q8wpMsNZ0PBMOvPMustxsm/
DpmQ9MtiS2kGux+8/lR9pOCk6XoNdwpgSd8TdFwDvjRdX7OadrUnWBYZSHp7Hkow
avshAoGBAMtIw1LXeHrm4x7ngdRPEsyRQ2yKfvbHtgpIWtl9rcEQPoFC+slOlvoA
xY164RiE6GkAlFI0HwC6Xidg9xRgxNzAC70PjxKS9r2SVOZlsSpN3QE88CBZx62F
ZMtAm8mrV+h0ef/lr6zdJffz/EmM5MZrRAu2/dcK6S6qSEkwCTZ4
-----END RSA PRIVATE KEY-----`),
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "bar",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "jwt-keys",
								"kdex.dev/active-key":  "true",
							},
						},
						Data: map[string][]byte{
							"private-key": []byte(`-----BEGIN PRIVATE KEY-----
KID: kdex-dev-1769451504

MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXufwXet+BRiqMQDn
7lWcoIgz6AVTAKOOJXlOz8JfxR2hRANCAASq6yLdpv9BkUW8SumvAkl+13QaAFDY
L51w6mkJ5U6GWpH1eZsXgKm0ZZJKEPsN9wYKe2LXT/WPpa5AwGzo7BLm
-----END PRIVATE KEY-----`),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.NotNil(t, got.ActivePair)
				assert.Equal(t, "kdex-dev-1769451504", got.ActivePair.KeyId)
				assert.Equal(t, 2, len(*got.KeyPairs))
			},
		},
		{
			name: "OIDC - constructor, secret defined, valid key",
			args: testargs{
				auth: &v1alpha1.Auth{
					OIDCProvider: &v1alpha1.OIDCProvider{
						OIDCProviderURL: "http://bad",
					},
				},
				namespace: "foo",
				devMode:   true,
				secrets: kdexv1alpha1.Secrets{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "foo",
							Annotations: map[string]string{
								"kdex.dev/secret-type": "oidc-client",
							},
						},
						Data: map[string][]byte{
							"client_secret": []byte("bar"),
							"client_id":     []byte("foo"),
						},
					},
				},
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", got.OIDC.ClientSecret)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

			configBuilder := NewConfigBuilder().WithAuthClientLoader(
				func() (map[string]AuthClient, error) {
					return AuthClientLoader(tt.args.secrets)
				},
			).WithKeyLoader(
				func() (*keys.KeyPairs, error) {
					return keys.LoadOrGenerateKeyPair(
						tt.args.secrets,
						tt.args.devMode)
				},
			).WithOIDCClientConfigLoader(
				func() (*OIDCClientConfig, error) {
					return OIDCConfigLoader(tt.args.secrets, tt.args.devMode)
				},
			).WithAudience(
				"audience",
			).WithIssuer(
				"issuer",
			).WithDevMode(
				tt.args.devMode,
			).WithCacheManager(
				cacheManager,
			)

			got, gotErr := configBuilder.Build(tt.args.auth)
			tt.assertions(t, got, gotErr)
		})
	}
}

func claimStrings(v any) []string {
	out := []string{}
	switch l := v.(type) {
	case []any:
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, l...)
	}
	return out
}

// TestEnrichAuthContext pins the auth-context enrichment invariant: the given
// ClaimMappings mapper is applied to an authContext in place, so any external
// enrichment a mapping performs (folding a backend-supplied source claim into
// entitlements) is reflected before anything reads the context. The source claim
// name is deliberately ARBITRARY (extra_grants) — no claim is special-cased in
// code; ClaimMappings are the generic enrichment mechanism. See #142.
func TestEnrichAuthContext(t *testing.T) {
	mapper, err := dmapper.NewMapper([]dmapper.MappingRule{{
		SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.extra_grants) ? self.extra_grants : [])`,
		TargetPropPath:   "entitlements",
	}})
	require.NoError(t, err)

	t.Run("folds an arbitrary external source claim into entitlements", func(t *testing.T) {
		ac := AuthContext{
			"entitlements": []any{"functions:x:read"},
			"extra_grants": []any{"resource:r1:all"},
		}
		EnrichAuthContext(ac, mapper)
		got := claimStrings(ac["entitlements"])
		assert.Contains(t, got, "functions:x:read")
		assert.Contains(t, got, "resource:r1:all", "the mapping must fold the external claim into entitlements")
	})

	t.Run("idempotent when the source claim is absent (already-enriched context)", func(t *testing.T) {
		ac := AuthContext{"entitlements": []any{"functions:x:read"}}
		EnrichAuthContext(ac, mapper)
		assert.Equal(t, []string{"functions:x:read"}, claimStrings(ac["entitlements"]))
	})

	t.Run("nil mapper / nil context is a safe no-op", func(t *testing.T) {
		require.NotPanics(t, func() {
			EnrichAuthContext(AuthContext{}, nil)
			EnrichAuthContext(nil, mapper)
		})
	})
}

// authCookieCleared reports whether the response clears the named cookie
// (Max-Age < 0), i.e. the middleware invalidated a stale session cookie.
func authCookieCleared(w *httptest.ResponseRecorder, name string) bool {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == name && ck.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestConfig_AddAuthentication(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(t.Output()), zap.UseDevMode(true)))

	type testargs struct {
		c         client.Client
		auth      *kdexv1alpha1.Auth
		namespace string
		devMode   bool
		secrets   kdexv1alpha1.Secrets
	}

	tests := []struct {
		name       string
		args       testargs
		assertions func(t *testing.T, got *Config, goterr error)
	}{
		{
			name: "authentication middleware skipped when no auth",
			args: testargs{
				c:         nil,
				auth:      nil,
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				handler := got.AddAuthentication(mux, nil)
				assert.NotNil(t, handler)
				assert.True(t, mux == handler)
			},
		},
		{
			name: "authentication middleware added when auth",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				handler := got.AddAuthentication(mux, nil)
				assert.NotNil(t, handler)
				assert.True(t, mux != handler)
			},
		},
		{
			name: "authentication - no header",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)
				handler.ServeHTTP(w, r)
				assert.Equal(t, 200, w.Code)
			},
		},
		{
			name: "authentication - Authorization header with bad token",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)
				r.Header.Set("Authorization", "Bearer foo")
				handler.ServeHTTP(w, r)
				assert.Equal(t, 401, w.Code)
				assert.Contains(t, w.Body.String(), "Invalid token")
			},
		},
		{
			name: "authentication - Authorization header with bad format",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)
				r.Header.Set("Authorization", "Bearer foo bar")
				handler.ServeHTTP(w, r)
				assert.Equal(t, 400, w.Code)
				assert.Contains(t, w.Body.String(), "Invalid Authorization header format")
			},
		},
		{
			name: "authentication - Cookie invalid token",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)
				r.Header.Set(COOKIE, "auth_token=foo")
				handler.ServeHTTP(w, r)
				// An unparseable cookie is treated like NO cookie: cleared and
				// passed through anonymously so the wrapped handler decides. The
				// old behavior hard-redirected to "/". See #141.
				assert.Equal(t, 200, w.Code)
				assert.True(t, authCookieCleared(w, "auth_token"), "invalid auth_token cookie must be cleared")
			},
		},
		{
			name: "authentication - Authorization header signed token",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)

				token, err := got.Signer.Sign(jwt.MapClaims{
					"sub":   "foo",
					"email": "foo@foo.bar",
					"iss":   got.Issuer,
					"aud":   got.Audience,
				})
				if assert.NoError(t, err) {
					r.Header.Set("Authorization", "Bearer "+token)
					handler.ServeHTTP(w, r)
					assert.Equal(t, 200, w.Code)
				}
			},
		},
		{
			name: "authentication - Cookie signed token",
			args: testargs{
				c:         nil,
				auth:      &kdexv1alpha1.Auth{},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				assert.NoError(t, gotErr)
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)

				token, err := got.Signer.Sign(jwt.MapClaims{
					"sub":   "foo",
					"email": "foo@foo.bar",
					"iss":   got.Issuer,
					"aud":   got.Audience,
				})

				assert.Nil(t, err)

				r.Header.Set(COOKIE, "auth_token="+token)
				handler.ServeHTTP(w, r)
				assert.Equal(t, 200, w.Code)
			},
		},
		{
			name: "authentication - Cookie token expired",
			args: testargs{
				c: nil,
				auth: &kdexv1alpha1.Auth{
					ClaimMappings: []dmapper.MappingRule{
						{
							SourceExpression: "-1",
							TargetPropPath:   "exp",
							Required:         true,
						},
					},
				},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				mux.Handle("GET /foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/foo", http.NoBody)

				token, err := got.Signer.Sign(jwt.MapClaims{
					"sub":   "foo",
					"email": "foo@foo.bar",
					"iss":   got.Issuer,
					"aud":   got.Audience,
				})

				assert.Nil(t, err)

				r.Header.Set(COOKIE, "auth_token="+token)
				handler.ServeHTTP(w, r)
				// Expired cookie -> cleared + anonymous fall-through (was 303 -> "/"). See #141.
				assert.Equal(t, 200, w.Code)
				assert.True(t, authCookieCleared(w, "auth_token"), "expired auth_token cookie must be cleared")
			},
		},
		{
			name: "authentication - #141 expired cookie lets authorize redirect to login not root",
			args: testargs{
				c: nil,
				auth: &kdexv1alpha1.Auth{
					ClaimMappings: []dmapper.MappingRule{
						{SourceExpression: "-1", TargetPropPath: "exp", Required: true},
					},
				},
				namespace: "foo",
				devMode:   true,
			},
			assertions: func(t *testing.T, got *Config, gotErr error) {
				mux := http.NewServeMux()
				// Mimic AuthorizeHandler's anonymous branch: no auth context -> login.
				mux.Handle("GET /-/oauth/authorize", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, ok := GetAuthContext(r.Context()); !ok {
						http.Redirect(w, r, "/-/login?return="+r.URL.RequestURI(), http.StatusSeeOther)
						return
					}
					w.WriteHeader(200)
				}))
				handler := got.AddAuthentication(mux, nil)
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/-/oauth/authorize?client_id=mcp&response_type=code", http.NoBody)

				token, err := got.Signer.Sign(jwt.MapClaims{
					"sub": "foo", "iss": got.Issuer, "aud": got.Audience,
				})
				assert.Nil(t, err)
				r.Header.Set(COOKIE, "auth_token="+token) // expired via the exp=-1 mapping

				handler.ServeHTTP(w, r)

				// The stale cookie must NOT abort the OAuth flow to root; it must
				// fall through so AuthorizeHandler redirects to login, preserving
				// the in-flight authorize request. See #141.
				assert.Equal(t, http.StatusSeeOther, w.Code)
				loc := w.Header().Get("Location")
				assert.Contains(t, loc, "/-/login", "expired cookie must not abort the OAuth flow to root")
				assert.Contains(t, loc, "client_id=mcp", "the in-flight authorize request must be preserved")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

			configBuilder := NewConfigBuilder().WithAuthClientLoader(
				func() (map[string]AuthClient, error) {
					return AuthClientLoader(tt.args.secrets)
				},
			).WithKeyLoader(
				func() (*keys.KeyPairs, error) {
					return keys.LoadOrGenerateKeyPair(
						tt.args.secrets,
						tt.args.devMode)
				},
			).WithOIDCClientConfigLoader(
				func() (*OIDCClientConfig, error) {
					return OIDCConfigLoader(tt.args.secrets, tt.args.devMode)
				},
			).WithAudience(
				"audience",
			).WithIssuer(
				"issuer",
			).WithDevMode(
				tt.args.devMode,
			).WithCacheManager(
				cacheManager,
			)

			got, gotErr := configBuilder.Build(tt.args.auth)
			tt.assertions(t, got, gotErr)
		})
	}
}

func TestConfig_OIDC(t *testing.T) {
	extra := map[string]any{
		"firstName": "Joe",
		"lastName":  "Bar",
		"address": map[string]any{
			"street":  "1 Long Dr",
			"city":    "Baytown",
			"country": "Supernautica",
		},
	}
	scopeProvider := &mockScopeProvider{
		resolveIdentity: func(subject string, password string) (jwt.MapClaims, error) {
			if subject == "not-allowed" {
				return nil, fmt.Errorf("invalid credentials")
			}

			return jwt.MapClaims{
				"email":        subject,
				"extra":        extra,
				"sub":          subject,
				"entitlements": []string{"foo", "bar"},
			}, nil
		},
		resolveRolesAndEntitlements: func(subject string) ([]string, []string, error) {
			return nil, nil, nil
		},
	}

	tests := []struct {
		name       string
		cfg        func(string) (Config, error)
		sp         InternalIdentityProvider
		assertions func(t *testing.T, serverURL string)
	}{
		{
			name: "OIDC - constructor, no client id",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string) {
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("OIDC secret does not contain 'client_id' or 'client-id'")
					},
				).WithAudience(
					"audience",
				).WithIssuer(
					"issuer",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				_, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), "OIDC secret does not contain 'client_id' or 'client-id'")
			},
		},
		{
			name: "OIDC - constructor, no secret defined",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string) {
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("missing secret of type 'oidc-client' required for OIDC provider")
					},
				).WithAudience(
					"audience",
				).WithIssuer(
					"issuer",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				_, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), `missing secret of type 'oidc-client' required for OIDC provider`)
			},
		},
		{
			name: "OIDC - constructor, secret defined but missing key",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string) {
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("OIDC secret does not contain 'client_secret' or 'client-secret'")
					},
				).WithAudience(
					"audience",
				).WithIssuer(
					"issuer",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				_, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), "OIDC secret does not contain 'client_secret' or 'client-secret'")
			},
		},
		{
			name: "OIDC - constructor, secret defined, valid key",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string) {
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "bar",
							ClientSecret: "foo",
						}, nil
					},
				).WithAudience(
					"audience",
				).WithIssuer(
					"issuer",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "foo", cfg.OIDC.ClientSecret)
			},
		},
		{
			name: "OIDC - constructor, client-auth secrets",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string) {
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{
							"baz": {
								ClientID:     "baz",
								ClientSecret: "fiz",
								RedirectURIs: []string{"http://ok"},
							},
						}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "bar",
							ClientSecret: "foo",
						}, nil
					},
				).WithAudience(
					"audience",
				).WithIssuer(
					"issuer",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.Nil(t, gotErr)
				authClient := cfg.Clients["baz"]
				assert.Equal(t, "fiz", authClient.ClientSecret)
				assert.True(t, slices.Contains(authClient.RedirectURIs, "http://ok"), "redirect url not found in list: %v", authClient.RedirectURIs)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertions(t, "http://foo")
		})
	}
}

func TestBuild_MintTokenPolicy(t *testing.T) {
	g := NewWithT(t)
	cb := newTestConfigBuilder(t) // helper that wires KeyLoader + Audience + Issuer (mirror existing config tests)
	auth := &kdexv1alpha1.Auth{
		JWT: kdexv1alpha1.JWT{},
		MintToken: &kdexv1alpha1.MintToken{
			Enabled: true, TTLCapSeconds: 45, UsesCap: 8,
			DestructiveVerbs: []string{"delete"},
		},
	}
	cfg, err := cb.Build(auth)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cfg.MintTokenEnabled).To(BeTrue())
	g.Expect(cfg.MintTokenTTLCap).To(Equal(45 * time.Second))
	g.Expect(cfg.MintTokenUsesCap).To(Equal(8))
	g.Expect(cfg.MintTokenDestructiveVerbs).To(Equal([]string{"delete"}))
}

func TestApplyMintTokenPolicy_URLDelivery(t *testing.T) {
	g := NewWithT(t)

	on := &Config{}
	applyMintTokenPolicy(on, &kdexv1alpha1.MintToken{Enabled: true, URLDelivery: true})
	g.Expect(on.MintTokenEnabled).To(BeTrue())
	g.Expect(on.MintTokenURLDelivery).To(BeTrue())

	off := &Config{}
	applyMintTokenPolicy(off, &kdexv1alpha1.MintToken{Enabled: true})
	g.Expect(off.MintTokenURLDelivery).To(BeFalse())
}
