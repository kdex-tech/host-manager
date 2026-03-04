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
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
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
		secrets   kdexv1alpha1.ServiceAccountSecrets
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
							CreationTimestamp: metav1.NewTime(time.Now().Add(-48 * time.Hour)),
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
				secrets: kdexv1alpha1.ServiceAccountSecrets{
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
			got, gotErr := NewConfig(
				tt.args.auth,
				func() (map[string]AuthClient, error) {
					return AuthClientLoader(tt.args.secrets)
				},
				func() (*keys.KeyPairs, error) {
					return keys.LoadOrGenerateKeyPair(
						tt.args.secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "jwt-keys" }),
						tt.args.devMode)
				},
				func() (*OIDCClientConfig, error) {
					return OIDCConfigLoader(tt.args.secrets, tt.args.devMode)
				},
				"audience",
				"issuer",
				tt.args.devMode,
				cacheManager,
			)
			tt.assertions(t, got, gotErr)
		})
	}
}

func TestConfig_AddAuthentication(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(t.Output()), zap.UseDevMode(true)))

	type testargs struct {
		c         client.Client
		auth      *kdexv1alpha1.Auth
		namespace string
		devMode   bool
		secrets   kdexv1alpha1.ServiceAccountSecrets
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
				assert.Equal(t, 303, w.Code)
				assert.Contains(t, w.Body.String(), "See Other")
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
					"iss":   "issuer",
					"aud":   "audience",
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
					"iss":   "issuer",
					"aud":   got.OIDC.ClientID,
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
					"iss":   "issuer",
					"aud":   got.OIDC.ClientID,
				})

				assert.Nil(t, err)

				r.Header.Set(COOKIE, "auth_token="+token)
				handler.ServeHTTP(w, r)
				assert.Equal(t, 303, w.Code)
				assert.Contains(t, w.Body.String(), "See Other")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))
			got, gotErr := NewConfig(
				tt.args.auth,
				func() (map[string]AuthClient, error) {
					return AuthClientLoader(tt.args.secrets)
				},
				func() (*keys.KeyPairs, error) {
					return keys.LoadOrGenerateKeyPair(
						tt.args.secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "jwt-keys" }),
						tt.args.devMode)
				},
				func() (*OIDCClientConfig, error) {
					return OIDCConfigLoader(tt.args.secrets, tt.args.devMode)
				},
				"audience",
				"issuer",
				tt.args.devMode,
				cacheManager,
			)
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
				_, gotErr := NewConfig(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("OIDC secret does not contain 'client_id' or 'client-id'")
					},
					"audience",
					"issuer",
					true,
					cacheManager,
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
				_, gotErr := NewConfig(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("missing secret of type 'oidc-client' required for OIDC provider")
					},
					"audience",
					"issuer",
					true,
					cacheManager,
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
				_, gotErr := NewConfig(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
					func() (*OIDCClientConfig, error) {
						return nil, fmt.Errorf("OIDC secret does not contain 'client_secret' or 'client-secret'")
					},
					"audience",
					"issuer",
					true,
					cacheManager,
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
				cfg, gotErr := NewConfig(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "bar",
							ClientSecret: "foo",
						}, nil
					},
					"audience",
					"issuer",
					true,
					cacheManager,
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
				cfg, gotErr := NewConfig(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{
							"baz": {
								ClientID:     "baz",
								ClientSecret: "fiz",
								RedirectURIs: []string{"http://ok"},
							},
						}, nil
					},
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "bar",
							ClientSecret: "foo",
						}, nil
					},
					"audience",
					"issuer",
					true,
					cacheManager,
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
