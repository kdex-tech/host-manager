package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// InstallerServiceAccountName is the ServiceAccount kdex-nexus-manager
// bootstraps in every host namespace and impersonates for Helm. It must equal
// the constant of the same name in kdex-nexus-manager's internal/controller
// package.
const InstallerServiceAccountName = "kdex-installer"

// reservedServiceAccount reports whether sa is a ServiceAccount no function,
// build or backend may run as: kdex-installer, host-manager's own
// (hostManagerSA), the function deployer's (deployerSA), or any account the
// host-manager chart created for another host (account, when non-nil, carries
// the chart's labels). Kubernetes does not authorize which ServiceAccount a
// pod names, so naming one of these would lend its rights to the pod.
func reservedServiceAccount(sa, hostManagerSA, deployerSA string, account *corev1.ServiceAccount) bool {
	if sa == "" {
		return false
	}
	if sa == InstallerServiceAccountName || sa == hostManagerSA || sa == deployerSA {
		return true
	}
	return account != nil && isHostManagerServiceAccount(account)
}

// isHostManagerServiceAccount reports whether account was created by the
// host-manager chart, for any host.
func isHostManagerServiceAccount(account *corev1.ServiceAccount) bool {
	return account.Labels["app.kubernetes.io/name"] == "host-manager" ||
		strings.HasPrefix(account.Labels["helm.sh/chart"], "host-manager-")
}

// reservedServiceAccountIn is reservedServiceAccount, reading the account from
// namespace when sa is not reserved by name. A missing account is not
// reserved.
func reservedServiceAccountIn(ctx context.Context, c client.Reader, namespace, sa, hostManagerSA, deployerSA string) bool {
	if reservedServiceAccount(sa, hostManagerSA, deployerSA, nil) {
		return true
	}
	if sa == "" {
		return false
	}
	account := &corev1.ServiceAccount{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: sa}, account); err != nil {
		return false
	}
	return reservedServiceAccount(sa, hostManagerSA, deployerSA, account)
}

// reservedServiceAccountMessage is the refusal text for a reserved account;
// field names the spec field.
func reservedServiceAccountMessage(field, sa string) string {
	return fmt.Sprintf("%s %q is a reserved ServiceAccount (host-manager, function-deployer or kdex-installer); a function must run as its own", field, sa)
}
