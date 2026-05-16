package internal

import corev1 "k8s.io/api/core/v1"

// PSSRestrictedPodSecurityContext returns a pod-level securityContext
// compliant with PodSecurity Admission's "restricted" profile.
//
// Restricted enforces: runAsNonRoot=true (or runAsUser >= 1000) and
// seccompProfile.type set to RuntimeDefault or Localhost. The remaining
// required fields (capabilities.drop=[ALL], allowPrivilegeEscalation=
// false) must be set per-container - see
// PSSRestrictedContainerSecurityContext.
//
// runAsUser/runAsGroup default to 65532 (the kubernetes-distroless
// convention) so image filesystems built for that UID are preserved.
func PSSRestrictedPodSecurityContext() *corev1.PodSecurityContext {
	return &corev1.PodSecurityContext{
		RunAsNonRoot: new(true),
		RunAsUser:    new(int64(65532)),
		RunAsGroup:   new(int64(65532)),
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
}

// PSSRestrictedContainerSecurityContext returns a container-level
// securityContext compliant with PodSecurity Admission's "restricted"
// profile.
//
// Restricted enforces drop=[ALL] and allowPrivilegeEscalation=false.
// readOnlyRootFilesystem is not required by restricted; we omit it so
// build/codegen containers that write to /tmp or /var work without
// additional emptyDir mounts.
func PSSRestrictedContainerSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
}
