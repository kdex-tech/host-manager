package controller

// Namespaced rules are emitted as a Role (namespace=host-namespace is a placeholder;
// the chart renders the rules into a Role in the release namespace, see `make chart-rbac`).

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;delete,namespace=host-namespace
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;delete,namespace=host-namespace
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete,namespace=host-namespace
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update,namespace=host-namespace
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update,namespace=host-namespace
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;delete,namespace=host-namespace
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;create;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexapps,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexfaasadaptors,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexfunctions,verbs=get;list;watch;create;update;patch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexfunctions/status,verbs=get;update;patch,namespace=host-namespace
// Needed for blockOwnerDeletion when OwnerReferencesPermissionEnforcement is enabled.
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexfunctions/finalizers,verbs=update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalhosts,verbs=get;list;watch,namespace=host-namespace
// Needed for blockOwnerDeletion when OwnerReferencesPermissionEnforcement is enabled.
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalhosts/finalizers,verbs=update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalhosts/status,verbs=get;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalpackagereferences,verbs=get;list;watch;create;update;patch;delete,namespace=host-namespace
// Needed for blockOwnerDeletion when OwnerReferencesPermissionEnforcement is enabled.
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalpackagereferences/finalizers,verbs=update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalpackagereferences/status,verbs=get;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternaltranslations,verbs=get;list;watch;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternaltranslations/status,verbs=get;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalutilitypages,verbs=get;list;watch;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexinternalutilitypages/status,verbs=get;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpagearchetypes,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpages,verbs=get;list;watch;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpages/status,verbs=get;update,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpagefooters,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpageheaders,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexpagenavigations,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexroles,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexrolebindings,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexscriptlibraries,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexthemes,verbs=get;list;watch,namespace=host-namespace
// +kubebuilder:rbac:groups=kpack.io,resources=images,verbs=get;list;watch;create;patch;delete,namespace=host-namespace
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update,namespace=host-namespace

// Cluster-scoped reads. controller-gen emits these into a ClusterRole in
// config/rbac/role.yaml, which nothing deploys: they declare what host-manager
// reads cluster-wide. In a cluster, nexus-manager's fixed
// kcnas-operator-host-manager-cluster-reader ClusterRole grants get/list/watch
// on every KDexCluster* kind, and nexus binds it to each host-manager
// ServiceAccount. So only get/list/watch on a kdexcluster* resource may be
// declared here (TestClusterScopedRBACMarkersAreKDexClusterReads): anything
// else would be a grant host-manager needs and never receives.
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterapps,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterfaasadaptors,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterpagearchetypes,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterpagefooters,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterpageheaders,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterpagenavigations,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterscriptlibraries,verbs=get;list;watch
// +kubebuilder:rbac:groups=kdex.dev,resources=kdexclusterthemes,verbs=get;list;watch
