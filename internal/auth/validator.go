// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package auth provides Kubernetes service-account token validation, in-memory
// issued-token storage, and role-based path authorization.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrInvalidToken indicates the presented JWT failed validation.
var ErrInvalidToken = errors.New("invalid service account token")

// Identity is the authenticated principal extracted from a validated K8s JWT.
type Identity struct {
	ServiceAccount    string
	ServiceAccountUID string
	Namespace         string
	Role              string
}

// TokenValidator validates a Kubernetes service-account JWT and returns the
// identity it represents.
type TokenValidator interface {
	ValidateK8sJWT(ctx context.Context, jwt string) (*Identity, error)
}

// tokenReviewer is the slice of the Kubernetes client the validator depends on.
// It is satisfied by kubernetes.Interface and by the fake clientset in tests.
type tokenReviewer interface {
	Create(ctx context.Context, tr *authnv1.TokenReview, opts metav1.CreateOptions) (*authnv1.TokenReview, error)
}

// K8sTokenValidator validates JWTs via the Kubernetes TokenReview API.
type K8sTokenValidator struct {
	reviews  tokenReviewer
	audience []string
	timeout  time.Duration
}

// NewK8sTokenValidator builds a validator from in-cluster config, falling back
// to the provided kubeconfig path for out-of-cluster development. audiences may
// be nil; when set, it is sent with each TokenReview for bound-token clusters.
func NewK8sTokenValidator(kubeconfigPath string, audiences []string, timeout time.Duration) (*K8sTokenValidator, error) {
	cfg, err := loadKubeConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &K8sTokenValidator{
		reviews:  clientset.AuthenticationV1().TokenReviews(),
		audience: audiences,
		timeout:  timeout,
	}, nil
}

// newValidatorWithReviewer is a test seam allowing injection of a fake reviewer.
func newValidatorWithReviewer(r tokenReviewer, audiences []string, timeout time.Duration) *K8sTokenValidator {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &K8sTokenValidator{reviews: r, audience: audiences, timeout: timeout}
}

func loadKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig (no in-cluster config available): %w", err)
	}
	return cfg, nil
}

// ValidateK8sJWT submits a TokenReview and parses the authenticated identity.
// The returned Identity has an empty Role; callers set it from the login request
// after verifying the role binding.
func (v *K8sTokenValidator) ValidateK8sJWT(ctx context.Context, jwt string) (*Identity, error) {
	if strings.TrimSpace(jwt) == "" {
		return nil, ErrInvalidToken
	}
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	review := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: jwt},
	}
	if len(v.audience) > 0 {
		review.Spec.Audiences = v.audience
	}

	result, err := v.reviews.Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	if !result.Status.Authenticated {
		return nil, ErrInvalidToken
	}

	namespace, sa, err := parseServiceAccountUsername(result.Status.User.Username)
	if err != nil {
		return nil, err
	}
	return &Identity{
		ServiceAccount:    sa,
		ServiceAccountUID: result.Status.User.UID,
		Namespace:         namespace,
	}, nil
}

// parseServiceAccountUsername parses "system:serviceaccount:<ns>:<name>".
func parseServiceAccountUsername(username string) (namespace, serviceAccount string, err error) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return "", "", fmt.Errorf("%w: not a service account (%q)", ErrInvalidToken, username)
	}
	rest := strings.TrimPrefix(username, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: malformed service account username", ErrInvalidToken)
	}
	return parts[0], parts[1], nil
}
