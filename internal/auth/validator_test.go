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

package auth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeReviewer is a canned tokenReviewer for tests. It records the submitted
// review and returns a preconfigured result/error.
type fakeReviewer struct {
	result    *authnv1.TokenReview
	err       error
	gotReview *authnv1.TokenReview
}

func (f *fakeReviewer) Create(ctx context.Context, tr *authnv1.TokenReview, opts metav1.CreateOptions) (*authnv1.TokenReview, error) {
	f.gotReview = tr
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func authenticatedReview(username, uid string) *authnv1.TokenReview {
	return &authnv1.TokenReview{
		Status: authnv1.TokenReviewStatus{
			Authenticated: true,
			User: authnv1.UserInfo{
				Username: username,
				UID:      uid,
			},
		},
	}
}

func TestValidateK8sJWTSuccess(t *testing.T) {
	fake := &fakeReviewer{result: authenticatedReview("system:serviceaccount:opus-apps:web", "uid-123")}
	v := newValidatorWithReviewer(fake, nil, time.Second)

	id, err := v.ValidateK8sJWT(context.Background(), "a.b.c")
	if err != nil {
		t.Fatalf("ValidateK8sJWT: %v", err)
	}
	if id.Namespace != "opus-apps" {
		t.Errorf("Namespace = %q, want opus-apps", id.Namespace)
	}
	if id.ServiceAccount != "web" {
		t.Errorf("ServiceAccount = %q, want web", id.ServiceAccount)
	}
	if id.ServiceAccountUID != "uid-123" {
		t.Errorf("UID = %q, want uid-123", id.ServiceAccountUID)
	}
	if id.Role != "" {
		t.Errorf("Role = %q, want empty", id.Role)
	}
	if fake.gotReview.Spec.Token != "a.b.c" {
		t.Errorf("submitted token = %q, want a.b.c", fake.gotReview.Spec.Token)
	}
}

func TestValidateK8sJWTAudiencesPassedThrough(t *testing.T) {
	auds := []string{"vault", "https://kubernetes.default.svc"}
	fake := &fakeReviewer{result: authenticatedReview("system:serviceaccount:ns:sa", "u")}
	v := newValidatorWithReviewer(fake, auds, time.Second)

	if _, err := v.ValidateK8sJWT(context.Background(), "tok"); err != nil {
		t.Fatalf("ValidateK8sJWT: %v", err)
	}
	if !reflect.DeepEqual(fake.gotReview.Spec.Audiences, auds) {
		t.Errorf("audiences = %v, want %v", fake.gotReview.Spec.Audiences, auds)
	}
}

func TestValidateK8sJWTNoAudiences(t *testing.T) {
	fake := &fakeReviewer{result: authenticatedReview("system:serviceaccount:ns:sa", "u")}
	v := newValidatorWithReviewer(fake, nil, time.Second)

	if _, err := v.ValidateK8sJWT(context.Background(), "tok"); err != nil {
		t.Fatalf("ValidateK8sJWT: %v", err)
	}
	if len(fake.gotReview.Spec.Audiences) != 0 {
		t.Errorf("audiences = %v, want none", fake.gotReview.Spec.Audiences)
	}
}

func TestValidateK8sJWTNotAuthenticated(t *testing.T) {
	fake := &fakeReviewer{result: &authnv1.TokenReview{
		Status: authnv1.TokenReviewStatus{Authenticated: false},
	}}
	v := newValidatorWithReviewer(fake, nil, time.Second)

	if _, err := v.ValidateK8sJWT(context.Background(), "tok"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestValidateK8sJWTReviewerError(t *testing.T) {
	sentinel := errors.New("api server unreachable")
	fake := &fakeReviewer{err: sentinel}
	v := newValidatorWithReviewer(fake, nil, time.Second)

	_, err := v.ValidateK8sJWT(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wrapped sentinel", err)
	}
}

func TestValidateK8sJWTEmptyToken(t *testing.T) {
	fake := &fakeReviewer{}
	v := newValidatorWithReviewer(fake, nil, time.Second)
	for _, jwt := range []string{"", "   ", "\t\n"} {
		if _, err := v.ValidateK8sJWT(context.Background(), jwt); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("jwt=%q err = %v, want ErrInvalidToken", jwt, err)
		}
	}
	if fake.gotReview != nil {
		t.Errorf("reviewer should not be called for empty token")
	}
}

func TestValidateK8sJWTMalformedUsername(t *testing.T) {
	fake := &fakeReviewer{result: authenticatedReview("system:node:worker-1", "uid")}
	v := newValidatorWithReviewer(fake, nil, time.Second)

	if _, err := v.ValidateK8sJWT(context.Background(), "tok"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestParseServiceAccountUsername(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		wantNS    string
		wantSA    string
		wantError bool
	}{
		{"valid", "system:serviceaccount:opus-apps:web", "opus-apps", "web", false},
		{"valid with dashes", "system:serviceaccount:kube-system:coredns", "kube-system", "coredns", false},
		{"not a service account", "system:node:worker", "", "", true},
		{"plain user", "alice", "", "", true},
		{"missing sa", "system:serviceaccount:opus-apps:", "", "", true},
		{"missing namespace", "system:serviceaccount::web", "", "", true},
		{"missing both", "system:serviceaccount:", "", "", true},
		{"no colon separator", "system:serviceaccount:onlyns", "", "", true},
		{"empty", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, sa, err := parseServiceAccountUsername(tt.username)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error for %q", tt.username)
				}
				if !errors.Is(err, ErrInvalidToken) {
					t.Errorf("err = %v, want wrap ErrInvalidToken", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ns != tt.wantNS || sa != tt.wantSA {
				t.Errorf("got (%q,%q), want (%q,%q)", ns, sa, tt.wantNS, tt.wantSA)
			}
		})
	}
}

func TestNewValidatorWithReviewerDefaultTimeout(t *testing.T) {
	v := newValidatorWithReviewer(&fakeReviewer{}, nil, 0)
	if v.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s default", v.timeout)
	}
}
