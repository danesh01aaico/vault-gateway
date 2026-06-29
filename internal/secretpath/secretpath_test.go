// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package secretpath

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate_ValidPaths(t *testing.T) {
	cases := []string{
		"secret/myapp",
		"secret/data/myapp/database",
		"myapp/db",
		"prod/payments/api-key",
		"a",
		"abc123",
		"my-app_v2.config",
		"namespace:secret",
		"a/b/c/d/e",
		strings.Repeat("a", MaxLength),
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			if err := Validate(path); err != nil {
				t.Errorf("Validate(%q) = %v, want nil", path, err)
			}
		})
	}
}

func TestValidate_EmptyPath(t *testing.T) {
	err := Validate("")
	if err == nil {
		t.Fatal("want error for empty path")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Errorf("want ErrInvalidPath, got %v", err)
	}
}

func TestValidate_TooLong(t *testing.T) {
	path := strings.Repeat("a", MaxLength+1)
	err := Validate(path)
	if err == nil {
		t.Fatal("want error for path exceeding MaxLength")
	}
	if !errors.Is(err, ErrInvalidPath) {
		t.Errorf("want ErrInvalidPath, got %v", err)
	}
}

func TestValidate_AbsolutePath(t *testing.T) {
	for _, path := range []string{"/secret/myapp", "/", "/a"} {
		err := Validate(path)
		if err == nil {
			t.Errorf("Validate(%q): want error for absolute path", path)
		}
	}
}

func TestValidate_TrailingSlash(t *testing.T) {
	for _, path := range []string{"secret/", "a/b/"} {
		err := Validate(path)
		if err == nil {
			t.Errorf("Validate(%q): want error for trailing slash", path)
		}
	}
}

func TestValidate_EmptySegment(t *testing.T) {
	for _, path := range []string{"a//b", "a///b"} {
		err := Validate(path)
		if err == nil {
			t.Errorf("Validate(%q): want error for empty segment", path)
		}
	}
}

func TestValidate_PathTraversal(t *testing.T) {
	for _, path := range []string{
		"../etc/passwd",
		"secret/../other",
		"./secret",
		"a/./b",
		"a/../b",
		"..",
		".",
	} {
		err := Validate(path)
		if err == nil {
			t.Errorf("Validate(%q): want error for path traversal", path)
		}
	}
}

func TestValidate_NullByte(t *testing.T) {
	err := Validate("secret/my\x00app")
	if err == nil {
		t.Fatal("want error for null byte")
	}
}

func TestValidate_ControlChars(t *testing.T) {
	for _, r := range []rune{'\t', '\n', '\r', '\x01', '\x1f', '\x7f'} {
		path := "secret/" + string(r) + "app"
		if err := Validate(path); err == nil {
			t.Errorf("Validate with control char %q: want error", r)
		}
	}
}

func TestValidate_ShellMetacharacters(t *testing.T) {
	metacharacters := []string{
		"secret/$PATH",
		"secret/`cmd`",
		"secret/$(cmd)",
		"secret/my app", // space
		"secret/a&b",
		"secret/a|b",
		"secret/a;b",
		"secret/a>b",
		"secret/a<b",
		"secret/a!b",
		"secret/a*b",
		"secret/a?b",
		"secret/a[b",
		"secret/a]b",
		"secret/a{b",
		"secret/a}b",
		"secret/a\\b",
		"secret/a'b",
		`secret/a"b`,
		"secret/a#b",
		"secret/a~b",
		"secret/a@b",
		"secret/a%b",
		"secret/a^b",
		"secret/a(b",
		"secret/a)b",
		"secret/a+b",
		"secret/a=b",
	}
	for _, path := range metacharacters {
		if err := Validate(path); err == nil {
			t.Errorf("Validate(%q): want error for shell metacharacter", path)
		}
	}
}

func TestValidate_NonASCII(t *testing.T) {
	for _, path := range []string{
		"secret/café",
		"secret/naïve",
		"secret/日本語",
		"secret/ÿ",
	} {
		if err := Validate(path); err == nil {
			t.Errorf("Validate(%q): want error for non-ASCII", path)
		}
	}
}

func TestValidate_ErrorWrapsErrInvalidPath(t *testing.T) {
	cases := []string{"", "/abs", "../traversal", "a//b", "too" + strings.Repeat("x", MaxLength)}
	for _, path := range cases {
		err := Validate(path)
		if err != nil && !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Validate(%q) error does not wrap ErrInvalidPath: %v", path, err)
		}
	}
}

func TestValidate_ExactlyMaxLength(t *testing.T) {
	path := strings.Repeat("a", MaxLength)
	if err := Validate(path); err != nil {
		t.Errorf("Validate(%q): want nil for exactly MaxLength chars, got %v", path, err)
	}
}
