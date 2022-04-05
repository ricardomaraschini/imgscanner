// Copyright 2020 The Shipwright Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trivy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/hashicorp/go-multierror"
)

// Trivy scans a container image using trivy command line utility.
type Trivy struct{}

// New returns a handler for all container image scan operations using trivy.
func New() *Trivy {
	return &Trivy{}
}

// Scan uses trivy command line utility to scan an image by reference. Uses all provided system
// contexts when attempting to access the remote image (registry authentication). XXX we most
// likely will have concurrency problems here as this function may run multiple times at the
// same time (hence this deserves its own struct as we most likely want to add some more logic
// here to avoid these kind of problems).
func (t *Trivy) Scan(
	ctx context.Context, imgref types.ImageReference, sysctxs []*types.SystemContext,
) (*runtime.RawExtension, error) {
	named := imgref.DockerReference()
	digested, ok := named.(reference.Digested)
	if !ok {
		return nil, fmt.Errorf("reference does not contain digest: %s", named)
	}

	var errors *multierror.Error
	for _, sysctx := range sysctxs {
		scanenv := []string{}
		if sysctx != nil {
			scanenv = append(
				scanenv,
				fmt.Sprintf("TRIVY_USERNAME=%s", sysctx.DockerAuthConfig.Username),
				fmt.Sprintf("TRIVY_PASSWORD=%s", sysctx.DockerAuthConfig.Password),
			)
		}

		cmd := exec.Command(
			"/home/rmarasch/go/bin/trivy",
			"--quiet",
			"image",
			"--format",
			"json",
			digested.String(),
		)

		var stdout bytes.Buffer
		var stderr bytes.Buffer

		cmd.Env = scanenv
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			errors = multierror.Append(errors, err)
			continue
		}

		return &runtime.RawExtension{Raw: stdout.Bytes()}, nil
	}
	return nil, fmt.Errorf("unable to scan image: %w", errors)
}
