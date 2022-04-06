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
	"encoding/json"
	"fmt"
	"os/exec"

	trtypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/hashicorp/go-multierror"

	v1b1scans "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
)

// Trivy scans a container image using trivy command line utility.
type Trivy struct{}

// New returns a handler for all container image scan operations using trivy.
func New() *Trivy {
	return &Trivy{}
}

// getEnvironment extracts from the provided system context the environment variables needed to
// run trivy on the command line as well as sets the environment defaults.
func (t *Trivy) getEnvironment(sysctx *types.SystemContext) []string {
	env := []string{"TRIVY_SEVERITY=MEDIUM,HIGH,CRITICAL"}
	if sysctx == nil {
		return env
	}

	if sysctx.DockerInsecureSkipTLSVerify == types.OptionalBoolTrue {
		env = append(env, "TRIVY_INSECURE=true")
	}

	if sysctx.DockerAuthConfig == nil {
		return env
	}

	return append(
		env,
		fmt.Sprintf("TRIVY_USERNAME=%s", sysctx.DockerAuthConfig.Username),
		fmt.Sprintf("TRIVY_PASSWORD=%s", sysctx.DockerAuthConfig.Password),
	)
}

// Scan uses trivy command line utility to scan an image by reference. Uses all provided system
// contexts when attempting to access the remote image (registry authentication). XXX we most
// likely will have concurrency problems here as this function may run multiple times at the
// same time (hence this deserves its own struct as we most likely want to add some more logic
// here to avoid these kind of problems).
func (t *Trivy) Scan(
	ctx context.Context, imgref types.ImageReference, sysctxs []*types.SystemContext,
) ([]v1b1scans.Vulnerability, error) {
	named := imgref.DockerReference()
	digested, ok := named.(reference.Digested)
	if !ok {
		return nil, fmt.Errorf("reference does not contain digest: %s", named)
	}

	var errors *multierror.Error
	for _, sysctx := range sysctxs {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		commandargs := []string{"--quiet", "image", "--format", "json", digested.String()}
		cmd := exec.Command("/usr/local/bin/trivy", commandargs...)
		cmd.Env = t.getEnvironment(sysctx)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			errors = multierror.Append(errors, err)
			continue
		}

		var report trtypes.Report
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			return nil, fmt.Errorf("error unmarshaling report: %w", err)
		}

		var vulnerabilities []v1b1scans.Vulnerability
		for _, res := range report.Results {
			for _, vuln := range res.Vulnerabilities {
				vulnerabilities = append(
					vulnerabilities,
					v1b1scans.Vulnerability{
						ID:          vuln.VulnerabilityID,
						Severity:    vuln.Severity,
						Description: vuln.Title,
					},
				)
			}
		}

		return vulnerabilities, nil
	}
	return nil, fmt.Errorf("unable to scan image: %w", errors)
}
