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

package scanners

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"

	imgv1b1 "github.com/shipwright-io/image/infra/images/v1beta1"
	iimginf "github.com/shipwright-io/image/infra/images/v1beta1/gen/informers/externalversions"
	imglist "github.com/shipwright-io/image/infra/images/v1beta1/gen/listers/images/v1beta1"
	imageservices "github.com/shipwright-io/image/services"

	v1b1scans "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
	v1b1clientset "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/clientset/versioned"
	v1b1informers "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/informers/externalversions"
	v1b1listers "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/listers/scans/v1beta1"
)

// Dispatcher do some preprocessing of top of Image objects and calls the internally configured
// Scanner. TODO expand this to accept multiple Scanners if necessary.
type Dispatcher struct {
	scancli v1b1clientset.Interface
	scanlis v1b1listers.ImageScanLister
	imginf  iimginf.SharedInformerFactory
	imglis  imglist.ImageLister
	sysctx  *imageservices.SysContext
	scanner Scanner
}

// Scanner implments a Scan method and is reponsible for scanning a given container image
// reference using provided system contexts. This function should return a list of vulnerability
// IDs (for example "CVE-2022-0185").
type Scanner interface {
	Scan(context.Context, types.ImageReference, []*types.SystemContext) ([]v1b1scans.Vulnerability, error)
}

// NewDispatcher returns a handler for all container image scan operations using trivy.
func NewDispatcher(
	scancli v1b1clientset.Interface,
	scaninf v1b1informers.SharedInformerFactory,
	imginf iimginf.SharedInformerFactory,
	sysctx *imageservices.SysContext,
	scanner Scanner,
) *Dispatcher {
	var scanlis v1b1listers.ImageScanLister
	if scaninf != nil {
		scanlis = scaninf.Shipwright().V1beta1().ImageScans().Lister()
	}

	return &Dispatcher{
		scancli: scancli,
		scanlis: scanlis,
		imginf:  imginf,
		imglis:  imginf.Shipwright().V1beta1().Images().Lister(),
		sysctx:  sysctx,
		scanner: scanner,
	}
}

// AddEventHandler adds a handler to Image related events.
func (t *Dispatcher) AddEventHandler(handler cache.ResourceEventHandler) {
	t.imginf.Shipwright().V1beta1().Images().Informer().AddEventHandler(handler)
}

// Get returns a shipwright image object.
func (t *Dispatcher) Get(ctx context.Context, ns, name string) (*imgv1b1.Image, error) {
	img, err := t.imglis.Images(ns).Get(name)
	if err != nil {
		return nil, fmt.Errorf("unable to get image: %w", err)
	}
	return img.DeepCopy(), nil
}

// Sync runs a scan on the provided Image object. Goes through all image hash references, parses
// them and calls processImage for all of them sequentially.
func (t *Dispatcher) Sync(ctx context.Context, img *imgv1b1.Image) error {
	for _, hr := range img.Status.HashReferences {
		imgproto := fmt.Sprintf("docker://%s", hr.ImageReference)
		imgref, err := alltransports.ParseImageName(imgproto)
		if err != nil {
			return fmt.Errorf("unable to parse image reference: %w", err)
		}

		if err := t.processImage(ctx, img, imgref); err != nil {
			klog.Errorf("error processing %q: %w", hr.ImageReference, err)
		}
	}
	return nil
}

// assureScan makes sure kubernetes has an object of type ImageScan named according to
// provided argument. Returns the most recent version of the object found. If the object
// does not exist a new one is created.
func (t *Dispatcher) assureScan(ctx context.Context, name string) (*v1b1scans.ImageScan, error) {
	scan, err := t.scanlis.Get(name)
	if err == nil {
		return scan, nil
	}

	if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unexpected error reading scan: %w", err)
	}

	// if no scan for a given image has been found we create a new one.
	scan = &v1b1scans.ImageScan{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}

	if scan, err = t.scancli.ShipwrightV1beta1().ImageScans().Create(
		ctx, scan, metav1.CreateOptions{},
	); err != nil {
		return nil, fmt.Errorf("unable to create new scan: %w", err)
	}

	return scan.DeepCopy(), nil
}

// processImage makes sure an ImageScan object for provided image reference exists and runs
// the scan if necessary (has not yet been scanned). ImageScans are ran only once per image and
// authentications for the target registry are read from the image namespace.
func (t *Dispatcher) processImage(
	ctx context.Context, img *imgv1b1.Image, imgref types.ImageReference,
) error {
	named := imgref.DockerReference()
	digested, ok := named.(reference.Digested)
	if !ok {
		return fmt.Errorf("reference does not contain digest: %s", named)
	}

	scanname := strings.TrimPrefix(digested.Digest().String(), "sha256:")
	scan, err := t.assureScan(ctx, scanname)
	if err != nil {
		return err
	}

	if scan.HasFailed() {
		klog.Infof("no more attemps to import %q", scanname)
		return nil
	}

	if scan.Executed() {
		klog.Infof("scan for %q already executed", scanname)
		return nil
	}

	sysctxs, err := t.sysctx.SystemContextsFor(ctx, imgref, img.Namespace, img.Spec.Insecure)
	if err != nil {
		return fmt.Errorf("error reading registry system contexts: %w", err)
	}

	if vulnerabilities, err := t.scanner.Scan(ctx, imgref, sysctxs); err != nil {
		scan.PrependFailure(err)
	} else {
		now := metav1.Now()
		scan.Status.FinishedAt = &now
		scan.Status.Vulnerabilities = vulnerabilities
	}

	if _, err := t.scancli.ShipwrightV1beta1().ImageScans().UpdateStatus(
		ctx, scan, metav1.UpdateOptions{},
	); err != nil {
		return fmt.Errorf("unable to update scan status: %w", err)
	}
	return nil
}
