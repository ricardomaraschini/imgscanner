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

package services

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	imginform "github.com/shipwright-io/image/infra/images/v1beta1/gen/informers/externalversions"
	imglist "github.com/shipwright-io/image/infra/images/v1beta1/gen/listers/images/v1beta1"

	v1b1scans "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
	v1b1client "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/clientset/versioned"
	v1b1informers "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/informers/externalversions"
	v1b1listers "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/listers/scans/v1beta1"
)

// ImageScan gather all actions related to ImageScan objects. Actions in a sense of "services" or
// if you prefer: "use cases". The business logic for ImageScans lives in this struct.
type ImageScan struct {
	scancli v1b1client.Interface
	scanlis v1b1listers.ImageScanLister
	scaninf v1b1informers.SharedInformerFactory
	imglis  imglist.ImageLister
}

// NewImageScan returns a handler for all ImageScan related services.
func NewImageScan(
	scancli v1b1client.Interface,
	scaninf v1b1informers.SharedInformerFactory,
	imginf imginform.SharedInformerFactory,
) *ImageScan {
	var scanlis v1b1listers.ImageScanLister
	if scaninf != nil {
		scanlis = scaninf.Shipwright().V1beta1().ImageScans().Lister()
	}

	var imglis imglist.ImageLister
	if imginf != nil {
		imglis = imginf.Shipwright().V1beta1().Images().Lister()
	}

	return &ImageScan{
		scaninf: scaninf,
		scancli: scancli,
		scanlis: scanlis,
		imglis:  imglis,
	}
}

// Sync manages image scan changes. We verify that the ImageScan still has reference to existing
// shipwright images, we delete references if the Image was deleted. This function also deletes
// the ImageScan if it has no reference to Images.
func (t *ImageScan) Sync(ctx context.Context, scan *v1b1scans.ImageScan) error {
	if !scan.Executed() {
		return nil
	}

	var delrefs []v1b1scans.ImageReference
	for _, ref := range scan.Status.References {
		if _, err := t.imglis.Images(ref.Namespace).Get(ref.Name); err == nil {
			continue
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("unexpected error getting image: %w", err)
		}

		// image was not found, gather its reference for later removal.
		delrefs = append(delrefs, ref)
	}

	if len(delrefs) == 0 {
		return nil
	}

	for _, ref := range delrefs {
		scan.DeleteReference(ref)
	}

	if scan.HasReferences() {
		if _, err := t.scancli.ShipwrightV1beta1().ImageScans().UpdateStatus(
			ctx, scan, metav1.UpdateOptions{},
		); err != nil {
			return fmt.Errorf("error updating image scan: %w", err)
		}
		return nil
	}

	if err := t.scancli.ShipwrightV1beta1().ImageScans().Delete(
		ctx, scan.Name, metav1.DeleteOptions{},
	); err != nil {
		return fmt.Errorf("error deleting image scan: %w", err)
	}
	return nil
}

// Get returns a ImageScan object. Returned object is already a copy of the cached object and
// may be modified by caller as needed.
func (t *ImageScan) Get(ctx context.Context, name string) (*v1b1scans.ImageScan, error) {
	scan, err := t.scanlis.Get(name)
	if err != nil {
		return nil, fmt.Errorf("unable to get image scan: %w", err)
	}
	return scan.DeepCopy(), nil
}

// AddEventHandler adds a handler to Image related events.
func (t *ImageScan) AddEventHandler(handler cache.ResourceEventHandler) {
	t.scaninf.Shipwright().V1beta1().ImageScans().Informer().AddEventHandler(handler)
}
