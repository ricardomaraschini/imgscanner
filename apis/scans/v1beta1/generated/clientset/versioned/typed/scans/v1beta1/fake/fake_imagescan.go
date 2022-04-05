/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1beta1 "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeImageScans implements ImageScanInterface
type FakeImageScans struct {
	Fake *FakeShipwrightV1beta1
}

var imagescansResource = schema.GroupVersionResource{Group: "shipwright.io", Version: "v1beta1", Resource: "imagescans"}

var imagescansKind = schema.GroupVersionKind{Group: "shipwright.io", Version: "v1beta1", Kind: "ImageScan"}

// Get takes name of the imageScan, and returns the corresponding imageScan object, and an error if there is any.
func (c *FakeImageScans) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.ImageScan, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(imagescansResource, name), &v1beta1.ImageScan{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ImageScan), err
}

// List takes label and field selectors, and returns the list of ImageScans that match those selectors.
func (c *FakeImageScans) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.ImageScanList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(imagescansResource, imagescansKind, opts), &v1beta1.ImageScanList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.ImageScanList{ListMeta: obj.(*v1beta1.ImageScanList).ListMeta}
	for _, item := range obj.(*v1beta1.ImageScanList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested imageScans.
func (c *FakeImageScans) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(imagescansResource, opts))
}

// Create takes the representation of a imageScan and creates it.  Returns the server's representation of the imageScan, and an error, if there is any.
func (c *FakeImageScans) Create(ctx context.Context, imageScan *v1beta1.ImageScan, opts v1.CreateOptions) (result *v1beta1.ImageScan, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(imagescansResource, imageScan), &v1beta1.ImageScan{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ImageScan), err
}

// Update takes the representation of a imageScan and updates it. Returns the server's representation of the imageScan, and an error, if there is any.
func (c *FakeImageScans) Update(ctx context.Context, imageScan *v1beta1.ImageScan, opts v1.UpdateOptions) (result *v1beta1.ImageScan, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(imagescansResource, imageScan), &v1beta1.ImageScan{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ImageScan), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeImageScans) UpdateStatus(ctx context.Context, imageScan *v1beta1.ImageScan, opts v1.UpdateOptions) (*v1beta1.ImageScan, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(imagescansResource, "status", imageScan), &v1beta1.ImageScan{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ImageScan), err
}

// Delete takes name of the imageScan and deletes it. Returns an error if one occurs.
func (c *FakeImageScans) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(imagescansResource, name, opts), &v1beta1.ImageScan{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeImageScans) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(imagescansResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.ImageScanList{})
	return err
}

// Patch applies the patch and returns the patched imageScan.
func (c *FakeImageScans) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.ImageScan, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(imagescansResource, name, pt, data, subresources...), &v1beta1.ImageScan{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ImageScan), err
}