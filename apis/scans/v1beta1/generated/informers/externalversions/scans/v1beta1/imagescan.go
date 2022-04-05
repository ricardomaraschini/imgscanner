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

// Code generated by informer-gen. DO NOT EDIT.

package v1beta1

import (
	"context"
	time "time"

	scansv1beta1 "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
	versioned "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/clientset/versioned"
	internalinterfaces "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/informers/externalversions/internalinterfaces"
	v1beta1 "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/listers/scans/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ImageScanInformer provides access to a shared informer and lister for
// ImageScans.
type ImageScanInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1beta1.ImageScanLister
}

type imageScanInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewImageScanInformer constructs a new informer for ImageScan type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewImageScanInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredImageScanInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredImageScanInformer constructs a new informer for ImageScan type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredImageScanInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ShipwrightV1beta1().ImageScans().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ShipwrightV1beta1().ImageScans().Watch(context.TODO(), options)
			},
		},
		&scansv1beta1.ImageScan{},
		resyncPeriod,
		indexers,
	)
}

func (f *imageScanInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredImageScanInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *imageScanInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&scansv1beta1.ImageScan{}, f.defaultInformer)
}

func (f *imageScanInformer) Lister() v1beta1.ImageScanLister {
	return v1beta1.NewImageScanLister(f.Informer().GetIndexer())
}