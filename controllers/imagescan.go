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

package controllers

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	v1b1scans "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1"
)

// ImageScanSyncer abstraction exists to make testing easier. You most likely wanna see ImageScan
// struct under services/imagescan.go for a concrete implementation of this.
type ImageScanSyncer interface {
	Sync(context.Context, *v1b1scans.ImageScan) error
	Get(context.Context, string) (*v1b1scans.ImageScan, error)
	AddEventHandler(cache.ResourceEventHandler)
}

// ImageScan controller handles events related to ImageScans. It starts and receives events from
// the informer, calling appropriate functions on our concrete services layer implementation.
type ImageScan struct {
	queue   workqueue.RateLimitingInterface
	scansvc ImageScanSyncer
	appctx  context.Context
}

// NewImageScan returns a new controller for ImageScans.
func NewImageScan(scansvc ImageScanSyncer) *ImageScan {
	ratelimit := workqueue.NewItemExponentialFailureRateLimiter(time.Second, time.Minute)
	ctrl := &ImageScan{
		queue:   workqueue.NewRateLimitingQueue(ratelimit),
		scansvc: scansvc,
	}
	scansvc.AddEventHandler(ctrl.handlers())
	return ctrl
}

// Name returns a name identifier for this controller.
func (i *ImageScan) Name() string {
	return "imagescan"
}

// RequiresLeaderElection returns if this controller requires or not a leader lease to run.
func (i *ImageScan) RequiresLeaderElection() bool {
	return true
}

// enqueueEvent generates a key using image scan "name" for the event received and then enqueues
// it to be processed.
func (i *ImageScan) enqueueEvent(obj interface{}) {
	imgscan, ok := obj.(*v1b1scans.ImageScan)
	if !ok {
		klog.Errorf("fail to enqueue event: %v", obj)
		return
	}
	i.queue.AddRateLimited(imgscan.Name)
}

// handlers return a event handler that will be called by the informer whenever an event occurs.
// This handler enqueues everything in our work queue using enqueueEvent.
func (i *ImageScan) handlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(o interface{}) {
			i.enqueueEvent(o)
		},
		UpdateFunc: func(o, n interface{}) {
			i.enqueueEvent(o)
		},
		DeleteFunc: func(o interface{}) {
			i.enqueueEvent(o)
		},
	}
}

// eventProcessor reads our events calling syncImage for all of them. Uses t.tokens to control
// how many images are processed in parallel.
func (i *ImageScan) eventProcessor(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		evt, end := i.queue.Get()
		if end {
			klog.Info("queue closed, ending.")
			return
		}

		name, ok := evt.(string)
		if !ok {
			klog.Errorf("invalid event received: %s", evt)
			i.queue.Done(evt)
			return
		}

		klog.Infof("received event for imagescan : %s", evt)
		if err := i.syncImageScan(name); err != nil {
			klog.Errorf("error processing imagescan %s: %v", evt, err)
			i.queue.Done(evt)
			i.queue.AddRateLimited(evt)
			return
		}

		klog.Infof("event for imagescan %s processed", evt)
		i.queue.Done(evt)
		i.queue.Forget(evt)
	}
}

// syncImageScan process an event for an ImageScan. A max of one minute is allowed per sync.
func (i *ImageScan) syncImageScan(name string) error {
	ctx, cancel := context.WithTimeout(i.appctx, time.Minute)
	defer cancel()

	imgscan, err := i.scansvc.Get(ctx, name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return i.scansvc.Sync(ctx, imgscan)
}

// Start starts the controller's event loop.
func (i *ImageScan) Start(ctx context.Context) error {
	// appctx is the 'keep going' context, if it is cancelled
	// everything we might be doing should stop.
	i.appctx = ctx

	var wg sync.WaitGroup
	wg.Add(1)
	go i.eventProcessor(&wg)

	// wait until it is time to die.
	<-i.appctx.Done()

	i.queue.ShutDown()
	wg.Wait()
	return nil
}
