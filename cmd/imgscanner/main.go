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

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	coreinf "k8s.io/client-go/informers"
	corecli "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	imagecontrollers "github.com/shipwright-io/image/controllers"
	imgv1b1clientset "github.com/shipwright-io/image/infra/images/v1beta1/gen/clientset/versioned"
	imgv1b1informers "github.com/shipwright-io/image/infra/images/v1beta1/gen/informers/externalversions"
	imagectrlstarter "github.com/shipwright-io/image/infra/starter"
	imageservices "github.com/shipwright-io/image/services"

	v1b1clientset "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/clientset/versioned"
	v1b1informers "github.com/ricardomaraschini/imgscanner/apis/scans/v1beta1/generated/informers/externalversions"
	"github.com/ricardomaraschini/imgscanner/scanners"
	"github.com/ricardomaraschini/imgscanner/scanners/trivy"
)

// Version holds the current binary version. Set at compile time.
var Version = "v0.0.0"

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ctx.Done()
		stop()
	}()

	klog.Info(`starting image scanner...`)
	klog.Info(`version `, Version)

	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		klog.Fatalf("unable to read kubeconfig: %v", err)
	}

	// creates core client, this client is used during leader election.
	corcli, err := corecli.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to create core client: %v", err)
	}
	corinf := coreinf.NewSharedInformerFactory(corcli, time.Minute)

	// creates image client and informer, we will use this to receive events related to
	// shipwright image objects.
	imgcli, err := imgv1b1clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to create image image client: %v", err)
	}
	imginf := imgv1b1informers.NewSharedInformerFactory(imgcli, time.Minute)

	scancli, err := v1b1clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to create image image client: %v", err)
	}
	scaninf := v1b1informers.NewSharedInformerFactory(scancli, time.Minute)
	sysctx := imageservices.NewSysContext(corinf)

	trivyscan := trivy.New()
	dispatcher := scanners.NewDispatcher(scancli, scaninf, imginf, sysctx, trivyscan)
	controller := imagecontrollers.NewImage(dispatcher)

	// starts up all informers and waits for their cache to sync up, only then we start the
	// controllers i.e. start to process events from the queue.
	klog.Info("waiting for caches to sync ...")
	imginf.Start(ctx.Done())
	scaninf.Start(ctx.Done())
	corinf.Start(ctx.Done())
	if !cache.WaitForCacheSync(
		ctx.Done(),
		imginf.Shipwright().V1beta1().Images().Informer().HasSynced,
		scaninf.Shipwright().V1beta1().ImageScans().Informer().HasSynced,
		corinf.Core().V1().ConfigMaps().Informer().HasSynced,
		corinf.Core().V1().Secrets().Informer().HasSynced,
	) {
		klog.Fatal("caches not syncing")
	}
	klog.Info("caches in sync, moving on.")

	st := imagectrlstarter.New(corcli, controller)
	if err := st.Start(ctx, "imgscanner-leader-election"); err != nil {
		klog.Errorf("unable to start controllers: %s", err)
	}
}
