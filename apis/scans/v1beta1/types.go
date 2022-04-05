package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	// MaxScanAttempts holds how many times we gonna try to scan an ImageImport object
	// before giving up.
	MaxScanAttempts = 10
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageScan holds the result of an Image vulnerability scan. ImageScans scope is global, we
// do not keep them per namespace. All ImageScans are named after the image layer hash.
type ImageScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            ImageScanStatus `json:"status"`
}

// Executed returns true if the scan has already been executed in the past.
func (s *ImageScan) Executed() bool {
	return s.Status.Result != nil
}

// PrependFailure prepends a failure to the scan list of failures. Keep at max MaxScanAttempts
// failures before rotating them.
func (s *ImageScan) PrependFailure(err error) {
	fail := Failure{
		When:  metav1.Now(),
		Error: err.Error(),
	}

	s.Status.Failures = append([]Failure{fail}, s.Status.Failures...)
	if len(s.Status.Failures) > MaxScanAttempts {
		s.Status.Failures = s.Status.Failures[0:MaxScanAttempts]
	}
}

// HasFailed returns if we still have attempts to be executed. i.e. if we have failed more than
// MaxScanAttempts attempts.
func (s *ImageScan) HasFailed() bool {
	return len(s.Status.Failures) >= MaxScanAttempts
}

// ImageScanStatus hold the status for the last image scan this operator ran. Results of a scan
// are stored in "free form" by using a runtime.RawExtension. As long as it is an object and can
// be json marshaled correctly we can store any data structure. This is by design as we may want
// to support other container scanners in the future and I don't feel like restricting it only
// to the one implemented during the proof of concept.
type ImageScanStatus struct {
	Failures []Failure             `json:"failures,omitempty"`
	Result   *runtime.RawExtension `json:"result,omitempty"`
}

// Failure represents a failure during a scan attempt. It is a very generic struct that serves
// the purpose of just keeping a list of errors found during image scan attempts.
type Failure struct {
	When  metav1.Time `json:"when"`
	Error string      `json:"error"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageScanList holds a list of ImageScan objects.
type ImageScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []ImageScan `json:"items" protobuf:"bytes,2,rep,name=items"`
}
