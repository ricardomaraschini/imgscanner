package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	imgv1b1 "github.com/shipwright-io/image/infra/images/v1beta1"
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
	return s.Status.FinishedAt != nil
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

// HasReference returns if the ImageScan has a reference to provided Image.
func (s *ImageScan) HasReference(img *imgv1b1.Image) bool {
	for _, ref := range s.Status.References {
		if ref.UID != img.UID {
			continue
		}
		return true
	}
	return false
}

// HasReferences returns true if the ImageScan contains one or more Image references in its
// status
func (s *ImageScan) HasReferences() bool {
	return len(s.Status.References) > 0
}

// DeleteReference deletes an Image reference from the list of references.
func (s *ImageScan) DeleteReference(delref ImageReference) {
	var newrefs []ImageReference
	for _, ref := range s.Status.References {
		if delref.UID == ref.UID {
			continue
		}
		newrefs = append(newrefs, ref)
	}
	s.Status.References = newrefs
}

// AssureReference makes sure that the ImageScan has a reference to provided Image in its status.
func (s *ImageScan) AssureReference(img *imgv1b1.Image) {
	if s.HasReference(img) {
		return
	}

	s.Status.References = append(
		s.Status.References,
		ImageReference{
			Namespace: img.Namespace,
			Name:      img.Name,
			UID:       img.UID,
		},
	)
}

// HasFailed returns if we still have attempts to be executed. i.e. if we have failed more than
// MaxScanAttempts attempts.
func (s *ImageScan) HasFailed() bool {
	return len(s.Status.Failures) >= MaxScanAttempts
}

// ImageScanStatus hold the status for the last image scan this operator ran.
type ImageScanStatus struct {
	Failures        []Failure        `json:"failures,omitempty"`
	FinishedAt      *metav1.Time     `json:"finishedAt,omitempty"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	References      []ImageReference `json:"references,omitempty"`
}

// ImageReference holds a reference to a single Shipwright Image object.
type ImageReference struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	UID       types.UID `json:"uid"`
}

// Vulnerability describes a vulnerability found in an image. ID points to a CVE while severity
// is scanner dependant.
type Vulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
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
