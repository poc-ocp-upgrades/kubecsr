package aws

import (
	"crypto/x509"
	"fmt"
	"strings"
	"github.com/golang/glog"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	csrutil "k8s.io/client-go/util/certificate/csr"
)

func (ar *Approver) handle(csr *certificates.CertificateSigningRequest) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	glog.V(4).Infof("handle: csr %v", csr)
	if len(csr.Status.Certificate) != 0 {
		return nil
	}
	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}
	x509cr, err := csrutil.ParseCSR(csr)
	if err != nil {
		return err
	}
	glog.V(4).Infof("handle: running recognizers on %s", csr.GetName())
	csrrs := ar.recognizers()
	for _, csrr := range csrrs {
		rs := csrr.recognizers
		approved := true
		for _, r := range rs {
			if rerr := r(csr, x509cr); err != nil {
				glog.V(4).Infof("handle: %v", rerr)
				approved = false
				break
			}
		}
		if !approved {
			continue
		}
		glog.V(4).Infof("csr %s was approved! message: %s", csr.GetName(), csrr.successMessage)
		csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{Type: certificates.CertificateApproved, Reason: "AutoApproved", Message: csrr.successMessage})
		_, err = ar.kubeClient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
		if err != nil {
			return fmt.Errorf("error updating approval for csr: %v", err)
		}
		break
	}
	return nil
}

type recognizerFunc func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error
type csrRecognizer struct {
	recognizers		[]recognizerFunc
	successMessage	string
}

func (ar *Approver) recognizers() []csrRecognizer {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return []csrRecognizer{{recognizers: []recognizerFunc{isSelfNodeClientCert, ar.isValidNode(ar.aws.instanceID), ar.isValidASG(ar.aws.autoScalingGroupID)}, successMessage: "kube-aws-approver approved self node client cert"}, {recognizers: []recognizerFunc{isNodeClientCert, ar.isValidNewNode(ar.aws.instanceID), ar.isValidASG(ar.aws.autoScalingGroupID)}, successMessage: "kube-aws-approver approved new node client cert"}}
}
func isNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if x509cr.Subject.Organization != nil && len(x509cr.Subject.Organization) != 1 && x509cr.Subject.Organization[0] != "system:nodes" {
		return fmt.Errorf("isNodeClientCert: error mismatch org")
	}
	if (len(x509cr.DNSNames) > 0) || (len(x509cr.EmailAddresses) > 0) || (len(x509cr.IPAddresses) > 0) {
		return fmt.Errorf("isNodeClientCert: error non empty dnsnames/emailaddress/ipaddress")
	}
	if !hasExactUsages(csr, kubeletClientUsages) {
		return fmt.Errorf("isNodeClientCert: error invalid key usages")
	}
	if !strings.HasPrefix(x509cr.Subject.CommonName, "system:node:") {
		return fmt.Errorf("isNodeClientCert: error common name doesn't have system:node: prefix")
	}
	return nil
}
func isSelfNodeClientCert(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if err := isNodeClientCert(csr, x509cr); err != nil {
		return err
	}
	if csr.Spec.Username != x509cr.Subject.CommonName {
		return fmt.Errorf("isSelfNodeClientCert: error mismatch Username and CommonName")
	}
	return nil
}

type instanceIDFunc func(nodeName string) (string, error)

func (ar *Approver) isValidNewNode(f instanceIDFunc) recognizerFunc {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		gset := sets.NewString(csr.Spec.Groups...)
		if !gset.Has("system:bootstrappers") {
			return fmt.Errorf("isValidNewNode: error system:bootstrapper doesn't exist in groups")
		}
		idu, err := getInstanceIDFromUsername(csr.Spec.Username)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting id from username: %v", err)
		}
		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting node name from common name: %v", err)
		}
		idn, err := f(nn)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting instance id for %s: %v", nn, err)
		}
		if idn != idu {
			return fmt.Errorf("isValidNewNode: error mismatch instance id from Username and CommonName")
		}
		_, err = ar.kubeClient.CoreV1().Nodes().Get(nn, metav1.GetOptions{})
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("isValidNewNode: error expecting node not found, got: %v", err)
		}
		return nil
	}
}
func (ar *Approver) isValidNode(f instanceIDFunc) recognizerFunc {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		gset := sets.NewString(csr.Spec.Groups...)
		if !gset.Has("system:nodes") {
			return fmt.Errorf("isValidNewNode: error system:nodes doesn't exist in groups")
		}
		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidNewNode: error getting node name from common name: %v", err)
		}
		_, err = f(nn)
		if err != nil {
			return fmt.Errorf("isValidNode: error getting instance id for %s: %v", nn, err)
		}
		node, err := ar.kubeClient.CoreV1().Nodes().Get(nn, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("isValidNode: error getting node %s: %v", nn, err)
		}
		for _, cond := range node.Status.Conditions {
			if cond.Type == v1.NodeReady {
				if cond.Status == v1.ConditionTrue {
					return nil
				}
			}
		}
		return fmt.Errorf("isValidNode: expecting node %s status to be ready, it is not ready", nn)
	}
}

type autoScalingGroupIDFunc func(nodeName string) (string, error)

func (ar *Approver) isValidASG(f autoScalingGroupIDFunc) recognizerFunc {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return func(csr *certificates.CertificateSigningRequest, x509cr *x509.CertificateRequest) error {
		nn, err := getNodeNameFromCN(x509cr.Subject.CommonName)
		if err != nil {
			return fmt.Errorf("isValidASG: error getting node name from common name: %v", err)
		}
		asg, err := f(nn)
		if err != nil {
			return fmt.Errorf("isValidASG: error getting auto scaling group for node %s: %v", nn, err)
		}
		if !ar.allowedASGs.Has(asg) {
			return fmt.Errorf("isValidASG: node %s from invalid asg %s", nn, asg)
		}
		return nil
	}
}
func getCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}

var kubeletClientUsages = []certificates.KeyUsage{certificates.UsageKeyEncipherment, certificates.UsageDigitalSignature, certificates.UsageClientAuth}

func hasExactUsages(csr *certificates.CertificateSigningRequest, usages []certificates.KeyUsage) bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if len(usages) != len(csr.Spec.Usages) {
		return false
	}
	usageMap := map[certificates.KeyUsage]struct{}{}
	for _, u := range usages {
		usageMap[u] = struct{}{}
	}
	for _, u := range csr.Spec.Usages {
		if _, ok := usageMap[u]; !ok {
			return false
		}
	}
	return true
}
func getNodeNameFromCN(cn string) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	nn := strings.TrimPrefix(cn, "system:node:")
	if nn == cn {
		return "", fmt.Errorf("error system:node: prefix not found")
	}
	return nn, nil
}
func getInstanceIDFromUsername(username string) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	id := strings.TrimPrefix(username, "system:bootstrappers:")
	if id == username {
		return "", fmt.Errorf("error system:bootstrappers: prefix not found")
	}
	return id, nil
}
