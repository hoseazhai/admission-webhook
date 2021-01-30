package pkg

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func InitKubernetesCli() (*kubernetes.Clientset, error) {
	var (
		err    error
		config *rest.Config
	)
	if config, err = rest.InClusterConfig(); err != nil {
		return nil, err
	}

	// 创建ClientSet 对象
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, err
}
