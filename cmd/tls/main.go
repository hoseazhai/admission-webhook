package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/hoseazhai/admission-webhook/pkg"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	var caPEM, serverCertPEM, serverPrivKeyPEM *bytes.Buffer
	// CA config
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"hosea.io"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// CA private key
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// self signed CA certificate
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode CA cert
	caPEM = new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	dnsNames := []string{"admission-webhook", "admission-webhook.default", "admission-webhook.default.svc"}
	commonName := "admission-webhook.default.svc"

	// server cert config
	cert := &x509.Certificate{
		DNSNames: dnsNames,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"hosea.io"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// server private key
	serverPriKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPriKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PME encode the server cert and key
	serverCertPEM = new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})
	serverPrivKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPriKey),
	})

	err = os.MkdirAll("/etc/webhook/certs/", 0666)
	if err != nil {
		log.Panic(err)
	}
	err = WriteFIle("/etc/webhook/certs/tls.crt", serverCertPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	err = WriteFIle("/etc/webhook/certs/tls.key", serverPrivKeyPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	log.Println("webhook sever tls generated successfully")
	if err := CreateAdmissionConfig(caPEM); err != nil {
		log.Panic(err)
	}
	log.Println("webhook admission config object generated successfully")
}

func WriteFIle(filepath string, bts []byte) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bts)
	if err != nil {
		return err
	}
	return nil
}

func CreateAdmissionConfig(caCert *bytes.Buffer) error {
	clientset, err := pkg.InitKubernetesCli()
	if err != nil {
		return err
	}

	var (
		webhookNamespace, _ = os.LookupEnv("WEBHOOK_NAMESPACE")
		validateCfgName, _  = os.LookupEnv("VALIDATE_CONFIG")
		mutateCfgName, _    = os.LookupEnv("MUTATE_CONFIG")
		webhookService, _   = os.LookupEnv("WEBHOOK_SERVICE")
		validatePath, _     = os.LookupEnv("VALIDATE_PATH")
		mutatePath, _       = os.LookupEnv("MUTATE_PATH")
	)

	ctx := context.Background()
	if validateCfgName != "" {
		// 创建ValidatingWebhookConiguration
		validateConfig := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: validateCfgName,
			},
			Webhooks: []admissionv1.ValidatingWebhook{
				{
					Name: "io.hosea.admission-webhook",
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admissionv1.ServiceReference{
							Namespace: webhookNamespace,
							Name:      webhookService,
							Path:      &validatePath,
						},
					},
					Rules: []admissionv1.RuleWithOperations{
						{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule: admissionv1.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"pods"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionv1.SideEffectClass {
						se := admissionv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		validateAdmissionClient := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		if _, err := validateAdmissionClient.Get(ctx, validateCfgName, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				if _, err := validateAdmissionClient.Create(ctx, validateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := validateAdmissionClient.Update(ctx, validateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	if mutateCfgName != "" {
		mutateConfig := &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: mutateCfgName,
			},
			Webhooks: []admissionv1.MutatingWebhook{
				{
					Name: "io.hosea.admission-webhook",
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admissionv1.ServiceReference{
							Namespace: webhookNamespace,
							Name:      webhookService,
							Path:      &mutatePath,
						},
					},
					Rules: []admissionv1.RuleWithOperations{
						{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule: admissionv1.Rule{
								APIGroups:   []string{"apps", "v1"},
								APIVersions: []string{"v1"},
								Resources:   []string{"deployments", "service"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionv1.SideEffectClass {
						se := admissionv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		mutateAdmissionClient := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
		if _, err := mutateAdmissionClient.Get(ctx, mutateCfgName, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				if _, err := mutateAdmissionClient.Create(ctx, mutateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := mutateAdmissionClient.Update(ctx, mutateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}
