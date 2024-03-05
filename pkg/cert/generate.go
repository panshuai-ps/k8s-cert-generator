package cert

import (
    "crypto"
    "crypto/x509"
    "fmt"
    "net"
    "os"
    "path"

    "k8s.io/klog/v2"
    "path/filepath"
)

var (
    KubeDefaultCertPath     = "/etc/kubernetes/pki"
    kubeDefaultCertEtcdPath = "/etc/kubernetes/pki/etcd"
)

func CaList(CertPath, CertEtcdPath string) []Config {
    return []Config{
        {
            Path:         CertPath,
            BaseName:     "ca",
            CommonName:   "kubernetes",
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{},
            Usages:       nil,
        },
        {
            Path:         CertPath,
            BaseName:     "front-proxy-ca",
            CommonName:   "front-proxy-ca",
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{},
            Usages:       nil,
        },
        {
            Path:         CertEtcdPath,
            BaseName:     "ca",
            CommonName:   "etcd-ca",
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{},
            Usages:       nil,
        },
    }
}

func List(CertPath, CertEtcdPath string) []Config {
    return []Config{
        {
            Path:         CertPath,
            BaseName:     "apiserver",
            CAName:       "kubernetes",
            CommonName:   "kube-apiserver",
            Organization: nil,
            Year:         100,
            AltNames: AltNames{
                DNSNames: map[string]string{
                    "localhost":              "localhost",
                    "kubernetes":             "kubernetes",
                    "kubernetes.default":     "kubernetes.default",
                    "kubernetes.default.svc": "kubernetes.default.svc",
                },
                IPs: map[string]net.IP{
                    "127.0.0.1": net.IPv4(127, 0, 0, 1),
                },
            },
            Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        },
        {
            Path:         CertPath,
            BaseName:     "client",
            CAName:       "kubernetes",
            CommonName:   "kubernetes-admin",
            Organization: []string{"system:masters"},
            Year:         100,
            AltNames:     AltNames{},
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertPath,
            BaseName:     "apiserver-kubelet-client",
            CAName:       "kubernetes",
            CommonName:   "kube-apiserver-kubelet-client",
            Organization: []string{"system:masters"},
            Year:         100,
            AltNames:     AltNames{},
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertPath,
            BaseName:     "front-proxy-client",
            CAName:       "front-proxy-ca",
            CommonName:   "front-proxy-client",
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{},
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertPath,
            BaseName:     "apiserver-etcd-client",
            CAName:       "etcd-ca",
            CommonName:   "kube-apiserver-etcd-client",
            Organization: []string{"system:masters"},
            Year:         100,
            AltNames:     AltNames{},
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertEtcdPath,
            BaseName:     "server",
            CAName:       "etcd-ca",
            CommonName:   "etcd", // kubeadm using node name as common name cc.CommonName = mc.NodeRegistration.Name
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{}, // need set altNames
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertEtcdPath,
            BaseName:     "peer",
            CAName:       "etcd-ca",
            CommonName:   "etcd-peer", // change this in filter
            Organization: nil,
            Year:         100,
            AltNames:     AltNames{}, // change this in filter
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        },
        {
            Path:         CertEtcdPath,
            BaseName:     "healthcheck-client",
            CAName:       "etcd-ca",
            CommonName:   "kube-etcd-healthcheck-client",
            Organization: []string{"system:masters"},
            Year:         100,
            AltNames:     AltNames{},
            Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        },
    }
}

type CertMetaData struct {
    APIServer    AltNames
    NodeName     string
    NodeIP       string
    DNSDomain    string
    CertPath     string
    CertEtcdPath string
}

const (
    APIserverCert = iota
    APIserverKubeletClientCert
    FrontProxyClientCert
    APIserverEtcdClientCert
    EtcdServerCert
    EtcdPeerCert
    EtcdHealthcheckClientCert
)

func NewCertMetaData(apiServerIPAndDomains []string, svcCIDR, nodeName, nodeIP, DNSDomain string) (*CertMetaData, error) {
    pwd, err := os.Getwd()
    if err != nil {
        return nil, err
    }

    data := &CertMetaData{}
    data.CertPath = filepath.Join(pwd, "pki")
    data.CertEtcdPath = filepath.Join(pwd, "pki", "etcd")
    data.DNSDomain = DNSDomain
    data.NodeIP = nodeIP
    data.NodeName = nodeName
    data.APIServer.IPs = make(map[string]net.IP)
    data.APIServer.DNSNames = make(map[string]string)

    svcFirstIP, _, err := net.ParseCIDR(svcCIDR)
    if err != nil {
        klog.Warningf("%v", err)
    } else {
        svcFirstIP[len(svcFirstIP)-1]++
        data.APIServer.IPs[svcFirstIP.String()] = svcFirstIP
    }

    if ip := net.ParseIP(nodeIP); ip != nil {
        data.APIServer.IPs[ip.String()] = ip
    }

    for _, altName := range apiServerIPAndDomains {
        ip := net.ParseIP(altName)
        if ip != nil {
            data.APIServer.IPs[ip.String()] = ip
            continue
        }
        data.APIServer.DNSNames[altName] = altName
    }

    return data, nil
}

func (meta *CertMetaData) apiServerAltName(certList *[]Config) {
    for _, dns := range meta.APIServer.DNSNames {
        (*certList)[APIserverCert].AltNames.DNSNames[dns] = dns
    }
    if meta.DNSDomain != "" {
        svcDNS := fmt.Sprintf("kubernetes.default.svc.%s", meta.DNSDomain)
        (*certList)[APIserverCert].AltNames.DNSNames[svcDNS] = svcDNS
    }
    if meta.NodeName != "" {
        (*certList)[APIserverCert].AltNames.DNSNames[meta.NodeName] = meta.NodeName
    }
    for _, ip := range meta.APIServer.IPs {
        (*certList)[APIserverCert].AltNames.IPs[ip.String()] = ip
    }
    klog.Infof("apiserver altNames : %+v", (*certList)[APIserverCert].AltNames)
}

func (meta *CertMetaData) etcdAltAndCommonName(certList *[]Config) {
    if meta.NodeName == "" {
        return
    }

    altname := AltNames{
        DNSNames: map[string]string{
            "localhost":   "localhost",
            meta.NodeName: meta.NodeName,
        },
        IPs: map[string]net.IP{
            net.IPv4(127, 0, 0, 1).String():         net.IPv4(127, 0, 0, 1),
            net.ParseIP(meta.NodeIP).To4().String(): net.ParseIP(meta.NodeIP).To4(),
            net.IPv6loopback.String():               net.IPv6loopback,
        },
    }
    (*certList)[EtcdServerCert].CommonName = meta.NodeName
    (*certList)[EtcdServerCert].AltNames = altname
    (*certList)[EtcdPeerCert].CommonName = meta.NodeName
    (*certList)[EtcdPeerCert].AltNames = altname

    klog.Infof("Etcd altnames : %v, commonName : %s", (*certList)[EtcdPeerCert].AltNames, (*certList)[EtcdPeerCert].CommonName)
}

// create sa.key sa.pub for service Account
func (meta *CertMetaData) generatorServiceAccountKeyPaire() error {
    dir := meta.CertPath
    _, err := os.Stat(path.Join(dir, "sa.key"))
    if !os.IsNotExist(err) {
        klog.Infof("sa.key sa.pub already exist")
        return nil
    }

    key, err := NewPrivateKey(x509.RSA)
    if err != nil {
        return err
    }
    pub := key.Public()

    err = WriteKey(dir, "sa", key)
    if err != nil {
        return err
    }

    return WritePublicKey(dir, "sa", pub)
}

func (meta *CertMetaData) GenerateAll() error {
    cas := CaList(meta.CertPath, meta.CertEtcdPath)
    certs := List(meta.CertPath, meta.CertEtcdPath)
    meta.apiServerAltName(&certs)
    meta.etcdAltAndCommonName(&certs)
    _ = meta.generatorServiceAccountKeyPaire()

    CACerts := map[string]*x509.Certificate{}
    CAKeys := map[string]crypto.Signer{}
    for _, ca := range cas {
        caCert, caKey, err := NewCaCertAndKey(ca)
        if err != nil {
            return err
        }
        CACerts[ca.CommonName] = caCert
        CAKeys[ca.CommonName] = caKey

        err = WriteCertAndKey(ca.Path, ca.BaseName, caCert, caKey)
        if err != nil {
            return err
        }
    }

    for _, cert := range certs {
        caCert, ok := CACerts[cert.CAName]
        if !ok {
            return fmt.Errorf("root ca cert not found %s", cert.CAName)
        }
        caKey, ok := CAKeys[cert.CAName]
        if !ok {
            return fmt.Errorf("root ca key not found %s", cert.CAName)
        }

        Cert, Key, err := NewCaCertAndKeyFromRoot(cert, caCert, caKey)
        if err != nil {
            return err
        }
        err = WriteCertAndKey(cert.Path, cert.BaseName, Cert, Key)
        if err != nil {
            return err
        }
    }
    return nil
}
