# k8s-cert-generator
The k8s-cert-generator is a CLI tool designed to generate CA and TLS certificates for Kubernetes clusters. It simplifies the process of creating the necessary certificates for secure communication within your Kubernetes environment.

## Installation
To install k8s-cert-generator, you need to have Go installed on your machine. If you don't have Go installed, you can download and install it from the official Go website.

Once you have Go set up, you can install k8s-cert-generator by running the following command:

```
go install github.com/panshuai-ps/k8s-cert-generator@latest
```

This command will download and install the k8s-cert-generator binary to your $GOPATH/bin directory or $GOBIN directory if set. Ensure that the installation path is included in your system's PATH environment variable so that you can run the k8s-cert-generator from any location.

## Generating Certificates
After installing k8s-cert-generator, you can generate the necessary Kubernetes certificates by executing the following command:

```
k8s-cert-generator generate
```

By default, this command will create a pki directory in your current working directory and place all generated certificates inside it. Make sure you have the proper permissions to write to your current working directory.
