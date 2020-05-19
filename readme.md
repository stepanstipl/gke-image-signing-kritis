# Kubernetes Image Signing<br />with GCP Container Analysis<br />and Kritis

This guide will show you how to sign your Images and setup GKE Kubernetes
Cluster to enforce deploy-time security policies using the [Google Cloud
Container Analysis API][gca] and [Kritis][kritis].

[gca]: https://cloud.google.com/container-registry/docs/reference/rest 
[kritis]: https://github.com/grafeas/kritis

### Variables used in this document

- `${GCP_PROJECT}` - GCP Project ID
- `${IMAGE_NAME}` - Docker Image name
- `${IMAGE_TAG}` - Docker Image tag
- `${IMAGE_SHA}` - Docker Image SHA
- `${GPG_USER}` - GPG User ID used to sign the image
- `${NOTE_NAME}` - Name of the Grafeas Note used for signing
- `${K8S_NAMESPACE` - Kubernetes Namespace to deploy Kritis into

### Prerequisites

- `curl`
- `docker`
- `gcloud`
- `git`
- `gpg`, GPG private and public key to use for signing
- `kubectl`, configured to access GKE Cluster
- `openssl`
- GKE Cluster, with [Workload Identity][gke-wi] enabled

[gke-wi]: https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity

## Usage

Any file paths used in the document are relative to the root of the repository.

Start by cloning the repository locally and changing working directory to the
local folder.

```sh
git clone https://github.com/stepanstipl/gke-image-signing-kritis
cd gke-image-signing-kritis/
```

### Set initial variables

Start by setting up several Environment variables used throughout this document.

```bash
GCP_PROJECT="your-gcp-project-id"
GPG_USER="joe@example.com"
IMAGE_NAME="alpine"
IMAGE_TAG="3.9.5"
NOTE_NAME="seal-of-approval"
K8S_NAMESPACE="kritis"
```

### Setup Container Analysis API

You will first enable and perform initial setup of the [Google Container Analysis API][gca] (GCA). GCA is an artifact metadata API, based on open source project [Grafeas][grafeas]. It can be used to store and query various type of metadata about your software artifacts, such as signatures, vulnerabilities or deployments. This API is required both to sign container images, as well as to retrieve security information about existing images. Container Analysis uses the API to store vulnerability scanning results about images upload to GCR.

Grafeas uses concepts of Notes and Occurrences. Notes are high-level descriptions of particular type of metadata. Occurrences are instances of notes, describing how a given note occurs on a resource.

Image Attestation (signature) is an example of a Note. Attestation for `gcr.io/google.com/cloudsdktool/cloud-sdk@sha256:1615d48b376b8a03b6beb6fc3efb62346ddb24f9492d8aa5367ab9d1bdd46482` image is example of an Occurence.

You will also need to enable [Google Container Scanning API][csapi], as this enables vulnerability scanning in your project. Note that you get billed for every scanned image.

[grafeas]: https://grafeas.io/
[gca]: https://cloud.google.com/container-registry/docs/reference/rest
[csapi]: https://cloud.google.com/container-registry/docs/enabling-disabling-container-analysis

- **Enable  Container Analysis API**

  ```sh
  gcloud services enable containeranalysis.googleapis.com
  ```

- **Enable  Container Scanning API**

  ```sh
  gcloud services enable containerscanning.googleapis.com
  ```


### Deploy Kritis

[Kritis][kritis] is policy enforcer for Kubernetes, implemented as Kubernetes Admission Webhook. Kritis runs as a service inside your Kubernetes Cluster and requires access to the GCA API.

- **Create GCP Service Account for Kritis**

  Create Service Account and allow it to be used by Workload Identity

  ```sh
  gcloud iam service-accounts create kritis

  gcloud iam service-accounts add-iam-policy-binding \
    "kritis@${GCP_PROJECT}.iam.gserviceaccount.com" \
    --member="serviceAccount:${GCP_PROJECT}.svc.id.goog[${K8S_NAMESPACE}/kritis]" \
    --role='roles/iam.workloadIdentityUser'
  ```

- **Create and assign required role to Service Account**

  ```sh
  gcloud iam roles create kritisRole \
    --permissions "containeranalysis.notes.listOccurrences,containeranalysis.occurrences.list" \
    --project "${GCP_PROJECT}"

  gcloud projects add-iam-policy-binding "${GCP_PROJECT}" \
    --member "serviceAccount:kritis@${GCP_PROJECT}.iam.gserviceaccount.com" \
    --role "projects/${GCP_PROJECT}/roles/kritisRole"
  ```

- **Generete CSR for Kritis Certificates** 
  ```sh
  cat > openssl.conf <<EOF
  [ req ]
  default_bits = 2048
  prompt = no
  encrypt_key = no
  distinguished_name = req_dn
  req_extensions = req_ext

  [ req_dn ]
  CN = kritis-validation-hook.${K8S_NAMESPACE}.svc.cluster.local

  [ req_ext ]
  subjectAltName = @alt_names

  [ alt_names ]
  DNS.1 = kritis-validation-hook.${K8S_NAMESPACE}.svc 
  EOF


  openssl req -new -config openssl.conf \
    -out server.csr \
    -keyout server.key
  ```

- **Create CSR**

  ```sh
  cat <<EOF | kubectl apply -f-
  apiVersion: certificates.k8s.io/v1beta1
  kind: CertificateSigningRequest
  metadata:
    name: kritis-tls
  spec:
    request: $(cat server.csr | base64 | tr -d '\n')
    usages:
    - digital signature
    - key encipherment
    - server auth
  EOF
  ```

- **Approve CSR**

  ```sh
  kubectl certificate approve kritis-tls
  ```

- **Create Kritis Namespace**

  ```sh
  kubectl create ns "${K8S_NAMESPACE}"
  ```

- **Create Certificate**

  ```sh
  kubectl get csr kritis-tls \
    -o jsonpath='{.status.certificate}' \
  | base64 --decode > server.crt

  kubectl create secret tls tls-kritis-secret -n "${K8S_NAMESPACE}" \
    --key="server.key" \
    --cert="server.crt"
  ```

- **Deploy Kritis**

  Create CRDs
  ```sh
  kubectl apply -f deploy/crds.yaml
  ```

  Create Cluster Role, Cluster Role Binding and Service Account

  ```sh
  kubectl apply -f deploy/cluster-role.yaml

  sed "s/\${K8S_NAMESPACE}/${K8S_NAMESPACE}/g" deploy/cluster-role-binding.yaml \
  | kubectl apply -f-

  sed "s/\${K8S_NAMESPACE}/${K8S_NAMESPACE}/g" deploy/service-account.yaml \
  | sed "s/\${GCP_PROJECT}/${GCP_PROJECT}/g" \
  | kubectl apply -f-
  ```

  Create Kritis Deployment and Service

  ```sh
  sed "s/\${K8S_NAMESPACE}/${K8S_NAMESPACE}/g" deploy/deployment.yaml \
  | kubectl apply -f-

  sed "s/\${K8S_NAMESPACE}/${K8S_NAMESPACE}/g" deploy/service.yaml \
  | kubectl apply -f-
  ```

- **Create Admision Webhook**

  This Admission Wehook tells Kubernetes Cluster to validate any requests for given type of operations (CREATE, UPDATE) on given type of resources (pods, deployments, replicasets) by calling our Kritis service. 

  Note: `failurePolicy: Ignore` in the manifest tells K8s how to behave in case the validation service fails or is unreachable. It can be set to `Fail`, but be careful - this can negatively impact your cluster availability.

  ```sh
  K8S_CA_BUNDLE=$(kubectl config view --raw --minify \
    --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}')

  sed "s/\${K8S_NAMESPACE}/${K8S_NAMESPACE}/g" deploy/webhook.yaml \
  | sed "s/\${K8S_CA_BUNDLE}/${K8S_CA_BUNDLE}/g" \
  | kubectl apply -f-
  ```

### Admitting Images Based on Name Only

This is currently not supported, Image has to have at least one attestation when using `GenericAttestationPolicy` to be allowed. This is addressed in https://github.com/grafeas/kritis/pull/449.


### Admitting Images Based on Vulnerability Scans

- **Create `ImageSecurityPolicy`**

  ```console
  cat <<EOF | kubectl apply -f-
  apiVersion: kritis.grafeas.io/v1beta1
  kind: ImageSecurityPolicy
  metadata:
    name: test-security-policy
    namespace: default
  spec:
    packageVulnerabilityRequirements:
      maximumSeverity: MEDIUM
      allowlistCVEs:
        - providers/goog-vulnz/notes/CVE-2017-1000082
        - providers/goog-vulnz/notes/CVE-2017-1000081
  EOF
  ```

- **Populate your GCR Registry**

  Copy two image with security vulnerabilities (such as older `ubuntu:xenial-20161010`) to your GCR registry:
  ```sh
  docker pull ubuntu:xenial-20161010
  docker tag ubuntu:xenial-20161010 gcr.io/${GCP_PROJECT}/ubuntu:xenial-20161010
  docker push gcr.io/${GCP_PROJECT}/ubuntu:xenial-20161010
  ```

- **Review Found Vulnerabilities**
  Wait until these have been scanned (can take couple of minutes) and verify that some `CRITICAL` vulnerabilities have been found:
  ```sh
  gcloud beta container images list-tags gcr.io/${GCP_PROJECT}/ubuntu
  ```
  The output should list some critical vulnerabilities for the ubuntu image, such as `CRITICAL=4,HIGH=30,LOW=12,MEDIUM=69`.

- **Test image won't be admitted**

  Deploy image without vulnerabilities:
  ```sh
  # Get image SHA
  IMAGE_VULN_SHA=$(docker inspect "ubuntu:xenial-20161010" \
  --format='{{range .RepoDigests}}{{printf "%s\n" .}}{{end}}' \
  | grep gcr.io \
  | cut -f2 -d"@")

  # Image digest (SHA) can change once pushed to new registry
  # -> always take the correct digest for given registry.

  # Deploy Pod
  cat <<EOF | kubectl apply -f-
  apiVersion: v1
  kind: Pod
  metadata:
    name: test-healthy
  spec:
    containers:
    - name: hello
      image: "gcr.io/${GCP_PROJECT}/ubuntu:@${IMAGE_VULN_SHA}"
      command: ["/bin/sh", "-c", "while true; do echo 'Hello World!'; date; sleep 1; done"]
  EOF
  ```

  Image should not be admitted with message such as:
  ```
  Error from server: error when creating "STDIN": admission webhook "kritis-validation-hook.grafeas.io"
  denied the request: found violations in gcr.io/<GCP_PROJECT>/ubuntu@sha256:0ab17d92ef2450481576e0c4ba0700b8e3699e3e72295577762e30866198974a
  ```

### Setup Container Analysis API for Signing

- **Create Grafeas Note**

  ```sh
  cat > note.json <<EOF
  {
    "name": "projects/${GCP_PROJECT}/notes/${NOTE_NAME}",
    "shortDescription": "Image Attestation.",
    "longDescription": "Image Attestation.",
    "attestation": {
      "hint": {
        "humanReadableName": "Seal of Approval"
  }}}
  EOF

  curl -X POST "https://containeranalysis.googleapis.com/v1/projects/${GCP_PROJECT}/notes?noteId=${NOTE_NAME}" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json; charset=utf-8" \
    -d @note.json
  ```

- **Verify the Note has been created** (optional)
  ```sh
  curl "https://containeranalysis.googleapis.com/v1/projects/${GCP_PROJECT}/notes/${NOTE_NAME}" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)"
  ```

### Sign Image

Images have to be referenced by their digests. Digests are immutable (as opposed to tags).

- **Push image to GCR Registry**

  Currently Kritis implementation requires that all images are stored in a GCR registry.

  ```sh
  docker pull "${IMAGE_NAME}:${IMAGE_TAG}"
  docker tag "${IMAGE_NAME}:${IMAGE_TAG}" "eu.gcr.io/${GCP_PROJECT}/${IMAGE_NAME}:${IMAGE_TAG}"
  docker push "eu.gcr.io/${GCP_PROJECT}/${IMAGE_NAME}:${IMAGE_TAG}"
  ```

- **Get Image SHA**

  Find and note full image digest (`${IMAGE_SHA}`) of the docker image:

  ```sh
  IMAGE_SHA=$(docker inspect "${IMAGE_NAME}:${IMAGE_TAG}" \
    --format='{{range .RepoDigests}}{{printf "%s\n" .}}{{end}}' \
  | grep gcr.io \
  | cut -f2 -d"@")
  ```

  *Image digest (SHA) can change once pushed to new registry -> always take the correct digest for given registry.*

- **Prepare GPG Signature and Key**

  Generate image signature:
  ```sh
  cat <<EOF | gpg -u "${GPG_USER}" -a --sign > signature.gpg
  {
    "critical": {
        "type": "atomic container signature",
        "image": {
         "docker-manifest-digest": "${IMAGE_SHA}"
	},
        "identity": {
            "docker-reference": "eu.gcr.io/${GCP_PROJECT}/${IMAGE_NAME}"
  }}}
  EOF
  ```

  Verify the signature (optional)

  ```sh
  gpg --output - --verify signature.gpg
  ```

  Export public GPG Key:
  ```sh
  gpg --armor --export "${GPG_USER}" > key.pub
  ```

- **Create Grafeas Occurence**

  Occurence is instance of a Note specific for your image.

  ```sh
  GPG_KEY_ID=$(gpg --list-keys --with-colons "${GPG_USER}" \
  | awk -F: '$1 == "fpr"{print $10;}' | head -n1)

  cat > occurrence.json <<EOF
  {
    "resource": {
      "uri": "https://eu.gcr.io/${GCP_PROJECT}/${IMAGE_NAME}@${IMAGE_SHA}"
    },
    "noteName": "projects/${GCP_PROJECT}/notes/${NOTE_NAME}",
    "attestation": {
      "attestation": {
      	"pgpSignedAttestation": {
          "signature": "$(base64 signature.gpg)",
          "contentType": "SIMPLE_SIGNING_JSON",
          "pgpKeyId": "${GPG_KEY_ID}"
  }}}}
  EOF

  curl -X POST "https://containeranalysis.googleapis.com/v1beta1/projects/${GCP_PROJECT}/occurrences" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json; charset=utf-8" \
    -d @occurrence.json
  ```

  Verify the Occurence has been created (optional)
  ```sh
  curl "https://containeranalysis.googleapis.com/v1beta1/projects/${GCP_PROJECT}/occurrences" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)"
  ```



### Configure Kritis to require Attestation

Kritis has concept of [Attestation Authority][att-auth], which basically maps to one or more GPG keys accepted for verifying Attestations, and [Attestation Policy][att-pol]. Policy then defines which Attestations are required for Image to be admitted (for a given Namespace). 

[att-auth]: https://github.com/grafeas/kritis/blob/master/docs/resources.md#attestationauthority-crd
[att-pol]: https://github.com/grafeas/kritis/blob/master/docs/resources.md#genericattestationpolicy-crd

- **Create Attestation Authority**

  ```sh
  cat <<EOF | kubectl apply -f-
  apiVersion: kritis.grafeas.io/v1beta1
  kind: AttestationAuthority
  metadata:
    name: ${NOTE_NAME}
    namespace: default
  spec:
    noteReference: projects/${GCP_PROJECT}
    publicKeyData: $(base64 key.pub)
  EOF
  ```

- **Create Attestation Policy**
  ```sh
  cat <<EOF | kubectl apply -f-
  apiVersion: kritis.grafeas.io/v1beta1
  kind: GenericAttestationPolicy
  metadata:
    name: ${NOTE_NAME}-policy
    namespace: default
  spec:
    attestationAuthorityNames:
    - ${NOTE_NAME}
  EOF
  ```


### Test Image Signing

- **Deploy Pod that uses the signed image**

  Images have to be from gcr.io (or regional eu., us. and asia. variants) registry and referenced by SHA digest.

  ```sh
  cat <<EOF | kubectl apply -f-
  apiVersion: v1
  kind: Pod
  metadata:
    name: test
  spec:
    containers:
    - name: hello
      image: eu.gcr.io/${GCP_PROJECT}/${IMAGE_NAME}@${IMAGE_SHA}
      command: ["/bin/sh", "-c", "while true; do echo 'Hello World!'; date; sleep 1; done"]
  EOF
  ```

  This Pod should be admitted to run.

  ```
  kubectl get pod test
  ```
  
- **Deploy Pod that uses unsigned image**
  ```sh
  cat <<EOF | kubectl apply -f-
  apiVersion: v1
  kind: Pod
  metadata:
    name: test-unsigned
  spec:
    containers:
    - name: hello
      # gcr.io/google.com/cloudsdktool/cloud-sdk:285.0.1-alpine
      image: gcr.io/google.com/cloudsdktool/cloud-sdk@sha256:1615d48b376b8a03b6beb6fc3efb62346ddb24f9492d8aa5367ab9d1bdd46482
      command: ["/bin/sh", "-c", "while true; do echo 'Hello World!'; date; sleep 1; done"]
  EOF
  ```

  This Pod is expected to be denied, as the used Image has not been signed.

## Caveats
- Kritis can crash when parsing unexpected payloads in the GCA Occurence or Attestation Authority.
- Occurence and Note structure changed between v1beta1 anv v1 of GCA API, currently Kritis only supports v1beta1.
