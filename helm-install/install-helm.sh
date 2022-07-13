#!/bin/zsh
# follows https://www.jfrog.com/confluence/display/JFROG/Installing+Artifactory#InstallingArtifactory-HelmInstallation
set -e
SCRIPT_RELATIVE_DIR=$(dirname "${BASH_SOURCE[0]}")

minikube stop && minikube start --kubernetes-version=1.24.1 --disk-size=100g && eval "$(minikube docker-env)" || echo 'maybe u need to "brew install minikube"'
minikube addons enable ingress

pushd "$SCRIPT_RELATIVE_DIR"/.. || exit 1
  curl -s "https://get.sdkman.io" | bash
  source "$HOME/.sdkman/bin/sdkman-init.sh"
  sdk install java 11.0.15-zulu # please install sdkman for this to work
  sdk use java 11.0.15-zulu # please install sdkman for this to work
  # build
  ./mvnw clean package -DskipTests
  # unzip distribution
  pushd distribution/target
    unzip artifactory-snyk-security-plugin-LOCAL-SNAPSHOT.zip
    SNYK=$(type snyk|cut -f3 -d" ")
    if [[ $SNYK == "" ]];then
      curl https://static.snyk.io/cli/latest/snyk-macos > snyk
      chmod +x snyk
      SNYK="$PWD/snyk"
    fi
    SNYK_TOKEN=$($SNYK config get api)
    if [[ $SNYK_TOKEN == "" ]]; then
      $SNYK auth
    fi
    ORG=$(curl -s -H "Authorization: token $SNYK_TOKEN" https://snyk.io/api/v1/orgs | jq -r '.orgs|first|.id')

    # monkey patching config file
    pushd plugins
      echo "Adding Snyk Token and Snyk Org to config..."
      grep -v "snyk.api.token=" snykSecurityPlugin.properties > snykSecurityPlugin.properties.temp
      echo "snyk.api.token=$SNYK_TOKEN" >> snykSecurityPlugin.properties.temp
      grep -v "snyk.api.organization=" snykSecurityPlugin.properties.temp > snykSecurityPlugin.properties.temp2
      echo "snyk.api.organization=$ORG" >> snykSecurityPlugin.properties.temp2
      rm snykSecurityPlugin.properties.temp
      mv snykSecurityPlugin.properties.temp2 snykSecurityPlugin.properties
    popd
  popd
  # add plugin to kubernetes as configmap
    helm uninstall --namespace artifactory artifactory
  if [[ $(kubectl get ns | grep artifactory) != "" ]]; then
        # remove previous deployment completely
      kubectl delete ns artifactory
  fi
  kubectl create ns artifactory
  kubectl create cm snyk-plugin --from-file=distribution/target/plugins -n artifactory

  helm repo add jfrog https://charts.jfrog.io || echo "Helm repo already added"
  helm repo update
  # Create a key
  MASTER_KEY=$(openssl rand -hex 32)
  echo "Master Key: ${MASTER_KEY}"
  kubectl create secret generic my-masterkey-secret -n artifactory --from-literal=master-key="${MASTER_KEY}"

  # create join key
  JOIN_KEY=$(openssl rand -hex 32)
  echo "Join Key: ${JOIN_KEY}"
  kubectl create secret generic my-joinkey-secret -n artifactory --from-literal=join-key="${JOIN_KEY}"

  # install
  helm upgrade --install artifactory \
   --set postgresql.enabled=false \
   --set artifactory.joinKeySecretName=my-joinkey-secret \
   --set artifactory.masterKeySecretName=my-masterkey-secret \
   -f helm-install/snyk-plugin-deploy.yaml \
   --namespace artifactory jfrog/artifactory
popd || exit 1

minikube service artifactory-artifactory-nginx -n artifactory
