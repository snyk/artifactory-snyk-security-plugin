# Artifactory Gatekeeper plugin

For information about the Artifactory Gatekeeper plugin, see the Snyk user
docs, [Artifactory Gatekeeper plugin](https://docs.snyk.io/integrations/private-registry-gatekeeper-plugins/artifactory-gatekeeper-plugin-overview).

## Setup local development environment

### Download an Artifactory Docker image:

```
docker pull releases-docker.jfrog.io/jfrog/artifactory-pro:latest
```

Does not have to be `pro`, but in this example we'll do it.

### Create a `$JFROG_HOME` folder

```
mkdir -p ~/.jfrog/artifactory/var/
```

Export it to your environment for ease of use

```
echo export JFROG_HOME=~/.jfrog >> ~/.zshrc
```

### Build the plugin

Depends a lot on your system. But something like

```
mvn install -DskipTests
```

Will probably work. Per default, you'll find a baked `.zip`
in `~/.m2/repository/io/snyk/plugins/artifactory-snyk-security-plugin/LOCAL-SNAPSHOT`.

Edit the `.properties` file to something like:

```
snyk.api.token=<INSERT_TOKEN>
snyk.api.organization=<INSERT_ORG_ID>
snyk.api.url=http://host.docker.internal:8000/api/v1/
```

The latter if you want to debug against a local registry. At least if you're on OSX, you cannot probe
against `localhost` from within a Docker container.

Also, remember to activate some of the scanners depending on what you're debugging:

```
snyk.scanner.packageType.maven=true
snyk.scanner.packageType.npm=true
snyk.scanner.packageType.pypi=true
```

### Enable debugging JVM options

```
vim $JFROG_HOME/artifactory/var/etc/system.yaml
``` 

Add `extraJavaOpts`

```
shared:
    ## Java 17 distribution to use
    #javaHome: "JFROG_HOME/artifactory/app/third-party/java"

    ## Extra Java options to pass to the JVM. These values add to or override the defaults.
    #extraJavaOpts: "-Xms512m -Xmx4g"
    extraJavaOpts: "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
```

### Run the Docker image

And ensure you expose debugging ports, in this case, `5005`

```
docker run -d --name artifactory -p 8888:8082 -p 8081:8081 -p 5005:5005 -v $JFROG_HOME/artifactory/var/:/var/opt/jfrog/artifactory releases-docker.jfrog.io/jfrog/artifactory-pro:latest
```

Wait until the Docker has loaded, it can take a while. Check the progress with `docker logs -f <id>`.

#### Notice for M1 Macs

You'll have a ton of trouble if you default to building your Docker images as `linux/amd64`. At least I had. Ensure you
do not have a env variable like `DOCKER_DEFAULT_PLATFORM=linux/amd64` enabled when pulling and/or running the image.
