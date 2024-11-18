# Artifactory Gatekeeper plugin

For information about the Artifactory Gatekeeper plugin, see the Snyk user
docs, [Artifactory Gatekeeper plugin](https://docs.snyk.io/integrations/private-registry-gatekeeper-plugins/artifactory-gatekeeper-plugin-overview).

## Local development

## Running artifactory locally
You can run artifactory pro with docker compose. There are a few steps needed to set it up:

### Step 1: Initialise the file system
Start up the containers:

```shell
docker compose up
```

That will initialise the system files at `distribution/docker`.

### Step 2: Point Artifactory to the DB
Ctrl+C out of the containers and edit the DB configuration in
`distribution/docker/etc/system.yaml`:

```yaml
    database:
        type: postgresql
        driver: org.postgresql.Driver
        url: "jdbc:postgresql://postgres/artifactory"
        username: artifactory
        password: password
```

Run `docker compose up` again. The application should start at [localhost:8082](http://localhost:8082),
you can log in with username `admin` and password `password`.

### Step 3: Enable the license
Artifactory pro license is required to run the plugin. You can get a trial one
for free by signing up at [JFrog website](https://jfrog.com/start-free/).
Paste the license in you artifactory.

There! You have an artifactory pro running locally. Time to install the Snyk plugin.

## Installing the plugin
Build the plugin first with `mvn install -DskipTests`.
Then unpack the release into artifactory's plugins folder:

```shell
unzip -o distribution/target/artifactory-snyk-security-plugin-LOCAL-SNAPSHOT.zip -d distribution/docker/etc/artifactory/
```

Set your Snyk org ID and API token inside `distribution/docker/etc/artifactory/plugins/snykSecurityPlugin.properties`
and restart Artifactory. Check [the logs](http://localhost:8082/ui/admin/artifactory/advanced/system_logs)
to confirm the plugin gets loaded.

After making changes to the plugin, repeat `mvn install` and extract the jar file but without touching your config:

```shell
unzip -p distribution/target/artifactory-snyk-security-plugin-LOCAL-SNAPSHOT.zip plugins/lib/artifactory-snyk-security-core.jar > distribution/docker/etc/artifactory/plugins/lib/artifactory-snyk-security-core.jar
unzip -p distribution/target/artifactory-snyk-security-plugin-LOCAL-SNAPSHOT.zip plugins/snykSecurityPlugin.groovy > distribution/docker/etc/artifactory/plugins/snykSecurityPlugin.groovy
```

## Inspecting plugin logs
In order to see the logs, set the log level for Snyk by inserting this line: `<logger name="io.snyk" level="debug"/>`
into this file: `distribution/docker/etc/artifactory/logback.xml`.
