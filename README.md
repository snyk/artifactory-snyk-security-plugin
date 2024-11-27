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

## Testing supported ecosystems
Here are some tips for pointing local dev tools to Artifactory in order to try out the plugin.

### NPM
1. In the Artifactory UI, create a remote NPM repository using Repository Key `npm`.
2. Authenticate your NPM client: `npm login --registry=http://localhost:8081/artifactory/api/npm/npm/ --auth-type=web`.
3. Install a package `npm add jest-get-type@30.0.0-alpha.5 --registry=http://localhost:8081/artifactory/api/npm/npm/ --cache /tmp/npm-cache && rm -rf /tmp/npm-cache`

### Maven
This actually uses a Gradle project to test:
1. In the Artifactory UI, create a remote Maven repository using Repository Key `maven`.
2. Drop repository coords in `settings.gradle.kts` of your Gradle project (see the snippet below).
```kotlin
pluginManagement {
	repositories {
		maven {
			url = uri("http://localhost:8082/artifactory/maven/")
			isAllowInsecureProtocol = true
			credentials {
				username = "admin"
				password = "password"
			}
		}
		gradlePluginPortal()
	}
}
```
3. Make sure the `repositories` block only includes your Artifactory in `build.gradle.kts` (see the second snippet below).
```kotlin
repositories {
	maven {
		url = uri("http://localhost:8082/artifactory/maven/")
		isAllowInsecureProtocol = true
		credentials {
			username = "admin"
			password = "password"
		}
	}
}
```
4. Install your project's dependencies.


### PyPi
1. In the Artifactory UI, create a remote Pypi repository using Repository Key `pypi`.
2. `pip3 install --index-url http://localhost:8082/artifactory/api/pypi/pypi/simple libdev`

### Ruby Gems
1. In the Artifactory UI, create a remote Gems repository using Repository Key `rubygems`.
2. Still in the Artifactory UI, navigate to the artifacts view and hit the `Set me up` option.
3. Choose the `rubygems` repository and generate an access token.
4. `gem source -a http://admin:ACCESS_TOKEN_FROM_PREVIOUS_STEP@localhost:8081/artifactory/api/gems/rubygems/`
5. `gem install openssl`

### Cocoapods
1. In the Artifactory UI, create a remote CocoaPods repository using Repository Key `cocoapods`.
2. Create a `Podfile`:
```
source "http://localhost:8081/artifactory/api/pods/cocoapods"
project 'project/test/test.xcodeproj'
platform :ios, '10.0'
target 'test' do
  use_frameworks!
  pod 'Alamofire', '~> 5.10'
  pod 'Bolts', '~> 1.9'
end
```
3. `pod install`

### Nuget
1. In the Artifactory UI, create a remote Nuget repository using Repository Key `nuget`.
2. `nuget sources Add -Name Artifactory -Source http://localhost:8081/artifactory/api/nuget/nuget`
3. Disable the default source: `nuget sources disable -Name nuget.org`.
4. Verify only Artifactory is enabled: `nuget sources List`.
5. `nuget install Newtonsoft.Json -Version 13.0.1`
