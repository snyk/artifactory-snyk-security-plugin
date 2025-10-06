package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.maven.MavenPurlScanner;
import io.snyk.plugins.artifactory.scanner.maven.MavenScanner;
import io.snyk.plugins.artifactory.scanner.npm.NpmPurlScanner;
import io.snyk.plugins.artifactory.scanner.npm.NpmScanner;
import io.snyk.plugins.artifactory.scanner.python.PythonPurlScanner;
import io.snyk.plugins.artifactory.scanner.python.PythonScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Properties;
import java.util.stream.Stream;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
import static io.snyk.plugins.artifactory.ecosystem.Ecosystem.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class ScannerResolverTest {

  @Test
  void scannerEnabled() {
    ScannerResolver resolver = new ScannerResolver((param) -> "true")
      .register(MAVEN, new DummyScanner());

    assertThat(resolver.getFor(MAVEN)).isPresent();
  }

  @Test
  void scannerDisabled() {
    ScannerResolver resolver = new ScannerResolver((param) -> "false")
      .register(MAVEN, new DummyScanner());

    assertThat(resolver.getFor(MAVEN)).isEmpty();
  }

  @Test
  void scannerNotRegistered() {
    ScannerResolver resolver = new ScannerResolver((param) -> "true");

    assertThat(resolver.getFor(MAVEN)).isEmpty();
  }

  @Test
  void setupRegistersPurlScannersWhenRestApiEnabled() throws Exception {
    ConfigurationModule config = buildConfiguration("true");

    SnykConfig snykConfig = SnykConfigForTests.withDefaults();
    SnykClient snykClient = new SnykClient(snykConfig);
    ScannerResolver resolver = ScannerResolver.setup(config, snykClient);

    assertThat(resolver.getFor(MAVEN).get()).isInstanceOf(MavenPurlScanner.class);
    assertThat(resolver.getFor(NPM).get()).isInstanceOf(NpmPurlScanner.class);
    assertThat(resolver.getFor(PYPI).get()).isInstanceOf(PythonPurlScanner.class);
    assertThat(resolver.getFor(RUBYGEMS).isPresent()).isTrue();
    assertThat(resolver.getFor(NUGET).isPresent()).isTrue();
    assertThat(resolver.getFor(COCOAPODS).isPresent()).isTrue();
  }

  @Test
  void setupRegistersRegularScannersWhenRestApiDisabled() throws Exception {
    ConfigurationModule config = buildConfiguration("false");

    SnykConfig snykConfig = SnykConfigForTests.withDefaults();
    SnykClient snykClient = new SnykClient(snykConfig);
    ScannerResolver resolver = ScannerResolver.setup(config, snykClient);

    assertThat(resolver.getFor(MAVEN).get()).isInstanceOf(MavenScanner.class);
    assertThat(resolver.getFor(NPM).get()).isInstanceOf(NpmScanner.class);
    assertThat(resolver.getFor(PYPI).get()).isInstanceOf(PythonScanner.class);
    assertThat(resolver.getFor(RUBYGEMS).isPresent()).isTrue();
    assertThat(resolver.getFor(NUGET).isPresent()).isTrue();
    assertThat(resolver.getFor(COCOAPODS).isPresent()).isTrue();
  }

  private static ConfigurationModule buildConfiguration(String restEnabled) {
    Properties properties = new Properties();
    properties.put(API_TOKEN.propertyKey(), "test-token");
    properties.put(API_ORGANIZATION.propertyKey(), "test-org");
    properties.put(API_REST_ENABLED.propertyKey(), restEnabled);
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_RUBYGEMS.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_NUGET.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_COCOAPODS.propertyKey(), "true");
    return new ConfigurationModule(properties);
  }

  static class DummyScanner implements PackageScanner {

    @Override
    public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
      return new TestResult(
        IssueSummary.from(Stream.empty()),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io")
      );
    }
  }
}
