package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.v1.SnykV1Client;
import io.snyk.sdk.model.v1.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NpmScannerTest {
  @Test
  void shouldTestNpmPackage() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykV1Client snykClient = new SnykV1Client(config);
    NpmScanner scanner = new NpmScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    when(repoPath.toString()).thenReturn("npm:lodash/-/lodash-4.17.15.tgz");
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertFalse(result.success);
    assertEquals(1, result.dependencyCount);
    assertTrue(result.issues.vulnerabilities.size() > 0);
    assertEquals("npm", result.packageManager);
    assertEquals(org, result.organisation.id);
    assertEquals("https://snyk.io/test/npm/lodash/4.17.15", result.packageDetailsURL);
  }

  @Test
  void getPackageDetailsFromUrl_shouldExtractDetailsFromTgzURL() {
    var result = NpmScanner.getPackageDetailsFromUrl(
      "snyk-npm-remote:lodash/-/lodash-4.17.15.tgz"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("lodash", details.name);
    assertEquals("4.17.15", details.version);
  }

  @Test
  void getPackageDetailsFromUrl_shouldExtractDetailsFromTgzURL_WithScope() {
    var result = NpmScanner.getPackageDetailsFromUrl(
      "snyk-npm-remote:@snyk/protect/-/protect-1.675.0.tgz"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("@snyk/protect", details.name);
    assertEquals("1.675.0", details.version);
  }

  @Test
  void getPackageDetailsFromUrl_shouldExtractDetailsFromTgzURL_WithPostfix() {
    var result = NpmScanner.getPackageDetailsFromUrl(
      "snyk-npm-remote:@babel/core/-/core-7.0.0-rc.4.tgz"
    );
    assertTrue(result.isPresent());
    var details = result.get();
    assertEquals("@babel/core", details.name);
    assertEquals("7.0.0-rc.4", details.version);
  }

  @Test
  void getPackageDetailsURL_shouldUseTestPage() {
    var details = new NpmScanner.PackageURLDetails("@babel/core", "7.0.0-rc.4");
    var result = NpmScanner.getPackageDetailsURL(details);
    assertEquals("https://snyk.io/test/npm/@babel/core/7.0.0-rc.4", result);
  }
}
