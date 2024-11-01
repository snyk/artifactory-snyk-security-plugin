package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.exception.SnykAPIFailureException;
import io.snyk.plugins.artifactory.model.MonitoredArtifact;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.v1.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.annotation.Nonnull;
import java.net.http.HttpConnectTimeoutException;
import java.time.Duration;
import java.util.Properties;
import java.util.function.Function;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ScannerModuleTest {

  @Test
  void testGetScannerForPackageType_cannotScanPathsWithDisabledScanners() {
    Properties properties = new Properties();
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "false");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "false");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "false");
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    ScannerModule sm = new ScannerModule(
      configurationModule,
      mock(Repositories.class),
      mock(SnykClient.class)
    );

    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.jar"));
    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.tgz"));
    assertThrows(CannotScanException.class, () -> sm.getScannerForPackageType("myArtifact.whl"));
  }

  ScanTestSetup createScannerSpyModuleForTest(FileLayoutInfo fileLayoutInfo) throws Exception {
    return createScannerSpyModuleForTest(fileLayoutInfo, Function.identity());
  }

  ScanTestSetup createScannerSpyModuleForTest(
    FileLayoutInfo fileLayoutInfo,
    Function<SnykConfig.Builder, SnykConfig.Builder> customiseBuilder
  ) throws Exception {
    SnykConfig config = customiseBuilder.apply(SnykConfigForTests.newBuilder()).build();
    Properties properties = new Properties();
    properties.put(SCANNER_PACKAGE_TYPE_MAVEN.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_NPM.propertyKey(), "true");
    properties.put(SCANNER_PACKAGE_TYPE_PYPI.propertyKey(), "true");

    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);

    RepoPath repoPath = mock(RepoPath.class);

    Repositories repositories = mock(Repositories.class);
    when(repositories.getLayoutInfo(repoPath)).thenReturn(fileLayoutInfo);

    ScannerModule scanner = new ScannerModule(
      configurationModule,
      repositories,
      snykClient);

    ScannerModule scannerSpy = Mockito.spy(scanner);
    return new ScanTestSetup(scannerSpy, repoPath, org);
  }

  class ScanTestSetup {
    ScannerModule scannerModule;
    RepoPath repoPath;
    String org;

    public ScanTestSetup(ScannerModule scannerModule, RepoPath repoPath, String org) {
      this.scannerModule = scannerModule;
      this.repoPath = repoPath;
      this.org = org;
    }
  }

  @Test
  void shouldUseConfiguredTimeoutForAPIRequests() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("minimist");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.2.6");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo, config -> config.setTimeout(Duration.ofMillis(1)));
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:minimist/-/minimist-1.2.6.tgz");

    // Using try-catch as assertThrows does not let us check the cause.
    try {
      spyScanner.scanArtifact(repoPath);
      fail("Expected SnykAPIFailureException for timeout but no exception was thrown.");
    } catch (SnykAPIFailureException e) {
      Throwable cause = e.getCause();
      assertEquals(HttpConnectTimeoutException.class, cause.getClass());
      assertEquals("HTTP connect timed out", cause.getMessage());
    }
  }

  @Test
  void testScanNpmItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("minimist");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.2.6");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:minimist/-/minimist-1.2.6.tgz");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);

    assertEquals(0, result.getTestResult().getVulnSummary().getTotalCount());
  }

  @Test
  void testScanNpmItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("lodash");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("4.17.15");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.tgz");
    when(repoPath.toString()).thenReturn("npm:lodash/-/lodash-4.17.15.tgz");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);
    assertTrue(result.getTestResult().getVulnSummary().getTotalCount() > 0);
  }

  @Test
  void testScanMavenItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("org.apache.commons"); // corresponds to groupId
    when(fileLayoutInfo.getModule()).thenReturn("commons-lang3"); // corresponds to artifactId
    when(fileLayoutInfo.getBaseRevision()).thenReturn("3.12.0");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.jar");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);
    assertEquals(0, result.getTestResult().getVulnSummary().getTotalCount());
  }

  @Test
  void testScanMavenItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core"); // corresponds to groupId
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind"); // corresponds to artifactId
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.jar");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);
    assertTrue(result.getTestResult().getVulnSummary().getTotalCount() > 0);
  }

  @Test
  void testScanPythonItem_noVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("numpy");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.22.2");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.whl");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);
    assertEquals(0, result.getTestResult().getVulnSummary().getTotalCount());
  }

  @Test
  void testScanPythonItem_withVulns() throws Exception {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    ScanTestSetup testSetup = createScannerSpyModuleForTest(fileLayoutInfo);
    ScannerModule spyScanner = testSetup.scannerModule;
    RepoPath repoPath = testSetup.repoPath;
    when(repoPath.getPath()).thenReturn("myArtifact.whl");

    MonitoredArtifact result = spyScanner.resolveArtifact(repoPath);
    assertEquals(6, result.getTestResult().getVulnSummary().getTotalCount());
  }
}
