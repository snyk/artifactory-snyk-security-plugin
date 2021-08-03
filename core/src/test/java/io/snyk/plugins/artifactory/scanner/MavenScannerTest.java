package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.Properties;

import static io.snyk.plugins.artifactory.configuration.PluginConfiguration.API_ORGANIZATION;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MavenScannerTest {
  @Test
  void shouldTestMavenPackage() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    MavenScanner scanner = new MavenScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    Optional<TestResult> result = scanner.scan(fileLayoutInfo, repoPath);
    Assertions.assertTrue(result.isPresent());
    TestResult actualResult = result.get();
    assertFalse(actualResult.success); // false because it has vulns
    assertEquals(3, actualResult.dependencyCount);
    assertEquals(47, actualResult.issues.vulnerabilities.size());
    assertEquals("maven", actualResult.packageManager);
    assertEquals(org, actualResult.organisation.id);
    assertEquals("https://snyk.io/vuln/maven:com.fasterxml.jackson.core%3Ajackson-databind@2.9.8",
      actualResult.packageDetailsURL
    );
  }

  @Test
  void shouldNotTestMavenPackage_WhenGroupIDNotProvided() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    MavenScanner scanner = new MavenScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn(null);
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    assertThrows(CannotScanException.class, () -> scanner.scan(fileLayoutInfo, repoPath));
  }

  @Test
  void shouldNotTestMavenPackage_WhenArtifactIDNotProvided() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    MavenScanner scanner = new MavenScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    assertThrows(CannotScanException.class, () -> scanner.scan(fileLayoutInfo, repoPath));
  }

  @Test
  void shouldNotTestMavenPackage_WhenArtifactVersionNotProvided() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    MavenScanner scanner = new MavenScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);

    assertThrows(CannotScanException.class, () -> scanner.scan(fileLayoutInfo, repoPath));
  }
}
