package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
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

public class MavenScannerTest {
  @Test
  void shouldTestMavenPackage() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
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

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertTrue(result.getVulnSummary().getTotalCount() > 0);
    assertEquals("https://security.snyk.io/package/maven/com.fasterxml.jackson.core%3Ajackson-databind/2.9.8",
      result.getDetailsUrl().toString()
    );
  }

  @Test
  void shouldNotTestMavenPackage_WhenGroupIDNotProvided() throws Exception {
    SnykConfig config = SnykConfigForTests.withDefaults();
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
    SnykConfig config = SnykConfigForTests.withDefaults();
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
    SnykConfig config = SnykConfigForTests.withDefaults();
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

  @Test
  void getPackageDetailsURL_shouldEncodeNameAndVersion() {
    var result = MavenScanner.getArtifactDetailsURL("com.fasterxml.jackson.core", "jackson-databind", "2.12.0-rc1");
    assertEquals("https://security.snyk.io/package/maven/com.fasterxml.jackson.core%3Ajackson-databind/2.12.0-rc1", result);
  }
}
