package io.snyk.plugins.artifactory.scanner.maven;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MavenPurlScannerTest {

  MavenPurlScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new MavenPurlScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidMavenPackage() {
    when(repoPath.getName()).thenReturn("jackson-databind-2.9.8.jar");
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getTotalCount()).isGreaterThanOrEqualTo(50)
      .withFailMessage("As of 2025-10-03 jackson-databind@2.9.8 should have at least 50 vulns");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/maven/com.fasterxml.jackson.core%3Ajackson-databind/2.9.8");
  }

  @Test
  void whenGroupIDNotProvided() {
    when(repoPath.getName()).thenReturn("jackson-databind-2.9.8.jar");
    when(fileLayoutInfo.getOrganization()).thenReturn(null);
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    assertThatThrownBy(() -> scanner.scan(fileLayoutInfo, repoPath))
      .isExactlyInstanceOf(CannotScanException.class)
      .hasMessageContaining("Maven package details not provided");
  }

  @Test
  void getArtifactDetailsURL_shouldEncodeNameAndVersion() {
    String result = MavenPurlScanner.getArtifactDetailsURL("com.fasterxml.jackson.core", "jackson-databind", "2.12.0-rc1");
    assertThat(result).isEqualTo("https://security.snyk.io/package/maven/com.fasterxml.jackson.core%3Ajackson-databind/2.12.0-rc1");
  }
}

