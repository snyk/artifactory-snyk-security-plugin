package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NpmScannerTest {
  @Test
  void shouldTestNpmPackage() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    SnykClient snykClient = new SnykClient(config);
    NpmScanner scanner = new NpmScanner(configurationModule, snykClient);

    RepoPath repoPath = mock(RepoPath.class);
    when(repoPath.toString()).thenReturn("npm:lodash/-/lodash-4.17.15.tgz");
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);

    Optional<TestResult> result = scanner.scan(fileLayoutInfo, repoPath);
    Assertions.assertTrue(result.isPresent());
    TestResult actualResult = result.get();
    assertFalse(actualResult.success);
    assertEquals(1, actualResult.dependencyCount);
    assertEquals(5, actualResult.issues.vulnerabilities.size());
    assertEquals("npm", actualResult.packageManager);
    assertEquals(org, actualResult.organisation.id);
    assertEquals("https://snyk.io/vuln/npm:lodash@4.17.15", actualResult.packageDetailsURL);
  }

  // TODO: test a case where repoPath is not matching the regex
}
