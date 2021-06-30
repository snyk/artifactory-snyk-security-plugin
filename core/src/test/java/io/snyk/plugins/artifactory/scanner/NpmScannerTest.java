package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.configuration.ConfigurationModule;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.NewSnykClient;
import io.snyk.sdk.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
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
  void canTestNpmPackage() throws Exception {
    Snyk.Config config = new Snyk.Config(System.getenv("TEST_SNYK_TOKEN"));
    Properties properties = new Properties();
    @Nonnull String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    properties.put(API_ORGANIZATION.propertyKey(), org);
    ConfigurationModule configurationModule = new ConfigurationModule(properties);

    NewSnykClient snykClient = new NewSnykClient(config);
    NpmScanner scanner = new NpmScanner(configurationModule, snykClient);

    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("lodash");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("4.17.15");

    Optional<TestResult> result = scanner.scan(fileLayoutInfo);
    Assertions.assertTrue(result.isPresent());
    TestResult actualResult = result.get();
    assertFalse(actualResult.success);
    assertEquals(1, actualResult.dependencyCount);
    assertEquals(5, actualResult.issues.vulnerabilities.size());
    assertEquals("npm", actualResult.packageManager);
    assertEquals(org, actualResult.organisation.id);
  }
}
