package io.snyk.plugins.artifactory.scanner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EcosystemTest {

  @Test
  void testGetScannerForPackageType() {
    assertEquals(Ecosystem.MAVEN, Ecosystem.fromPackagePath("myArtifact.jar").orElse(null));
    assertEquals(Ecosystem.NPM, Ecosystem.fromPackagePath("myArtifact.tgz").orElse(null));
    assertEquals(Ecosystem.PYPI, Ecosystem.fromPackagePath("myArtifact.whl").orElse(null));
    assertEquals(Ecosystem.PYPI, Ecosystem.fromPackagePath("myArtifact.tar.gz").orElse(null));
    assertEquals(Ecosystem.PYPI, Ecosystem.fromPackagePath("myArtifact.zip").orElse(null));
    assertEquals(Ecosystem.PYPI, Ecosystem.fromPackagePath("myArtifact.egg").orElse(null));
    assertNull(Ecosystem.fromPackagePath("file.txt").orElse(null));
  }
}
