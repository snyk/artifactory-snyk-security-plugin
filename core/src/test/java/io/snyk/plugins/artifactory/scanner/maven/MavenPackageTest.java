package io.snyk.plugins.artifactory.scanner.maven;

import org.artifactory.fs.FileLayoutInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MavenPackageTest {

  @Test
  void parse() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    Optional<MavenPackage> pkg = MavenPackage.parse(fileLayoutInfo);

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getGroupID()).isEqualTo("com.fasterxml.jackson.core");
    assertThat(pkg.get().getArtifactID()).isEqualTo("jackson-databind");
    assertThat(pkg.get().getName()).isEqualTo("com.fasterxml.jackson.core/jackson-databind");
    assertThat(pkg.get().getVersion()).isEqualTo("2.9.8");
  }

  @Test
  void parse_missingGroupID() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn(null);
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    assertThat(MavenPackage.parse(fileLayoutInfo)).isEmpty();
  }

  @Test
  void parse_missingArtifactID() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn("2.9.8");

    assertThat(MavenPackage.parse(fileLayoutInfo)).isEmpty();
  }

  @Test
  void parse_missingVersion() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getOrganization()).thenReturn("com.fasterxml.jackson.core");
    when(fileLayoutInfo.getModule()).thenReturn("jackson-databind");
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);

    assertThat(MavenPackage.parse(fileLayoutInfo)).isEmpty();
  }
}

