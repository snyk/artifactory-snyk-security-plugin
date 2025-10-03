package io.snyk.plugins.artifactory.scanner.python;

import org.artifactory.fs.FileLayoutInfo;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PythonPackageTest {

  @Test
  void parseFromFileLayoutInfo() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    Optional<PythonPackage> pkg = PythonPackage.parseFromFileLayoutInfo(fileLayoutInfo);

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("urllib3");
    assertThat(pkg.get().getVersion()).isEqualTo("1.25.7");
  }

  @Test
  void parseFromFileLayoutInfo_missingModule() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn(null);
    when(fileLayoutInfo.getBaseRevision()).thenReturn("1.25.7");

    assertThat(PythonPackage.parseFromFileLayoutInfo(fileLayoutInfo)).isEmpty();
  }

  @Test
  void parseFromFileLayoutInfo_missingVersion() {
    FileLayoutInfo fileLayoutInfo = mock(FileLayoutInfo.class);
    when(fileLayoutInfo.getModule()).thenReturn("urllib3");
    when(fileLayoutInfo.getBaseRevision()).thenReturn(null);

    assertThat(PythonPackage.parseFromFileLayoutInfo(fileLayoutInfo)).isEmpty();
  }

  @Test
  void parseFromUrl_tarGz() {
    Optional<PythonPackage> pkg = PythonPackage.parseFromUrl(
      "pypi:8c/15/3298c4ee5d187a462883a7f80d7621a05e8b880a8234729e733769a3476f/urllib3-1.25.7.tar.gz"
    );

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("urllib3");
    assertThat(pkg.get().getVersion()).isEqualTo("1.25.7");
  }

  @Test
  void parseFromUrl_wheel() {
    Optional<PythonPackage> pkg = PythonPackage.parseFromUrl(
      "pypi:73/d1/8891d9f1813257b2ea06261cfb23abbd660fa344d7067a1283fb9195d9cd/pandas-1.3.1-cp39-cp39-macosx_10_9_x86_64.whl"
    );

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("pandas");
    assertThat(pkg.get().getVersion()).isEqualTo("1.3.1");
  }

  @Test
  void parseFromUrl_withPostfix() {
    Optional<PythonPackage> pkg = PythonPackage.parseFromUrl(
      "pypi:f9/1a/312d3cc9d29ac72a53d2a85144f5dce1e97b4ad513008394cfed5e27ffa2/ws3-0.0.1.post3-py3-none-any.whl"
    );

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("ws3");
    assertThat(pkg.get().getVersion()).isEqualTo("0.0.1.post3");
  }

  @Test
  void parseFromUrl_unexpectedInput() {
    assertThat(PythonPackage.parseFromUrl("urllib3-1.25.7.tar.gz")).isEmpty();
  }

  @Test
  void parseFromUrl_null() {
    assertThat(PythonPackage.parseFromUrl(null)).isEmpty();
  }
}

