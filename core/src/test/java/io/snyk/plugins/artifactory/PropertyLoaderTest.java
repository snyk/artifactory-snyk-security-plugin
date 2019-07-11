package io.snyk.plugins.artifactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertLinesMatch;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PropertyLoaderTest {

  private static File TEST_DIRECTORY;

  @BeforeAll
  static void setUpAll() throws Exception {
    URL testDirectoryUrl = PropertyLoaderTest.class.getClassLoader().getResource("./io/snyk/plugins/artifactory/PropertyLoaderTest");
    TEST_DIRECTORY = new File(requireNonNull(testDirectoryUrl).toURI());
  }

  @Test
  void loadProperties_shouldThrowIOE_ifPluginsDirNotExist() {
    Path notExistingPluginsDir = Paths.get(TEST_DIRECTORY.getAbsolutePath(), "not-existing-plugins-dir");

    IOException exception = assertThrows(IOException.class, () -> PropertyLoader.loadProperties(notExistingPluginsDir.toFile()));
    assertLinesMatch(singletonList("^Directory '.*' not found$"), singletonList(exception.getMessage()));
  }

  @Test
  void loadProperties_shouldThrowIOE_ifPropertyFileNotExist() {
    Path pluginsDirWithoutPropertyFile = Paths.get(TEST_DIRECTORY.getAbsolutePath(), "without-property-file");

    IOException exception = assertThrows(IOException.class, () -> PropertyLoader.loadProperties(pluginsDirWithoutPropertyFile.toFile()));
    assertLinesMatch(singletonList("^File '.*' not found$"), singletonList(exception.getMessage()));
  }

  @Test
  void loadProperties_shouldNotThrowException_ifPropertyFileExist() throws IOException {
    Path pluginsDirWithoutPropertyFile = Paths.get(TEST_DIRECTORY.getAbsolutePath(), "valid-property-file");

    PropertyLoader.loadProperties(pluginsDirWithoutPropertyFile.toFile());
  }
}
