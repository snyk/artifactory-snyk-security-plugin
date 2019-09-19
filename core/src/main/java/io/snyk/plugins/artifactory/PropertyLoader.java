package io.snyk.plugins.artifactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Properties;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

final class PropertyLoader {

  private static final String DIRECTORY_NOT_FOUND_ERROR_MESSAGE = "Directory '%s' not found";
  private static final String FILE_NOT_FOUND_ERROR_MESSAGE = "File '%s' not found";

  private static final String PLUGIN_VERSION_FILE = "snykSecurityPlugin.version";
  private static final String PROPERTY_FILE = "snykSecurityPlugin.properties";

  private PropertyLoader() {
    //squid:S1118
  }

  static Properties loadProperties(@Nonnull File pluginsDirectory) throws IOException {
    if (!pluginsDirectory.exists()) {
      throw new IOException(format(DIRECTORY_NOT_FOUND_ERROR_MESSAGE, pluginsDirectory.getAbsolutePath()));
    }

    File propertyFile = new File(pluginsDirectory, PROPERTY_FILE);
    if (!propertyFile.exists()) {
      throw new IOException(format(FILE_NOT_FOUND_ERROR_MESSAGE, propertyFile.getAbsolutePath()));
    }

    Properties properties = new Properties();
    try (FileInputStream fis = new FileInputStream(propertyFile)) {
      properties.load(fis);
    }
    return properties;
  }

  static String loadPluginVersion(@Nonnull File pluginsDirectory) throws IOException {
    if (!pluginsDirectory.exists()) {
      throw new IOException(format(DIRECTORY_NOT_FOUND_ERROR_MESSAGE, pluginsDirectory.getAbsolutePath()));
    }

    File libDirectory = new File(pluginsDirectory, "lib");
    if (!libDirectory.exists()) {
      throw new IOException(format(DIRECTORY_NOT_FOUND_ERROR_MESSAGE, libDirectory.getAbsolutePath()));
    }
    File pluginVersionFile = new File(libDirectory, PLUGIN_VERSION_FILE);
    if (!pluginVersionFile.exists()) {
      throw new IOException(format(FILE_NOT_FOUND_ERROR_MESSAGE, pluginVersionFile.getAbsolutePath()));
    }

    return new String(Files.readAllBytes(pluginVersionFile.toPath()), UTF_8);
  }
}
