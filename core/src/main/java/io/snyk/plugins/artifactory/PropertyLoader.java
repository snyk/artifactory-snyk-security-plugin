package io.snyk.plugins.artifactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

final class PropertyLoader {

  private static final String PROPERTY_FILE = "snykSecurityPlugin.properties";

  private PropertyLoader() {
    //squid:S1118
  }

  static Properties loadProperties(@Nonnull File pluginsDirectory) throws IOException {
    if (!pluginsDirectory.exists()) {
      throw new IOException("Directory '" + pluginsDirectory.getAbsolutePath() + "' not found");
    }

    File propertyFile = new File(pluginsDirectory, PROPERTY_FILE);
    if (!propertyFile.exists()) {
      throw new IOException("File '" + propertyFile.getAbsolutePath() + "' not found");
    }

    Properties properties = new Properties();
    try (FileInputStream fis = new FileInputStream(propertyFile)) {
      properties.load(fis);
    }
    return properties;
  }
}
