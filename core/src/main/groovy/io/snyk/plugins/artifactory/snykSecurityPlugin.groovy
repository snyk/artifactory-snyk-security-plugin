package io.snyk.plugins.artifactory

import groovy.transform.Field
import org.artifactory.fs.ItemInfo
import org.artifactory.repo.RepoPath
import org.artifactory.request.Request

@Field SnykPlugin snykPlugin

initialize()

private void initialize() {
  log.info("Initializing snykSecurityPlugin...")

  final File pluginsDirectory = ctx.artifactoryHome.pluginsDir
  snykPlugin = new SnykPlugin(repositories, pluginsDirectory)

  log.info("Initialization of snykSecurityPlugin completed")
}

executions {
  snykSecurityReload(httpMethod: "POST") { params ->
    initialize()
  }
}

download {

  beforeDownload { Request request, RepoPath repoPath ->
    try {
      snykPlugin.handleBeforeDownloadEvent(repoPath)
    } catch (Exception e) {
      log.error("An exception occurred during beforeDownload, re-throwing it for Artifactory to handle. Message was: ${e.message}")
      throw e
    }
  }

}

storage {

  afterCreate { ItemInfo itemInfo ->
    try {
      snykPlugin.handleAfterCreate(itemInfo.repoPath)
    } catch (Exception e) {
      log.error("An exception occurred during afterCreate, re-throwing it for Artifactory to handle. Message was: ${e.message}")
      throw e
    }
  }

  afterPropertyCreate { ItemInfo itemInfo, String propertyName, String[] propertyValues ->
    try {
      snykPlugin.handleAfterPropertyCreateEvent(security.currentUser(), itemInfo, propertyName, propertyValues)
    } catch (Exception e) {
      log.error("An exception occurred during afterPropertyCreate, re-throwing it for Artifactory to handle. Message was: ${e.message}")
      throw e;
    }
  }
}
