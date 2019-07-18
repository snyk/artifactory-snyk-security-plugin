package io.snyk.sdk.api.v1;

import javax.annotation.Nullable;

import io.snyk.sdk.model.NotificationSettings;
import io.snyk.sdk.model.TestResult;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface SnykClient {

  /**
   * Get the user notification settings that will determine which emails are sent.
   */
  @GET("user/me/notification-settings")
  Call<NotificationSettings> getNotificationSettings();

  /**
   * Test Maven packages for issues according to their coordinates: group ID, artifact ID and version:
   * <ul>
   * <li><strong>groupId</strong></li>
   * <li><strong>artifactId</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * <li>repository (optional)</li>
   * </ul>
   */
  @GET("test/maven/{groupId}/{artifactId}/{version}")
  Call<TestResult> testMaven(@Path("groupId") String groupId,
                             @Path("artifactId") String artifactId,
                             @Path("version") String version,
                             @Nullable @Query("org") String organisation,
                             @Nullable @Query("repository") String repository);

  /**
   * Test NPM packages for issues according to their name and version:
   * <ul>
   * <li><strong>packageName</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * </ul>
   */
  @GET("test/npm/{packageName}/{version}")
  Call<TestResult> testNpm(@Path("packageName") String packageName,
                           @Path("version") String version,
                           @Nullable @Query("org") String organisation);

  /**
   * Test RubyGems packages for issues according to their name and version:
   * <ul>
   * <li><strong>gemName</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * </ul>
   */
  @GET("test/rubygems/{gemName}/{version}")
  Call<TestResult> testRubyGems(@Path("gemName") String gemName,
                                @Path("version") String version,
                                @Nullable @Query("org") String organisation);

  /**
   * Test Gradle packages for issues according to their group, name and version:
   * <ul>
   * <li><strong>group</strong></li>
   * <li><strong>name</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * <li>repository (optional)</li>
   * </ul>
   */
  @GET("test/gradle/{group}/{name}/{version}")
  Call<TestResult> testGradle(@Path("group") String group,
                              @Path("name") String name,
                              @Path("version") String version,
                              @Nullable @Query("org") String organisation,
                              @Nullable @Query("repository") String repository);

  /**
   * Test SBT packages for issues according to their coordinates: group ID, artifact ID and version:
   * <ul>
   * <li><strong>groupId</strong></li>
   * <li><strong>artifactId</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * <li>repository (optional)</li>
   * </ul>
   */
  @GET("test/sbt/{groupId}/{artifactId}/{version}")
  Call<TestResult> testSbt(@Path("groupId") String groupId,
                           @Path("artifactId") String artifactId,
                           @Path("version") String version,
                           @Nullable @Query("org") String organisation,
                           @Nullable @Query("repository") String repository);

  /**
   * Test PIP packages for issues according to their name and version:
   * <ul>
   * <li><strong>packageName</strong></li>
   * <li><strong>version</strong></li>
   * <li>organisation (optional)</li>
   * </ul>
   */
  @GET("test/pip/{packageName}/{version}")
  Call<TestResult> testPip(@Path("packageName") String packageName,
                           @Path("version") String version,
                           @Nullable @Query("org") String organisation);
}
