package io.snyk.sdk.api.v1;

import javax.annotation.Nullable;

import io.snyk.sdk.model.TestResult;
import retrofit2.Call;
import retrofit2.http.GET;
import retrofit2.http.Path;
import retrofit2.http.Query;

public interface SnykClient {

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
  Call<TestResult> testMavenByGAV(@Path("groupId") String groupId,
                                  @Path("artifactId") String artifactId,
                                  @Path("version") String version,
                                  @Nullable @Query("org") String organisation,
                                  @Nullable @Query("repository") String repository);
}
