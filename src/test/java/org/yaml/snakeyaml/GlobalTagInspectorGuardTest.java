/**
 * Copyright (c) 2008, SnakeYAML
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package org.yaml.snakeyaml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.yaml.snakeyaml.composer.ComposerException;

/**
 * Regression tests for CVE-2022-1471: {@code new Yaml().load()} of a document carrying a custom
 * global tag (e.g. {@code !!javax.script.ScriptEngineManager}) instantiated an arbitrary Java class,
 * a critical remote-code-execution vector. This backport rejects custom global tags by default
 * (mirroring the snakeyaml-2.0 mechanism) while keeping 1.33's public API byte-compatible.
 *
 * <p>Backpatch-fresh: the 1.x line never received an upstream fix. The escape hatch
 * {@code -Dorg.yaml.snakeyaml.allowGlobalTags=true} restores the legacy permissive behavior.
 */
public class GlobalTagInspectorGuardTest {

  private static final String ALLOW_PROPERTY = "org.yaml.snakeyaml.allowGlobalTags";

  public static class LegacyBean {

    private String name;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }
  }

  @Test
  public void rejectsGlobalTagScriptEngineManagerPayload() {
    try {
      Object loaded = new Yaml().load("!!javax.script.ScriptEngineManager {}");
      fail("custom global tag must be rejected by default, but loaded: " + loaded);
    } catch (ComposerException e) {
      assertTrue("unexpected message: " + e.getMessage(),
          e.getMessage().contains("Global tag is not allowed"));
    }
  }

  @Test
  public void stillLoadsStandardScalarsSequencesAndMaps() {
    Yaml yaml = new Yaml();
    // Plain (resolver-typed) values are untouched.
    assertEquals(Integer.valueOf(42), yaml.load("42"));
    assertEquals("text", yaml.load("text"));
    assertEquals(Arrays.asList(1, 2, 3), yaml.load("[1, 2, 3]"));
    // Explicit standard yaml.org tags are not custom-global and must still load.
    assertEquals(Integer.valueOf(7), yaml.load("!!int 7"));
    List<?> seq = yaml.load("!!seq [a, b]");
    assertEquals(Arrays.asList("a", "b"), seq);
    Map<?, ?> map = yaml.load("!!map {x: 1}");
    assertEquals(Integer.valueOf(1), map.get("x"));
  }

  @Test
  public void allowGlobalTagsPropertyRestoresLegacyBehavior() {
    System.setProperty(ALLOW_PROPERTY, "true");
    try {
      Object loaded = new Yaml()
          .load("!!org.yaml.snakeyaml.GlobalTagInspectorGuardTest$LegacyBean {name: ok}");
      assertNotNull(loaded);
      assertTrue("expected a LegacyBean, got: " + loaded.getClass(), loaded instanceof LegacyBean);
      assertEquals("ok", ((LegacyBean) loaded).getName());
    } finally {
      System.clearProperty(ALLOW_PROPERTY);
    }
  }
}
