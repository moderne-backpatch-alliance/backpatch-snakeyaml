/**
 * Copyright (c) 2008-2011, http://www.snakeyaml.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.yaml.snakeyaml.issues.issue543;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.YAMLException;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.SequenceNode;
import org.yaml.snakeyaml.nodes.Tag;

/**
 * CVE-2022-41854 (oss-fuzz 50355): a mapping key whose sequence contains itself, built as a node graph.
 */
public class RecursiveKeyNodeGraphTest {

  @Test(timeout = 10000)
  public void selfContainingSequenceKeyIsRejected() {
    List<Node> items = new ArrayList<Node>();
    SequenceNode key = new SequenceNode(Tag.SEQ, items, Boolean.TRUE);
    items.add(key);
    // the Composer marks a node that an alias inside it refers back to
    key.setTwoStepsConstruction(true);
    List<NodeTuple> tuples = new ArrayList<NodeTuple>();
    tuples.add(new NodeTuple(key, new ScalarNode(Tag.STR, "value", null, null, (Character) null)));
    MappingNode mapping = new MappingNode(Tag.MAP, tuples, Boolean.FALSE);
    try {
      new NodeGraphConstructor().construct(mapping);
      fail("a self-containing sequence was accepted as a mapping key");
    } catch (YAMLException e) {
      assertEquals("Recursive key for mapping is detected but it is not configured to be allowed.",
          e.getMessage());
    }
  }

  private static class NodeGraphConstructor extends SafeConstructor {

    Object construct(Node node) {
      return constructObject(node);
    }
  }
}
