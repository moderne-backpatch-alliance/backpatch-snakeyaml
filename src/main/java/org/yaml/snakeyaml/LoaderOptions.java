/**
 * Copyright (c) 2008, http://www.snakeyaml.org
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
package org.yaml.snakeyaml;

public class LoaderOptions {

    private int maxAliasesForCollections = 50; //to prevent YAML at https://en.wikipedia.org/wiki/Billion_laughs_attack
    private boolean allowRecursiveKeys;
    private int nestingDepthLimit = 50;

    public int getMaxAliasesForCollections() {
        return maxAliasesForCollections;
    }

    public void setMaxAliasesForCollections(int maxAliasesForCollections) {
    	this.maxAliasesForCollections = maxAliasesForCollections;
    }

    public void setAllowRecursiveKeys(boolean allowRecursiveKeys) {
    	this.allowRecursiveKeys = allowRecursiveKeys;
    }

    public boolean getAllowRecursiveKeys() {
        return allowRecursiveKeys;
    }

    public int getNestingDepthLimit() {
        return nestingDepthLimit;
    }

    /**
     * Set max depth of nested collections. When the limit is exceeded an exception is thrown.
     * Aliases/Anchors are not counted.
     * This is to prevent a DoS attack
     * @param nestingDepthLimit - depth to be accepted (50 by default)
     */
    public void setNestingDepthLimit(int nestingDepthLimit) {
        this.nestingDepthLimit = nestingDepthLimit;
    }
}
