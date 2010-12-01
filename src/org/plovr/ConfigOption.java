package org.plovr;

import java.io.File;
import java.util.Map;

import org.plovr.ModuleConfig.BadDependencyTreeException;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.javascript.jscomp.CheckLevel;
import com.google.javascript.jscomp.DiagnosticGroup;
import com.google.javascript.jscomp.WarningLevel;

public enum ConfigOption {

  // DO NOT alpha-sort this list!
  // The enum order is the order in which these options appear in the generated
  // HTML documentation, so the most important options are deliberately listed
  // first.

  ID("id", new ConfigUpdater() {
    @Override
    public void apply(String id, Config.Builder builder) {
      builder.setId(id);
    }
  }),

  INPUTS("inputs" , new ConfigUpdater() {
    @Override
    public void apply(String input, Config.Builder builder) {
      builder.addInputByName(input);
    }

    @Override
    public void apply(JsonArray inputs, Config.Builder builder) {
      for (JsonElement item : inputs) {
        String input = GsonUtil.stringOrNull(item);
        if (input != null) {
          apply(input, builder);
        }
      }
    }
  }),

  PATHS("paths", new ConfigUpdater() {
    @Override
    public void apply(String path, Config.Builder builder) {
      String resolvedPath = maybeResolvePath(path, builder);
      builder.addPath(resolvedPath);
    }

    @Override
    public void apply(JsonArray paths, Config.Builder builder) {
      for (JsonElement item : paths) {
        String path = GsonUtil.stringOrNull(item);
        if (path != null) {
          apply(path, builder);
        }
      }
    }
  }),

  EXTERNS("externs", new ConfigUpdater() {
    @Override
    public void apply(String extern, Config.Builder builder) {
      String resolvedPath = maybeResolvePath(extern, builder);
      builder.addExtern(resolvedPath);
    }

    @Override
    public void apply(JsonArray externs, Config.Builder builder) {
      for (JsonElement item : externs) {
        String extern = GsonUtil.stringOrNull(item);
        if (extern != null) {
          apply(extern, builder);
        }
      }
    }
  }),

  CUSTOM_EXTERNS_ONLY("custom-externs-only", new ConfigUpdater() {
    @Override
    public void apply(boolean customExternsOnly, Config.Builder builder) {
      builder.setCustomExternsOnly(customExternsOnly);
    }
  }),

  CLOSURE_LIBRARY("closure-library", new ConfigUpdater() {
    @Override
    public void apply(String path, Config.Builder builder) {
      String resolvedPath = maybeResolvePath(path, builder);
      builder.setPathToClosureLibrary(resolvedPath);
    }
  }),

  COMPILATION_MODE("mode", new ConfigUpdater() {
    @Override
    public void apply(String mode, Config.Builder builder) {
      try {
        CompilationMode compilationMode = CompilationMode.valueOf(mode.toUpperCase());
        builder.setCompilationMode(compilationMode);
      } catch (IllegalArgumentException e) {
        // OK
      }
    }

    @Override
    public boolean update(String mode, Config.Builder builder) {
      apply(mode, builder);
      return true;
    }
  }),

  WARNING_LEVEL("level", new ConfigUpdater() {
    @Override
    public void apply(String level, Config.Builder builder) {
      try {
        WarningLevel warningLevel = WarningLevel.valueOf(level.toUpperCase());
        builder.setWarningLevel(warningLevel);
      } catch (IllegalArgumentException e) {
        // OK
      }
    }

    @Override
    public boolean update(String level, Config.Builder builder) {
      apply(level, builder);
      return true;
    }
  }),

  DEBUG("debug", new ConfigUpdater() {
    @Override
    public void apply(boolean debug, Config.Builder builder) {
      builder.setDebugOptions(debug);
    }

    @Override
    public boolean update(String debugParam, Config.Builder builder) {
      boolean debug = Boolean.valueOf(debugParam);
      builder.setDebugOptions(debug);
      return true;
    }
  }),

  PRETTY_PRINT("pretty-print", new ConfigUpdater() {
    @Override
    public void apply(boolean prettyPrint, Config.Builder builder) {
      builder.setPrettyPrint(prettyPrint);
    }

    @Override
    public boolean update(String prettyPrintParam, Config.Builder builder) {
      boolean prettyPrint = Boolean.valueOf(prettyPrintParam);
      builder.setPrettyPrint(prettyPrint);
      return true;
    }
  }),

  PRINT_INPUT_DELIMITER("print-input-delimiter", new ConfigUpdater() {
    @Override
    public void apply(boolean printInputDelimiter, Config.Builder builder) {
      builder.setPrintInputDelimiter(printInputDelimiter);
    }

    @Override
    public boolean update(String printInputDelimiterParam, Config.Builder builder) {
      boolean printInputDelimiter = Boolean.valueOf(printInputDelimiterParam);
      builder.setPrintInputDelimiter(printInputDelimiter);
      return true;
    }
  }),

  OUTPUT_WRAPPER("output-wrapper", new ConfigUpdater() {
    @Override
    public void apply(String outputWrapper, Config.Builder builder) {
      builder.setOutputWrapper(outputWrapper);
    }
  }),

  FINGERPRINT("fingerprint", new ConfigUpdater() {
    @Override
    public void apply(boolean fingerprint, Config.Builder builder) {
      builder.setFingerprintJsFiles(fingerprint);
    }
  }),

  MODULES("modules", new ConfigUpdater() {
    @Override
    public void apply(JsonObject modules, Config.Builder builder) {
      try {
        ModuleConfig.Builder moduleConfigBuilder = builder.getModuleConfigBuilder();
        moduleConfigBuilder.setModuleInfo(modules);
      } catch (BadDependencyTreeException e) {
        throw new RuntimeException(e);
      }
    }
  }),

  MODULE_OUTPUT_PATH("module-output-path", new ConfigUpdater() {
    @Override
    public void apply(String outputPath, Config.Builder builder) {
      ModuleConfig.Builder moduleConfigBuilder = builder.getModuleConfigBuilder();
      moduleConfigBuilder.setOutputPath(outputPath);
    }
  }),

  MODULE_PRODUCTION_URI("module-production-uri", new ConfigUpdater() {
    @Override
    public void apply(String productionUri, Config.Builder builder) {
      ModuleConfig.Builder moduleConfigBuilder = builder.getModuleConfigBuilder();
      moduleConfigBuilder.setProductionUri(productionUri);
    }
  }),

  /**
   * This option is used to write the plovr module info JS into a separate file
   * instead of prepending it to the root module. Prepending the JS causes the
   * source map to be several lines off in the root module, so doing this avoids
   * that issue.
   */
  // TODO(bolinfest): A better approach may be to fix the source map, in which
  // case this option could be eliminated.
  MODULE_INFO_PATH("module-info-path",
      new ConfigUpdater() {
    @Override
    public void apply(String moduleInfoPath, Config.Builder builder) {
      ModuleConfig.Builder moduleConfigBuilder = builder.getModuleConfigBuilder();
      moduleConfigBuilder.setModuleInfoPath(moduleInfoPath);
    }
  }),

  DEFINE("define", new ConfigUpdater() {
    @Override
    public void apply(JsonObject obj, Config.Builder builder) {
      for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
        JsonElement element = entry.getValue();
        if (element.isJsonPrimitive()) {
          String name = entry.getKey();
          builder.addDefine(name, element.getAsJsonPrimitive());
        }
      }
    }
  }),

  DIAGNOSTIC_GROUPS("checks", new ConfigUpdater() {
    @Override
    public void apply(JsonObject obj, Config.Builder builder) {
      Map<DiagnosticGroup, CheckLevel> groups = Maps.newHashMap();
      for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
        DiagnosticGroup group = DiagnosticGroupUtil.forName(entry.getKey());
        if (group == null) {
          continue;
        }

        String checkLevelString = GsonUtil.stringOrNull(entry.getValue());
        if (checkLevelString == null) {
          continue;
        }
        CheckLevel checkLevel = CheckLevel.valueOf(checkLevelString.toUpperCase());

        groups.put(group, checkLevel);
      }
      builder.setDiagnosticGroups(groups);
    }
  }),

  NAME_SUFFIXES_TO_STRIP("name-suffixes-to-strip", new ConfigUpdater() {
    @Override
    public void apply(String suffix, Config.Builder builder) {
      JsonArray suffixes = new JsonArray();
      suffixes.add(new JsonPrimitive(suffix));
      apply(suffixes, builder);
    }

    @Override
    public void apply(JsonArray suffixes, Config.Builder builder) {
      ImmutableSet.Builder<String> suffixesBuilder = ImmutableSet.builder();
      for (JsonElement item : suffixes) {
        String suffix = GsonUtil.stringOrNull(item);
        if (suffix != null) {
          suffixesBuilder.add(suffix);
        }
      }

      builder.setStripNameSuffixes(suffixesBuilder.build());
    }
  }),

  TYPE_PREFIXES_TO_STRIP("type-prefixes-to-strip", new ConfigUpdater() {
    @Override
    public void apply(String type, Config.Builder builder) {
      JsonArray types = new JsonArray();
      types.add(new JsonPrimitive(type));
      apply(types, builder);
    }

    @Override
    public void apply(JsonArray types, Config.Builder builder) {
      ImmutableSet.Builder<String> typesBuilder = ImmutableSet.builder();
      for (JsonElement item : types) {
        String type = GsonUtil.stringOrNull(item);
        if (type != null) {
          typesBuilder.add(type);
        }
      }

      builder.setStripTypePrefixes(typesBuilder.build());
    }
  }),

  ID_GENERATORS("id-generators", new ConfigUpdater() {
    @Override
    public void apply(String idGenerator, Config.Builder builder) {
      JsonArray idGenerators = new JsonArray();
      idGenerators.add(new JsonPrimitive(idGenerator));
      apply(idGenerators, builder);
    }

    @Override
    public void apply(JsonArray idGenerators, Config.Builder builder) {
      ImmutableSet.Builder<String> idGeneratorsBuilder = ImmutableSet.builder();
      for (JsonElement item : idGenerators) {
        String idGenerator = GsonUtil.stringOrNull(item);
        if (idGenerator != null) {
          idGeneratorsBuilder.add(idGenerator);
        }
      }

      builder.setIdGenerators(idGeneratorsBuilder.build());
    }
  }),

  AMBIGUATE_PROPERTIES("ambiguate-properties", new ConfigUpdater() {
    @Override
    public void apply(boolean ambiguateProperties, Config.Builder builder) {
      builder.setAmbiguateProperties(ambiguateProperties);
    }
  }),

  DISAMBIGUATE_PROPERTIES("disambiguate-properties", new ConfigUpdater() {
    @Override
    public void apply(boolean disambiguateProperties, Config.Builder builder) {
      builder.setDisambiguateProperties(disambiguateProperties);
    }
  }),
  ;

  private static class ConfigUpdater {

    public void apply(String json, Config.Builder builder) {
      throw new UnsupportedOperationException();
    }

    public void apply(boolean value, Config.Builder builder) {
      throw new UnsupportedOperationException();
    }

    public void apply(Number value, Config.Builder builder) {
      throw new UnsupportedOperationException();
    }

    public void apply(JsonArray value, Config.Builder builder) {
      throw new UnsupportedOperationException();
    }

    public void apply(JsonObject value, Config.Builder builder) {
      throw new UnsupportedOperationException();
    }

    private void apply(JsonElement json, Config.Builder builder) {
      if (json.isJsonPrimitive()) {
        JsonPrimitive primitive = json.getAsJsonPrimitive();
        if (primitive.isString()) {
          apply(primitive.getAsString(), builder);
        } else if (primitive.isBoolean()) {
          apply(primitive.getAsBoolean(), builder);
        } else if (primitive.isNumber()) {
          apply(primitive.getAsNumber(), builder);
        }
      } else if (json.isJsonArray()) {
        apply(json.getAsJsonArray(), builder);
      } else if (json.isJsonObject()) {
        apply(json.getAsJsonObject(), builder);
      }
    }

    /**
     * Only override this method if this option can be overridden using query
     * data.
     * @param queryDataValue
     * @param builder
     */
    public boolean update(String queryDataValue, Config.Builder builder) {
      // By default, does nothing. Only override if it is safe to update the
      // Config using a query data parameter, which anyone could pass in.
      return false;
    }
  }

  private final String name;

  private final ConfigUpdater configUpdater;

  ConfigOption(String name, ConfigUpdater configUpdater) {
    this.name = name;
    this.configUpdater = configUpdater;
  }

  public String getName() {
    return name;
  }

  public void update(Config.Builder builder, JsonElement json) {
    if (json == null) {
      return;
    }
    configUpdater.apply(json, builder);
  }

  /**
   * @return true to indicate that the parameter was processed
   */
  public boolean update(Config.Builder builder, QueryData data) {
    String value = data.getParam(name);
    if (value == null) {
      return false;
    }
    return configUpdater.update(value, builder);
  }

  /**
   * Config files often contain relative paths, so it is important to resolve
   * them against the directory that contains the config file when that is the
   * case.
   *
   * @param path
   * @param builder
   * @return
   */
  static String maybeResolvePath(String path, Config.Builder builder) {
    return maybeResolvePath(path, builder.getRelativePathBase());
  }

  static String maybeResolvePath(String path, File relativePathBase) {
    // Unfortunately, a File object must be constructed in order to determine
    // whether the path is absolute.
    File file = new File(path);
    if (file.isAbsolute()) {
      return path;
    } else {
      return (new File(relativePathBase, path)).getAbsolutePath();
    }
  }

  static void assertContainsModuleNamePlaceholder(String path) {
    if (path == null || !path.contains("%s")) {
      throw new IllegalArgumentException("Does not contain %s: " + path);
    }
  }
}
