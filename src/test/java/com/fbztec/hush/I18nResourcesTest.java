package com.fbztec.hush;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

// the frontend has no JS test runner: this keeps the translation files and their callers in sync
class I18nResourcesTest {

    private static final Path STATIC = Path.of("src/main/resources/static");

    private static Map<String, String> messages(String lang) throws IOException {
        JsonNode root = JsonMapper.shared().readTree(Files.readString(STATIC.resolve("i18n/" + lang + ".json")));
        Map<String, String> flat = new TreeMap<>();
        flatten("", root, flat);
        return flat;
    }

    private static void flatten(String prefix, JsonNode node, Map<String, String> out) {
        if (node.isObject()) {
            node.properties().forEach(e -> flatten(prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey(), e.getValue(), out));
        } else {
            out.put(prefix, node.asString());
        }
    }

    private static Set<String> matches(String text, String regex) {
        Set<String> found = new TreeSet<>();
        Matcher m = Pattern.compile(regex).matcher(text);
        while (m.find()) found.add(m.group(1));
        return found;
    }

    @Test
    void localesHaveSameKeysAndNoEmptyValue() throws IOException {
        Map<String, String> en = messages("en");
        Map<String, String> fr = messages("fr");

        assertThat(fr.keySet()).isEqualTo(en.keySet());
        assertThat(en.values()).allMatch(v -> !v.isBlank());
        assertThat(fr.values()).allMatch(v -> !v.isBlank());
    }

    @Test
    void htmlKeysExist() throws IOException {
        String html = Files.readString(STATIC.resolve("index.html"));
        Set<String> keys = matches(html, "data-i18n(?:-html)?=\"([\\w.]+)\"");
        matches(html, "data-i18n-attr=\"([^\"]+)\"")
                .forEach(attr -> keys.addAll(matches(attr, "[\\w-]+:([\\w.]+)")));

        assertThat(keys).isNotEmpty().allMatch(messages("en")::containsKey);
    }

    @Test
    void jsKeysExist() throws IOException {
        String js = Files.readString(STATIC.resolve("app.js"));
        // any quoted dotted literal: also catches keys passed indirectly ({key: 'errors.network'}, FIELD_ERROR_KEYS...)
        Set<String> keys = matches(js, "'([a-z]+(?:\\.\\w+)+)'");
        Map<String, String> en = messages("en");

        assertThat(keys).isNotEmpty().allMatch(k -> en.containsKey(k) || en.containsKey(k + ".other"));
    }
}
