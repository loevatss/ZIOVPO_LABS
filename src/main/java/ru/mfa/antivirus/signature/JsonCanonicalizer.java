package ru.mfa.antivirus.signature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

@Component
public class JsonCanonicalizer {
    private final ObjectMapper objectMapper;

    public JsonCanonicalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    // Преобразует объект в канонический JSON (детерминированный порядок, без пробелов) и UTF-8 байты.
    public byte[] canonicalizeToUtf8(Object payload) {
        JsonNode node = objectMapper.valueToTree(payload);
        String canonicalJson = canonicalizeNode(node);
        return canonicalJson.getBytes(StandardCharsets.UTF_8);
    }

    // Канонизирует узел JSON рекурсивно по правилам детерминированного вывода.
    private String canonicalizeNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return "null";
        }

        if (node.isObject()) {
            return canonicalizeObject(node);
        }

        if (node.isArray()) {
            return canonicalizeArray(node);
        }

        if (node.isTextual()) {
            return quote(node.textValue());
        }

        if (node.isNumber()) {
            return canonicalizeNumber(node);
        }

        if (node.isBoolean()) {
            return node.booleanValue() ? "true" : "false";
        }

        throw new IllegalArgumentException("Unsupported JSON node type for canonicalization: " + node.getNodeType());
    }

    // Канонизирует JSON-объект: сортирует ключи и сериализует пары ключ-значение.
    private String canonicalizeObject(JsonNode objectNode) {
        List<String> names = new ArrayList<>();
        Iterator<String> fieldNames = objectNode.fieldNames();
        while (fieldNames.hasNext()) {
            names.add(fieldNames.next());
        }

        names.sort(Comparator.naturalOrder());

        StringBuilder builder = new StringBuilder();
        builder.append('{');

        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            builder.append(quote(name));
            builder.append(':');
            builder.append(canonicalizeNode(objectNode.get(name)));

            if (i < names.size() - 1) {
                builder.append(',');
            }
        }

        builder.append('}');
        return builder.toString();
    }

    // Канонизирует JSON-массив, сохраняя порядок элементов.
    private String canonicalizeArray(JsonNode arrayNode) {
        StringBuilder builder = new StringBuilder();
        builder.append('[');

        for (int i = 0; i < arrayNode.size(); i++) {
            builder.append(canonicalizeNode(arrayNode.get(i)));
            if (i < arrayNode.size() - 1) {
                builder.append(',');
            }
        }

        builder.append(']');
        return builder.toString();
    }

    // Канонизирует числа в устойчивом формате через JsonParser, совместимый с JSON-представлением.
    private String canonicalizeNumber(JsonNode numberNode) {
        return numberNode.asText();
    }

    // Экранирует строку корректным JSON-образом.
    private String quote(String value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to escape JSON string", ex);
        }
    }
}
