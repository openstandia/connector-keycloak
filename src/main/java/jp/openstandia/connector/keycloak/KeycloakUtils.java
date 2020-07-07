/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides utility methods.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakUtils {

    public static ZonedDateTime toZoneDateTime(Instant instant) {
        ZoneId zone = ZoneId.systemDefault();
        return ZonedDateTime.ofInstant(instant, zone);
    }

    public static ZonedDateTime toZoneDateTime(long epoch) {
        Instant instant = Instant.ofEpochMilli(epoch);
        return toZoneDateTime(instant);
    }

    public static ZonedDateTime toZoneDateTime(String yyyymmdd) {
        LocalDate date = LocalDate.parse(yyyymmdd);
        return date.atStartOfDay(ZoneId.systemDefault());
    }

    /**
     * Transform a Keycloak attribute object to a Connector attribute object.
     *
     * @param attributeInfo
     * @param entry
     * @return
     */
    public static Attribute toConnectorAttribute(AttributeInfo attributeInfo, Map.Entry<String, List<String>> entry) {
        if (attributeInfo.isMultiValued()) {
            List<String> value = entry.getValue();
            if (value != null && value.size() > 0) {
                return toConnectorAttribute(attributeInfo, entry.getKey(), value);
            }

        } else {
            List<String> value = entry.getValue();
            if (value != null && value.size() > 0) {
                return toConnectorAttribute(attributeInfo, entry.getKey(), value.get(0));
            }
        }
        return AttributeBuilder.build(entry.getKey());
    }

    public static Attribute toConnectorAttribute(AttributeInfo attributeInfo, String attrName, List<String> attrValues) {
        List<Object> values = attrValues.stream()
                .map(a -> toConnectorAttributeValue(attributeInfo, a))
                .collect(Collectors.toList());

        return AttributeBuilder.build(attrName, values);
    }

    private static Object toConnectorAttributeValue(AttributeInfo attributeInfo, String attrValue) {
        // Keycloak API returns the attribute as string even if it's other types.
        // We need to check the type from the schema and convert it.
        if (attributeInfo.getType() == Integer.class) {
            return Integer.parseInt(attrValue);
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // The format is YYYY-MM-DD
            return toZoneDateTime(attrValue);
        }
        if (attributeInfo.getType() == Boolean.class) {
            return Boolean.parseBoolean(attrValue);
        }

        return attrValue;
    }

    public static Attribute toConnectorAttribute(AttributeInfo attributeInfo, String attrName, String attrValue) {
        Object value = toConnectorAttributeValue(attributeInfo, attrValue);

        return AttributeBuilder.build(attrName, value);
    }

    public static String toKeycloakValue(Map<String, AttributeInfo> schema, AttributeDelta delta) {
        AttributeInfo attributeInfo = schema.get(delta.getName());

        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + delta.getName());
        }

        String value;

        if (attributeInfo.getType() == Integer.class) {
            value = AttributeDeltaUtil.getAsStringValue(delta);
        } else if (attributeInfo.getType() == ZonedDateTime.class) {
            // TODO need to configure the format in the schema definition?
            ZonedDateTime date = (ZonedDateTime) AttributeDeltaUtil.getSingleValue(delta);
            value = date.format(DateTimeFormatter.ISO_INSTANT);
        } else if (attributeInfo.getType() == Boolean.class) {
            value = AttributeDeltaUtil.getAsStringValue(delta);
        } else {
            value = AttributeDeltaUtil.getAsStringValue(delta);
        }

        // Null means delete the value. But need to set empty string for deleting the value in keycloak side.
        if (value == null) {
            return "";
        }

        return value;
    }

    public static String toKeycloakValue(Map<String, AttributeInfo> schema, Attribute attr) {
        AttributeInfo attributeInfo = schema.get(attr.getName());
        if (attributeInfo == null) {
            throw new InvalidAttributeValueException("Invalid attribute. name: " + attr.getName());
        }

        if (attributeInfo.getType() == Integer.class) {
            return AttributeUtil.getAsStringValue(attr);
        }
        if (attributeInfo.getType() == ZonedDateTime.class) {
            // TODO need to configure the format in the schema definition?
            ZonedDateTime date = (ZonedDateTime) AttributeUtil.getSingleValue(attr);
            return date.format(DateTimeFormatter.ISO_LOCAL_DATE);
        }
        if (attributeInfo.getType() == Boolean.class) {
            return AttributeUtil.getAsStringValue(attr);
        }

        return AttributeUtil.getAsStringValue(attr);
    }

    public static boolean shouldReturn(Set<String> attrsToGetSet, String attr) {
        if (attrsToGetSet == null) {
            return true;
        }
        return attrsToGetSet.contains(attr);
    }

    /**
     * Check if ALLOW_PARTIAL_ATTRIBUTE_VALUES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldAllowPartialAttributeValues(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getAllowPartialAttributeValues());
    }

    /**
     * Check if RETURN_DEFAULT_ATTRIBUTES == true.
     *
     * @param options
     * @return
     */
    public static boolean shouldReturnDefaultAttributes(OperationOptions options) {
        // If the option isn't set from IDM, it may be null.
        return Boolean.TRUE.equals(options.getReturnDefaultAttributes());
    }

    public static void invalidSchema(String name) throws InvalidAttributeValueException {
        InvalidAttributeValueException exception = new InvalidAttributeValueException(
                String.format("Keycloak doesn't support to set '%s' attribute", name));
        exception.setAffectedAttributeNames(Arrays.asList(name));
        throw exception;
    }

    /**
     * Create full set of ATTRIBUTES_TO_GET which is composed by RETURN_DEFAULT_ATTRIBUTES + ATTRIBUTES_TO_GET.
     *
     * @param schema
     * @param options
     * @return
     */
    public static Set<String> createFullAttributesToGet(Map<String, AttributeInfo> schema, OperationOptions options) {
        Set<String> attributesToGet = null;
        if (shouldReturnDefaultAttributes(options)) {
            attributesToGet = new HashSet<>();
            attributesToGet.addAll(toReturnedByDefaultAttributesSet(schema));
        }
        if (options.getAttributesToGet() != null) {
            if (attributesToGet == null) {
                attributesToGet = new HashSet<>();
            }
            for (String a : options.getAttributesToGet()) {
                attributesToGet.add(a);
            }
        }
        return attributesToGet;
    }

    private static Set<String> toReturnedByDefaultAttributesSet(Map<String, AttributeInfo> schema) {
        return schema.entrySet().stream()
                .filter(entry -> entry.getValue().isReturnedByDefault())
                .map(entry -> entry.getKey())
                .collect(Collectors.toSet());
    }

    public static Throwable getRootCause(final Throwable t) {
        final List<Throwable> list = getThrowableList(t);
        return list.size() < 2 ? null : list.get(list.size() - 1);
    }

    private static List<Throwable> getThrowableList(Throwable t) {
        final List<Throwable> list = new ArrayList<>();
        while (t != null && !list.contains(t)) {
            list.add(t);
            t = t.getCause();
        }
        return list;
    }
}
