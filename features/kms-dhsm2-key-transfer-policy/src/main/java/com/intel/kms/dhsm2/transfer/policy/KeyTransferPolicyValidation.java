/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.kms.dhsm2.transfer.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.IntNode;
import java.util.ArrayList;

/*
 * Brief: This class contiains some common code for validation of policy.
 * @shefalik
 */

class KeyTransferPolicyValidation {
	final private static org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyTransferPolicyValidation.class);

	public static ArrayList<String> getStringList(JsonNode attrNode) {
		ArrayList<String> l1 = new ArrayList<String>();
		for (final JsonNode node : attrNode) {
			String val = node.textValue();
			l1.add(val);
		}
		return l1;
	}

	public static ArrayList<Integer> getIntegerList(JsonNode attrNode) {
		ArrayList<Integer> l1 = new ArrayList<>();
		for (final JsonNode node : attrNode) {
			int val = node.intValue();
			l1.add(val);
		}
		return l1;
	}

	public static ArrayList<Short> getShortIntList(JsonNode attrNode) {
		ArrayList<Short> l1 = new ArrayList<>();
		for (final JsonNode node : attrNode) {
			short val = node.shortValue();
			l1.add(val);
		}
		return l1;
	}

	public static boolean isAlphaNumString(String str)
	{
		return ((!str.equals("")) && (str != null)
				&& (str.matches("^[a-zA-Z0-9. ]*$")));
	}

	public static boolean isValidArrayOfCanonicalName(JsonNode attrNode)
	{
		boolean value = false;
		if (!attrNode.isMissingNode()) {
			if ((attrNode.getNodeType() != JsonNodeType.ARRAY) || attrNode.size() == 0) {
				return value;
			} else {
				ArrayList<String> s1 = new ArrayList<>();
				for (final JsonNode node : attrNode) {
					if (node.isTextual()) {
						String val = node.textValue();
						if ((val == null) || (val.equals("")) || (!val.matches("^([a-zA-Z0-9 ]*.)$"))) {
							return value;
						}
					} else {
						return value;
					}
				}
			}
		}
		value = true;
		return value;
	}

	public static boolean isValidArrayOfHexStrings(JsonNode attrNode)
	{
		boolean value = false;
		if (!attrNode.isMissingNode()) {
			if ((attrNode.getNodeType() != JsonNodeType.ARRAY) || attrNode.size() == 0) {
				return value;
			} else {
				ArrayList<String> s1 = new ArrayList<>();
				for (final JsonNode node : attrNode) {
					if (node.isTextual()) {
						String val = node.textValue();
						if ((val == null) || (val.equals("")) || (!val.matches("^([0-9A-Fa-f]+$)"))) {
							return value;
						}
					} else {
						return value;
					}
				}
			}
		}
		value = true;
		return value;
	}

	public static boolean isValidAlphaNumStringArray(JsonNode attrNode) {
		boolean value = false;
		if (!attrNode.isMissingNode()) {
			if ((attrNode.getNodeType() != JsonNodeType.ARRAY) || attrNode.size() == 0) {
				return value;
			} else {
				ArrayList<String> s1 = new ArrayList<>();
				for (final JsonNode node : attrNode) {
					if (node.isTextual()) {
						String val = node.textValue();
						if (!isAlphaNumString(val)) {
							return value;
						}
					} else {
						return value;
					}
				}
			}
		}
		value = true;
		return value;
	}

	public static boolean isValidIntegerArray(JsonNode attrNode) {
		boolean value = false;
		if (!attrNode.isMissingNode()) {
			if ((attrNode.getNodeType() != JsonNodeType.ARRAY) || attrNode.size() == 0) {
				return value;
			}
			else {
				for (final JsonNode node : attrNode) {
					if (!(node instanceof IntNode)) {
						return value;
					}
				}
			}
		}
		value = true;
		return value;
	}

	public static boolean isValidShortArray(JsonNode attrNode) {
		boolean value = false;
		if (!attrNode.isMissingNode()) {
			if ((attrNode.getNodeType() != JsonNodeType.ARRAY) || attrNode.size() == 0) {
				return value;
			} else {
				for (final JsonNode node : attrNode) {
					if (node.isNumber()) {
						try {
							Short.valueOf(node.asText());
							continue;
						} catch (NumberFormatException e) {
							return value;
						}
					}
				}
			}
		}
		value = true;
		return value;
	}
}
