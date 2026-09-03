import crypto from "node:crypto";
import readline from "node:readline";

const MAX_SAFE = 9007199254740991;

function utf16Compare(left, right) {
  const a = Buffer.from(left, "utf16le");
  const b = Buffer.from(right, "utf16le");
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 2) {
    const av = a[index] + 256 * a[index + 1];
    const bv = b[index] + 256 * b[index + 1];
    if (av !== bv) return av - bv;
  }
  return a.length - b.length;
}

function quote(value) {
  let result = '"';
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code >= 0xd800 && code <= 0xdfff) throw new Error("surrogate");
    if (character === '"') result += '\\"';
    else if (character === "\\") result += "\\\\";
    else if (character === "\b") result += "\\b";
    else if (character === "\t") result += "\\t";
    else if (character === "\n") result += "\\n";
    else if (character === "\f") result += "\\f";
    else if (character === "\r") result += "\\r";
    else if (code <= 0x1f) result += `\\u${code.toString(16).padStart(4, "0")}`;
    else result += character;
  }
  return `${result}"`;
}

function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error("integer");
    return String(value);
  }
  if (typeof value === "string") return quote(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort(utf16Compare).map((key) => `${quote(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("type");
}

function semanticDigest(request) {
  const envelope = {
    algorithm: "sha-256",
    body: request.body,
    canonicalizer: request.canonicalizer ?? "urn:gew:canonicalizer:jcs-input:1.0.0",
    contract_type: request.contract_type,
    digest_domain: request.digest_domain ?? "urn:gew:digest:semantic:1.0.0",
    projection_id: request.projection_id,
    schema_id: request.schema_id,
  };
  return `sha256-jcs-v1:${crypto.createHash("sha256").update(Buffer.from(canonical(envelope), "utf8")).digest("hex")}`;
}

function digestContract(request) {
  if (request.action === "identity") {
    const envelope = {
      algorithm: "sha-256",
      body: request.body,
      canonicalizer: request.canonicalizer ?? "urn:gew:canonicalizer:jcs-input:1.0.0",
      contract_type: request.contract_type,
      digest_domain: request.digest_domain ?? "urn:gew:digest:semantic:1.0.0",
      projection_id: request.projection_id,
      schema_id: request.schema_id,
    };
    const preimage = canonical(envelope);
    return {
      status: "ok",
      projected_body: request.body,
      preimage,
      digest: `sha256-jcs-v1:${crypto.createHash("sha256").update(Buffer.from(preimage, "utf8")).digest("hex")}`,
    };
  }
  const projection = request.projection;
  const digestFor = (body) => contractDigest(body, projection.contract_type, projection.projection_id, projection.schema_id);
  if (request.action === "create-self") {
    const candidate = JSON.parse(JSON.stringify(request.candidate));
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || Object.keys(candidate).sort().join(",") !== "schema_version,value" || candidate.schema_version !== "1.0.0") return { status: "error", code: "INPUT" };
    const digest = digestFor(candidate);
    const complete = { ...candidate, [projection.derived_field]: digest };
    return {
      status: "ok", complete, projected_body: candidate,
      preimage: canonical({
        algorithm: "sha-256", body: candidate,
        canonicalizer: "urn:gew:canonicalizer:jcs-input:1.0.0",
        contract_type: projection.contract_type,
        digest_domain: "urn:gew:digest:semantic:1.0.0",
        projection_id: projection.projection_id,
        schema_id: projection.schema_id,
      }),
      digest,
    };
  }
  if (request.action === "verify-self") {
    const record = JSON.parse(JSON.stringify(request.record));
    if (!record || typeof record !== "object" || Array.isArray(record) || Object.keys(record).sort().join(",") !== "digest,schema_version,value" || record.schema_version !== "1.0.0") return { status: "error", code: "SOURCE" };
    const expected = record[projection.derived_field];
    if (typeof expected !== "string" || !/^sha256-jcs-v1:[0-9a-f]{64}$/.test(expected)) return { status: "error", code: "DIGEST_FIELD" };
    const projected = { ...record }; delete projected[projection.derived_field];
    if (digestFor(projected) !== expected) return { status: "error", code: "MISMATCH" };
    return { status: "ok", complete: record, projected_body: projected, digest: expected };
  }
  throw new Error("digest-action");
}

function contractDigest(body, contractType, projectionId, schemaId) {
  return semanticDigest({ body, contract_type: contractType, projection_id: projectionId, schema_id: schemaId });
}

function jsonType(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number" && Number.isSafeInteger(value)) return "integer";
  if (typeof value === "string") return "string";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "object";
  return "invalid";
}

function equal(left, right) {
  if (jsonType(left) !== jsonType(right)) return false;
  if (Array.isArray(left)) return left.length === right.length && left.every((value, index) => equal(value, right[index]));
  if (left && typeof left === "object") {
    const keys = Object.keys(left);
    return keys.length === Object.keys(right).length && keys.every((key) => Object.hasOwn(right, key) && equal(left[key], right[key]));
  }
  return left === right;
}

function resolvePath(root, tokens) {
  let current = root;
  for (const token of tokens) {
    if (typeof token === "string" && current && !Array.isArray(current) && typeof current === "object" && Object.hasOwn(current, token)) current = current[token];
    else if (Number.isSafeInteger(token) && token >= 0 && Array.isArray(current) && token < current.length) current = current[token];
    else if ((typeof token === "string" && current && !Array.isArray(current) && typeof current === "object") || (Number.isSafeInteger(token) && Array.isArray(current))) throw new Error("path");
    else throw new Error("path-type");
  }
  return current;
}

function geel(node, roots) {
  const op = node.op;
  if (op === "literal") return node.value;
  if (op === "path") return resolvePath(roots[node.root], node.tokens);
  if (op === "exists") {
    try { resolvePath(roots[node.root], node.tokens); return true; } catch { return false; }
  }
  const child = (value) => geel(value, roots);
  if (op === "all") return node.args.map(child).every((value) => value === true);
  if (op === "any") return node.args.map(child).some((value) => value === true);
  if (op === "not") return !child(node.arg);
  if (["eq", "ne", "lt", "lte", "gt", "gte"].includes(op)) {
    const left = child(node.left); const right = child(node.right);
    if (jsonType(left) !== jsonType(right)) throw new Error("type");
    if (op === "eq") return equal(left, right);
    if (op === "ne") return !equal(left, right);
    if (op === "lt") return left < right;
    if (op === "lte") return left <= right;
    if (op === "gt") return left > right;
    return left >= right;
  }
  if (op === "contains") return child(node.container).some((value) => equal(value, child(node.value)));
  if (op === "in") return child(node.container).some((value) => equal(value, child(node.value)));
  if (op === "length") return Array.from(child(node.value)).length;
  if (op === "is_type") return jsonType(child(node.value)) === node.expected;
  if (op === "predicate") {
    const values = node.args.map(child);
    if (node.predicate_id !== "urn:gew:predicate:string-starts-with" || node.version !== "1.0.0") throw new Error("operator");
    if (values.length !== 2 || values.some((value) => typeof value !== "string")) throw new Error("type");
    return values[0].startsWith(values[1]);
  }
  throw new Error("operator");
}

function schemaValidate(schema, instance) {
  if (schema === true) return [];
  if (schema === false) return ["schema/false-schema"];
  const failures = [];
  const type = schema.type;
  const allowedTypes = Array.isArray(type) ? type : [type];
  if (type && !allowedTypes.includes(jsonType(instance))) return ["schema/type"];
  if (schema.const !== undefined && !equal(instance, schema.const)) failures.push("schema/const");
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => equal(instance, candidate))) failures.push("schema/enum");
  if (jsonType(instance) === "integer") {
    if (schema.minimum !== undefined && instance < schema.minimum) failures.push("schema/minimum");
    if (schema.maximum !== undefined && instance > schema.maximum) failures.push("schema/maximum");
    if (schema.exclusiveMinimum !== undefined && instance <= schema.exclusiveMinimum) failures.push("schema/exclusiveMinimum");
    if (schema.exclusiveMaximum !== undefined && instance >= schema.exclusiveMaximum) failures.push("schema/exclusiveMaximum");
  }
  if (jsonType(instance) === "string") {
    if (schema.minLength !== undefined && Array.from(instance).length < schema.minLength) failures.push("schema/minLength");
    if (schema.maxLength !== undefined && Array.from(instance).length > schema.maxLength) failures.push("schema/maxLength");
    if (schema.format !== undefined && !validFormat(schema.format, instance)) failures.push(`schema/format/${schema.format}`);
  }
  if (jsonType(instance) === "object") {
    for (const key of schema.required ?? []) if (!Object.hasOwn(instance, key)) failures.push("schema/required");
    for (const [key, child] of Object.entries(schema.properties ?? {})) if (Object.hasOwn(instance, key)) failures.push(...schemaValidate(child, instance[key]));
    const evaluated = new Set(Object.keys(instance).filter((key) => Object.hasOwn(schema.properties ?? {}, key)));
    for (const [key, dependencies] of Object.entries(schema.dependentRequired ?? {})) {
      if (Object.hasOwn(instance, key) && dependencies.some((member) => !Object.hasOwn(instance, member))) failures.push("schema/dependentRequired");
    }
    for (const [key, child] of Object.entries(schema.dependentSchemas ?? {})) {
      if (Object.hasOwn(instance, key)) {
        const result = schemaValidate(child, instance); failures.push(...result);
        if (result.length === 0) for (const member of Object.keys(child.properties ?? {})) if (Object.hasOwn(instance, member)) evaluated.add(member);
      }
    }
    if (schema.additionalProperties !== undefined) {
      for (const key of Object.keys(instance)) if (!Object.hasOwn(schema.properties ?? {}, key)) {
        failures.push(...schemaValidate(schema.additionalProperties, instance[key])); evaluated.add(key);
      }
    }
    for (const child of [...(schema.allOf ?? []), ...(schema.anyOf ?? []), ...(schema.oneOf ?? [])]) {
      if (schemaValidate(child, instance).length === 0) for (const member of Object.keys(child.properties ?? {})) if (Object.hasOwn(instance, member)) evaluated.add(member);
    }
    if (schema.unevaluatedProperties !== undefined) for (const key of Object.keys(instance)) if (!evaluated.has(key)) {
      if (schema.unevaluatedProperties === false) failures.push("schema/unevaluatedProperties");
      else failures.push(...schemaValidate(schema.unevaluatedProperties, instance[key]));
    }
    if (schema.minProperties !== undefined && Object.keys(instance).length < schema.minProperties) failures.push("schema/minProperties");
    if (schema.maxProperties !== undefined && Object.keys(instance).length > schema.maxProperties) failures.push("schema/maxProperties");
  }
  if (jsonType(instance) === "array") {
    const evaluated = new Set();
    if (schema.maxItems !== undefined && instance.length > schema.maxItems) failures.push("schema/maxItems");
    if (schema.minItems !== undefined && instance.length < schema.minItems) failures.push("schema/minItems");
    for (const [index, child] of (schema.prefixItems ?? []).entries()) if (index < instance.length) { failures.push(...schemaValidate(child, instance[index])); evaluated.add(index); }
    if (schema.items !== undefined) for (let index = (schema.prefixItems ?? []).length; index < instance.length; index += 1) { failures.push(...schemaValidate(schema.items, instance[index])); evaluated.add(index); }
    if (schema.uniqueItems === true) for (let left = 0; left < instance.length; left += 1) for (let right = left + 1; right < instance.length; right += 1) if (equal(instance[left], instance[right])) failures.push("schema/uniqueItems");
    if (schema.contains !== undefined) {
      let matches = 0; for (let index = 0; index < instance.length; index += 1) if (schemaValidate(schema.contains, instance[index]).length === 0) { matches += 1; evaluated.add(index); }
      if (matches < (schema.minContains ?? 1) || (schema.maxContains !== undefined && matches > schema.maxContains)) failures.push("schema/contains");
    }
    if (schema.unevaluatedItems !== undefined) for (let index = 0; index < instance.length; index += 1) if (!evaluated.has(index)) {
      if (schema.unevaluatedItems === false) failures.push("schema/unevaluatedItems"); else failures.push(...schemaValidate(schema.unevaluatedItems, instance[index]));
    }
  }
  for (const keyword of ["allOf", "anyOf", "oneOf"]) if (Array.isArray(schema[keyword])) {
    const matches = schema[keyword].filter((child) => schemaValidate(child, instance).length === 0).length;
    if ((keyword === "allOf" && matches !== schema[keyword].length) || (keyword === "anyOf" && matches === 0) || (keyword === "oneOf" && matches !== 1)) failures.push(`schema/${keyword}`);
  }
  if (schema.not !== undefined && schemaValidate(schema.not, instance).length === 0) failures.push("schema/not");
  if (schema.if !== undefined) {
    const branch = schemaValidate(schema.if, instance).length === 0 ? schema.then : schema.else;
    if (branch !== undefined) failures.push(...schemaValidate(branch, instance));
  }
  return failures.sort();
}

function schemaProfile(schema) {
  const allowed = new Set([
    "$schema", "$id", "$defs", "$ref", "$comment", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
    "dependentSchemas", "prefixItems", "items", "contains", "properties", "additionalProperties", "type", "enum", "const",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems",
    "uniqueItems", "minContains", "maxContains", "minProperties", "maxProperties", "required", "dependentRequired",
    "unevaluatedProperties", "unevaluatedItems", "title", "description", "deprecated", "readOnly", "writeOnly", "format",
  ]);
  if (!schema || schema.$schema !== "https://json-schema.org/draft/2020-12/schema" || !/^urn:gew:schema:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:1\.0\.0$/.test(schema.$id ?? "")) return false;
  if (schema.type !== "object" || schema.unevaluatedProperties !== false || schema.properties?.schema_version?.const !== "1.0.0" || !(schema.required ?? []).includes("schema_version")) return false;
  const walk = (current, root = false) => {
    if (typeof current === "boolean") return true;
    if (!current || typeof current !== "object" || Array.isArray(current)) return false;
    if (Object.keys(current).some((key) => !allowed.has(key))) return false;
    if (!root && Object.hasOwn(current, "$id")) return false;
    const types = Array.isArray(current.type) ? current.type : current.type === undefined ? [] : [current.type];
    if (types.some((type) => !["null", "boolean", "integer", "string", "array", "object"].includes(type))) return false;
    if (current.format !== undefined && !["gew-bigint", "gew-decimal", "gew-duration", "gew-id", "gew-opaque-ref", "gew-timestamp"].includes(current.format)) return false;
    if (types.includes("array") && (current.maxItems === undefined || (current.items === undefined && current.prefixItems === undefined))) return false;
    for (const keyword of ["$defs", "properties", "dependentSchemas"]) for (const child of Object.values(current[keyword] ?? {})) if (!walk(child)) return false;
    for (const keyword of ["additionalProperties", "unevaluatedProperties", "unevaluatedItems", "items", "contains", "not", "if", "then", "else"]) if (Object.hasOwn(current, keyword) && !walk(current[keyword])) return false;
    for (const keyword of ["allOf", "anyOf", "oneOf", "prefixItems"]) for (const child of current[keyword] ?? []) if (!walk(child)) return false;
    return true;
  };
  return walk(schema, true);
}

function strictJson(raw) {
  if (raw.startsWith("\ufeff")) return { status: "error", code: "BOM" };
  if (/\\u[dD][89aAbB][0-9a-fA-F]{2}(?!\\u[dD][c-fC-F][0-9a-fA-F]{2})/.test(raw)) return { status: "error", code: "SURROGATE" };
  const memberNames = [...raw.matchAll(/("(?:\\.|[^"\\])*")\s*:/g)].map((match) => JSON.parse(match[1]));
  if (memberNames.length !== new Set(memberNames).size) return { status: "error", code: "DUPLICATE" };
  const withoutStrings = raw.replace(/"(?:\\.|[^"\\])*"/g, '""');
  for (const match of withoutStrings.matchAll(/(?:^|[\[,:])\s*(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/g)) {
    const token = match[1];
    if (!/^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/.test(token) || token === "-0") return { status: "error", code: "NUMBER" };
    if (!Number.isSafeInteger(Number(token))) return { status: "error", code: "NUMBER" };
  }
  try { return { status: "ok", canonical: canonical(JSON.parse(raw)) }; }
  catch { return { status: "error", code: "SYNTAX" }; }
}

function validFormat(formatId, value) {
  if (formatId === "gew-bigint") return /^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/.test(value) && value !== "-0";
  if (formatId === "gew-decimal") return /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/.test(value) && !/^-0(?:\.0*)?$/.test(value);
  if (formatId === "gew-duration") return /^PT(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?S$/.test(value);
  if (formatId === "gew-id") return value.length <= 255 && /^[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*$/.test(value);
  if (formatId === "gew-timestamp") {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.([0-9]{0,8}[1-9]))?Z$/.exec(value);
    if (!match || Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59) return false;
    const date = new Date(`${match[1]}-${match[2]}-${match[3]}T00:00:00Z`);
    return date.getUTCFullYear() === Number(match[1]) && date.getUTCMonth() + 1 === Number(match[2]) && date.getUTCDate() === Number(match[3]);
  }
  if (formatId === "gew-opaque-ref") {
    if (value.length < 2 || value.length > 4096 || value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
    try {
      const decoded = Buffer.from(value, "base64url");
      const text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
      return decoded.length >= 1 && decoded.length <= 3072 && Buffer.from(text, "utf8").toString("base64url") === value;
    } catch { return false; }
  }
  return false;
}

function registryReference(reference) {
  if (reference.startsWith("#")) return reference === "#" || reference.startsWith("#/");
  return /^urn:gew:schema:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:#(?:\/.*)?)?$/.test(reference);
}

function registryContract(request) {
  const manifest = request.manifest;
  if (!manifest || Object.keys(manifest).sort().join(",") !== "registry_digest,registry_id,resources,schema_version" || manifest.schema_version !== "1.0.0") return { status: "error", code: "MANIFEST" };
  const unsigned = { schema_version: manifest.schema_version, registry_id: manifest.registry_id, resources: manifest.resources };
  const digest = contractDigest(unsigned, "urn:gew:contract:schema-registry", "urn:gew:digest-projection:schema-registry:1.0.0", "urn:gew:schema:schema-registry:1.0.0");
  if (digest !== manifest.registry_digest) return { status: "error", code: "MANIFEST" };
  if ((request.limit_override?.registry_resources ?? Number.MAX_SAFE_INTEGER) < manifest.resources.length) return { status: "error", code: "LIMIT" };
  const ids = manifest.resources.map((record) => record.schema_id);
  if (ids.join("\n") !== [...ids].sort().join("\n") || new Set(ids).size !== ids.length) return { status: "error", code: "BODY" };
  if (new Set([...ids, ...Object.keys(request.bodies)]).size !== ids.length || Object.keys(request.bodies).length !== ids.length) return { status: "error", code: "BODY" };
  const documents = {};
  for (const record of manifest.resources) {
    const raw = request.bodies[record.schema_id];
    if (typeof raw !== "string" || `sha256-raw-v1:${crypto.createHash("sha256").update(Buffer.from(raw, "utf8")).digest("hex")}` !== record.body_digest) return { status: "error", code: "DIGEST" };
    try { documents[record.schema_id] = JSON.parse(raw); } catch { return { status: "error", code: "BODY" }; }
    if (documents[record.schema_id].$id !== record.schema_id) return { status: "error", code: "BODY" };
  }
  const pointerTokens = (pointer) => {
    if (pointer === "") return [];
    if (!pointer.startsWith("/")) throw new Error("REF");
    return pointer.slice(1).split("/").map((token) => {
      if (/~(?![01])/.test(token)) throw new Error("REF");
      return token.replaceAll("~1", "/").replaceAll("~0", "~");
    });
  };
  const resolve = (schemaId, pointer) => {
    let current = documents[schemaId];
    for (const token of pointerTokens(pointer)) {
      if (Array.isArray(current) && /^(0|[1-9][0-9]*)$/.test(token) && Number(token) < current.length) current = current[Number(token)];
      else if (current && typeof current === "object" && Object.hasOwn(current, token)) current = current[token];
      else throw new Error("REF");
    }
    return current;
  };
  const split = (currentId, reference) => {
    if (typeof reference !== "string") throw new Error("REF");
    if (reference.startsWith("#")) return [currentId, reference.slice(1)];
    const [schemaId, fragment = ""] = reference.split("#", 2);
    if (!/^urn:gew:schema:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(schemaId) || !Object.hasOwn(documents, schemaId)) throw new Error("REF");
    return [schemaId, fragment];
  };
  const references = (value) => {
    const found = [];
    const walk = (current) => {
      if (!current || typeof current !== "object") return;
      if (!Array.isArray(current) && Object.hasOwn(current, "$ref")) found.push(current.$ref);
      for (const child of Object.values(current)) if (child && typeof child === "object") walk(child);
    };
    walk(value); return found;
  };
  const complete = new Set();
  const visit = (schemaId, pointer, active) => {
    const key = `${schemaId}#${pointer}`;
    if (active.has(key)) throw new Error("CYCLE");
    if (complete.has(key)) return;
    const target = resolve(schemaId, pointer);
    const next = new Set(active); next.add(key);
    for (const reference of references(target)) {
      const [targetId, targetPointer] = split(schemaId, reference);
      visit(targetId, targetPointer, next);
    }
    complete.add(key);
  };
  try {
    for (const schemaId of ids) visit(schemaId, "", new Set());
  } catch (error) {
    return { status: "error", code: error.message === "CYCLE" ? "CYCLE" : "REF" };
  }
  return { status: "ok", resource_ids: ids };
}

function geelSummary(expression, roots) {
  try {
    if (!expression || typeof expression !== "object" || typeof expression.op !== "string") return { status: "error", code: "E_SCHEMA" };
    if (["all", "any"].includes(expression.op) && (!Array.isArray(expression.args) || expression.args.length === 0)) return { status: "error", code: "E_SCHEMA" };
    if (!["literal", "path", "all", "any", "not", "eq", "ne", "lt", "lte", "gt", "gte", "contains", "in", "length", "exists", "is_type", "predicate"].includes(expression.op)) return { status: "error", code: "E_OPERATOR" };
    if (expression.op === "contains" && !Array.isArray(geel(expression.container, roots))) return { status: "error", code: "E_TYPE" };
    return { status: "ok", value: geel(expression, roots) };
  } catch (error) {
    return { status: "error", code: error.message === "path" ? "E_PATH_MISSING" : error.message === "path-type" ? "E_PATH_TYPE" : error.message === "type" ? "E_TYPE" : error.message === "operator" ? "E_OPERATOR" : "E_SCHEMA" };
  }
}

function budgetSummary(request) {
  let balance = request.budget;
  const trace = [];
  for (const event of request.events) {
    const coefficient = request.coefficients[event.event_id];
    const amount = coefficient * event.count * (event.multiplier ?? 1);
    const attempt = {
      amount: String(amount), coefficient: String(coefficient), count: String(event.count),
      event_id: event.event_id, event_ordinal: String(trace.length), multiplier: String(event.multiplier ?? 1),
      operation_path: event.operation_path ?? [], pre_balance: String(balance),
    };
    if (amount > balance) { attempt.status = "rejected"; trace.push(attempt); return { status: "error", code: "E_BUDGET", balance, trace }; }
    balance -= amount; attempt.post_balance = String(balance); attempt.status = "charged"; trace.push(attempt);
  }
  return { status: "ok", balance, trace };
}

function measureValue(value) {
  let nodes = 1; let members = 0; let items = 0; let scalars = typeof value === "string" ? Array.from(value).length : 0;
  if (Array.isArray(value)) {
    items = value.length; for (const child of value) { const m = measureValue(child); nodes += m.nodes; members += m.members; items += m.items; scalars += m.scalars; }
  } else if (value && typeof value === "object") {
    members = Object.keys(value).length;
    for (const [key, child] of Object.entries(value)) { scalars += Array.from(key).length; const m = measureValue(child); nodes += m.nodes; members += m.members; items += m.items; scalars += m.scalars; }
  }
  return { nodes, members, items, scalars, bytes: Buffer.byteLength(canonical(value), "utf8") };
}

function boundaryTracer() {
  const events = [];
  const next = new Map();
  const key = (path) => path.join("/");
  return {
    events,
    emit(event_id, count, operation_path = [], multiplier = 1) {
      if (count > 0) events.push({ event_id, count, operation_path: [...operation_path], multiplier });
    },
    child(parent = []) {
      const parentKey = key(parent); const ordinal = next.get(parentKey) ?? 0;
      next.set(parentKey, ordinal + 1); return [...parent, ordinal];
    },
  };
}

function parseTrace(text, tracer, path = []) {
  for (const _ of Buffer.from(text, "utf8")) tracer.emit("parse.input_byte", 1, path);
  const stack = [];
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    if (" \t\r\n".includes(character)) { index += 1; continue; }
    let token; let decoded = null;
    if ("{}[]:,".includes(character)) { token = character; index += 1; }
    else if (character === '"') {
      let end = index + 1; let escaped = false;
      while (end < text.length) {
        const current = text[end];
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === '"') break;
        end += 1;
      }
      const raw = text.slice(index, end + 1); decoded = JSON.parse(raw); token = "string"; index = end + 1;
    } else {
      let end = index;
      while (end < text.length && !"{}[]:, \t\r\n".includes(text[end])) end += 1;
      token = "scalar"; index = end;
    }
    if (stack.length && stack.at(-1).kind === "array" && stack.at(-1).expecting && token !== "]") {
      tracer.emit("parse.item", 1, path); stack.at(-1).expecting = false;
    }
    tracer.emit("parse.token", 1, path);
    if (token === "{" || token === "[") {
      tracer.emit("parse.container", 1, path); stack.push({ kind: token === "{" ? "object" : "array", expecting: token === "[" });
    } else if (token === "}" || token === "]") stack.pop();
    else if (token === ":") tracer.emit("parse.member", 1, path);
    else if (token === "," && stack.length && stack.at(-1).kind === "array") stack.at(-1).expecting = true;
    else if (token === "string") for (const _ of decoded) tracer.emit("parse.string_scalar", 1, path);
  }
}

function compareTrace(left, right, tracer, path) {
  const lm = measureValue(left); const rm = measureValue(right);
  tracer.emit("compare.base", 1, path);
  tracer.emit("compare.node", lm.nodes + rm.nodes, path);
  tracer.emit("compare.member", lm.members + rm.members, path);
  tracer.emit("compare.item", lm.items + rm.items, path);
  tracer.emit("compare.string_scalar", lm.scalars + rm.scalars, path);
  tracer.emit("compare.canonical_byte", lm.bytes + rm.bytes, path);
}

function canonicalTrace(value, tracer, path) {
  const measured = measureValue(value);
  tracer.emit("canonical.value", measured.nodes, path);
  tracer.emit("canonical.member", measured.members, path);
  tracer.emit("canonical.item", measured.items, path);
  tracer.emit("canonical.string_scalar", measured.scalars, path);
  for (const _ of Buffer.from(canonical(value), "utf8")) tracer.emit("canonical.output_byte", 1, path);
}

function projectedDigestTrace(body, contractType, projectionId, schemaId, tracer, parent = []) {
  const envelope = {
    algorithm: "sha-256", body, canonicalizer: "urn:gew:canonicalizer:jcs-input:1.0.0",
    contract_type: contractType, digest_domain: "urn:gew:digest:semantic:1.0.0",
    projection_id: projectionId, schema_id: schemaId,
  };
  const canonicalPath = tracer.child(parent); canonicalTrace(envelope, tracer, canonicalPath);
  const digestPath = tracer.child(parent);
  for (const _ of Buffer.from(canonical(envelope), "utf8")) tracer.emit("digest.input_byte", 1, digestPath);
  return contractDigest(body, contractType, projectionId, schemaId);
}

function semanticDigestTrace(body, contractType, schemaId, tracer, parent = []) {
  return projectedDigestTrace(
    body, contractType, "urn:gew:digest-projection:identity:1.0.0", schemaId, tracer, parent,
  );
}

function resultTrace(record, tracer, parent = []) {
  const measured = measureValue(record); const path = tracer.child(parent);
  tracer.emit("result.field", measured.members, path);
  tracer.emit("result.node", measured.nodes, path);
  for (const _ of Buffer.from(canonical(record), "utf8")) tracer.emit("result.output_byte", 1, path);
}

function schemaTrace(schema, instance, tracer, path = [], resolver = null) {
  tracer.emit("schema.instance_visit", 1, path);
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return;
  for (const keyword of Object.keys(schema).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
    tracer.emit("schema.keyword", 1, path);
    if (keyword === "$ref") {
      tracer.emit("schema.ref", 1, path);
      if (resolver) schemaTrace(resolver(schema[keyword]), instance, tracer, tracer.child(path), resolver);
    } else if (keyword === "format" && typeof instance === "string") {
      tracer.emit("schema.format", 1, path); const formatPath = tracer.child(path);
      for (const _ of instance) tracer.emit("format.scalar", 1, formatPath);
      if (schema[keyword] === "gew-opaque-ref" && validFormat("gew-opaque-ref", instance)) {
        for (const _ of Buffer.from(instance, "base64url")) tracer.emit("format.decoded_byte", 1, formatPath);
      }
    } else if (["properties", "additionalProperties", "unevaluatedProperties", "dependentSchemas"].includes(keyword) && instance && typeof instance === "object" && !Array.isArray(instance)) {
      const declared = schema.properties;
      for (const name of Object.keys(instance).sort(utf16Compare)) {
        tracer.emit("schema.property", 1, path); let child = null;
        if (keyword === "properties" && schema[keyword] && typeof schema[keyword] === "object") child = schema[keyword][name];
        else if (keyword === "additionalProperties" && (!declared || !(name in declared))) child = schema[keyword];
        else if (keyword === "unevaluatedProperties" && schema[keyword] !== false) child = schema[keyword];
        else if (keyword === "dependentSchemas" && schema[keyword] && name in schema[keyword]) child = schema[keyword][name];
        if (child !== null && child !== undefined) schemaTrace(child, keyword === "dependentSchemas" ? instance : instance[name], tracer, tracer.child(path), resolver);
      }
    } else if (["prefixItems", "items", "contains", "unevaluatedItems"].includes(keyword) && Array.isArray(instance)) {
      const prefix = schema.prefixItems;
      instance.forEach((item, index) => {
        tracer.emit("schema.item", 1, path); let child = null;
        if (keyword === "prefixItems" && Array.isArray(schema[keyword]) && index < schema[keyword].length) child = schema[keyword][index];
        else if (keyword === "items" && (!Array.isArray(prefix) || index >= prefix.length)) child = schema[keyword];
        else if (keyword === "contains") child = schema[keyword];
        else if (keyword === "unevaluatedItems" && schema[keyword] !== false) child = schema[keyword];
        if (child !== null) schemaTrace(child, item, tracer, tracer.child(path), resolver);
      });
    } else if (["allOf", "anyOf", "oneOf"].includes(keyword) && Array.isArray(schema[keyword])) {
      for (const child of schema[keyword]) { tracer.emit("schema.branch", 1, path); schemaTrace(child, instance, tracer, tracer.child(path), resolver); }
    } else if (["not", "if", "then", "else"].includes(keyword)) {
      tracer.emit("schema.branch", 1, path); schemaTrace(schema[keyword], instance, tracer, tracer.child(path), resolver);
    } else if (keyword === "uniqueItems" && schema[keyword] === true && Array.isArray(instance)) {
      for (let left = 0; left < instance.length; left += 1) for (let right = left + 1; right < instance.length; right += 1) {
        tracer.emit("unique.pair", 1, path); compareTrace(instance[left], instance[right], tracer, tracer.child(path));
      }
    }
  }
}

function schemaLocations(schema, path = []) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return [];
  const result = [[path, schema]];
  const maps = new Set(["$defs", "properties", "dependentSchemas"]);
  const scalars = new Set(["additionalProperties", "unevaluatedProperties", "unevaluatedItems", "items", "contains", "not", "if", "then", "else"]);
  const arrays = new Set(["allOf", "anyOf", "oneOf", "prefixItems"]);
  for (const keyword of Object.keys(schema).sort(utf16Compare)) {
    const children = schema[keyword];
    if (maps.has(keyword) && children && typeof children === "object" && !Array.isArray(children)) {
      for (const name of Object.keys(children).sort(utf16Compare)) result.push(...schemaLocations(children[name], [...path, keyword, name]));
    } else if (scalars.has(keyword)) result.push(...schemaLocations(children, [...path, keyword]));
    else if (arrays.has(keyword) && Array.isArray(children)) children.forEach((child, index) => result.push(...schemaLocations(child, [...path, keyword, index])));
  }
  return result;
}

function registryTrace(schemas, tracer) {
  for (const schema of [...schemas].sort((a, b) => Buffer.compare(Buffer.from(a.$id), Buffer.from(b.$id)))) {
    const raw = canonical(schema); const path = tracer.child([]);
    tracer.emit("registry.resource", 1, path); tracer.emit("registry.schema_byte", Buffer.byteLength(raw), path);
    parseTrace(raw, tracer, tracer.child(path));
    for (const [, location] of schemaLocations(schema)) {
      tracer.emit("registry.schema_location", 1, path);
      if (typeof location.$ref === "string") {
        tracer.emit("registry.ref_edge", 1, path);
        const fragment = location.$ref.includes("#") ? location.$ref.split("#", 2)[1] : "";
        if (fragment.startsWith("/")) for (const _ of fragment.slice(1).split("/")) tracer.emit("registry.pointer_token", 1, path);
      }
    }
    tracer.emit("registry.digest_compare", 1, path);
  }
}

function errorDetail(code, phase, rule_id, source_id, evaluation_path = []) {
  return { code, definition_path: [], evaluation_path, instance_path: [], phase, rule_id, source_id };
}

function geelTrace(expression, roots, tracer) {
  const programDigest = contractDigest(expression, "urn:gew:contract:geel-expression", "urn:gew:digest-projection:identity:1.0.0", "urn:gew:schema:geel-expression:1.0.0");
  function visit(node, path = [], evaluationPath = []) {
    tracer.emit("geel.node", 1, path);
    if (node.op === "literal") return { value: node.value };
    if (node.op === "path") {
      let current = roots[node.root];
      for (const token of node.tokens) {
        tracer.emit("geel.path_token", 1, path);
        if (current === undefined || current === null || !(token in current)) return { error: errorDetail("E_PATH_MISSING", "runtime", "path/member-missing", programDigest, evaluationPath) };
        current = current[token];
      }
      return { value: current };
    }
    const children = node.op === "all" || node.op === "any" ? node.args : node.op === "not" ? [node.arg] : node.op === "predicate" ? node.args : [node.left ?? node.container, node.right ?? node.value];
    const values = [];
    for (let index = 0; index < children.length; index += 1) {
      tracer.emit("geel.operand", 1, path); values.push(visit(children[index], tracer.child(path), [...evaluationPath, index]));
    }
    const error = values.find((item) => item.error)?.error; if (error) return { error };
    const operands = values.map((item) => item.value);
    if (["eq", "ne", "lt", "lte", "gt", "gte"].includes(node.op)) {
      compareTrace(operands[0], operands[1], tracer, tracer.child(path));
      return { value: node.op === "eq" ? canonical(operands[0]) === canonical(operands[1]) : true };
    }
    if (node.op === "contains" || node.op === "in") {
      const container = node.op === "contains" ? operands[0] : operands[1]; const sought = node.op === "contains" ? operands[1] : operands[0];
      for (const item of container) { tracer.emit("geel.membership_item", 1, path); compareTrace(item, sought, tracer, tracer.child(path)); }
      return { value: container.some((item) => canonical(item) === canonical(sought)) };
    }
    if (node.op === "predicate") {
      const executablePath = tracer.child(path); const measured = measureValue(operands);
      tracer.emit("executable.base", 1, executablePath); tracer.emit("executable.input_node", measured.nodes, executablePath);
      tracer.emit("executable.input_scalar", measured.scalars, executablePath); tracer.emit("executable.input_byte", measured.bytes, executablePath);
      return { value: operands[0].startsWith(operands[1]) };
    }
    if (node.op === "all") return { value: operands.every(Boolean) };
    if (node.op === "any") return { value: operands.some(Boolean) };
    return { value: true };
  }
  const outcome = visit(expression);
  const record = outcome.error
    ? { error: outcome.error, schema_version: "1.0.0", status: "error" }
    : { schema_version: "1.0.0", status: "ok", value: outcome.value };
  resultTrace(record, tracer); return record;
}

function boundarySummary(events) {
  let cumulative = 0;
  const observations = events.map((event, ordinal) => {
    const amount = event.count * event.multiplier;
    const attempt = (delta) => ({
      event_id: event.event_id, operation_path: event.operation_path, pre_balance: String(amount + delta),
      status: delta < 0 ? "rejected" : "charged", ...(delta < 0 ? {} : { post_balance: String(delta) }),
    });
    cumulative += amount;
    return {
      amount: String(amount), coefficient: "1", count: String(event.count), event_id: event.event_id,
      multiplier: String(event.multiplier), operation_path: event.operation_path, ordinal: String(ordinal),
      attempts: { before: attempt(-1), exact: attempt(0), after: attempt(1) },
    };
  });
  const paths = [...new Map(events.map((event) => [event.operation_path.join("/"), event.operation_path])).values()]
    .sort((a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i += 1) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; });
  return {
    boundary_digest: `sha256-raw-v1:${crypto.createHash("sha256").update(Buffer.from(canonical(observations), "utf8")).digest("hex")}`,
    event_count: events.length, event_ids: [...new Set(events.map((event) => event.event_id))].sort(),
    operation_paths: paths, total_cost: String(cumulative),
  };
}

function migrationBoundaryTrace(tracer) {
  const dialect = "https://json-schema.org/draft/2020-12/schema";
  const sourceSchema = { $id: "urn:gew:schema:contract-stack:1.0.0", $schema: dialect, properties: { index: { type: "integer" }, schema_version: { const: "1.0.0" }, value: { type: "integer" } }, required: ["schema_version"], type: "object", unevaluatedProperties: false };
  const targetSchema = { $id: "urn:gew:schema:contract-stack:1.0.1", $schema: dialect, properties: { index: { type: "integer" }, schema_version: { const: "1.0.1" }, value: { type: "integer" } }, required: ["schema_version"], type: "object", unevaluatedProperties: false };
  const sourceContract = "urn:gew:contract-stack:1.0.0"; const targetContract = "urn:gew:contract-stack:1.0.1";
  const value = { schema_version: "1.0.0", value: 1 };
  schemaTrace(sourceSchema, value, tracer);
  const sourceDigest = semanticDigestTrace(value, sourceContract, sourceSchema.$id, tracer);
  schemaTrace(sourceSchema, value, tracer);
  const executablePath = tracer.child([]); const measured = measureValue(value);
  tracer.emit("executable.base", 1, executablePath); tracer.emit("executable.input_node", measured.nodes, executablePath);
  tracer.emit("executable.input_scalar", measured.scalars, executablePath); tracer.emit("executable.input_byte", measured.bytes, executablePath);
  const output = { schema_version: "1.0.1", value: 1 };
  schemaTrace(targetSchema, output, tracer);
  const targetDigest = semanticDigestTrace(output, targetContract, targetSchema.$id, tracer);
  const provenance = {
    actor_id: "codex:boundary", registry_digest: "sha256-jcs-v1:e4704dc2aeefadf5c8bda310f663eea5e395d4f6423ea55f8a32b903c8286cda",
    registry_id: "urn:gew:migration-registry:builtin:1.0.0", result: "migrated", schema_version: "1.0.0",
    source_contract_id: sourceContract, source_digest: sourceDigest,
    steps: [{ implementation_digest: "sha256-raw-v1:293a27413af772784f61a4383eacbabd3997ec8007209b8e3dc6506a17d02ade", index: 0, output_digest: targetDigest, transform_id: "urn:gew:migration:contract-stack-1-0-0-to-1-0-1", version: "1.0.0" }],
    target_contract_id: targetContract, target_digest: targetDigest, transaction_id: "boundary-tx",
  };
  canonicalTrace(output, tracer, tracer.child([]));
  canonicalTrace(provenance, tracer, tracer.child([]));
  resultTrace({ output, output_canonical: canonical(output), provenance, provenance_canonical: canonical(provenance) }, tracer);
}

function productionBoundary(request) {
  const scenario = request.scenario; const tracer = boundaryTracer();
  const parseInputs = { "parse-null": "null", "parse-string": '"é"', "parse-array": "[1,true]", "parse-object": '{"a":1,"b":"x"}', "parse-nested": '{"a":[{"b":2}]}' };
  if (scenario in parseInputs) parseTrace(parseInputs[scenario], tracer);
  else {
    const schemas = {
      "schema-integer": [{ type: "integer", minimum: 1 }, 2],
      "schema-properties": [{ type: "object", properties: { x: { type: "integer" } } }, { x: 1 }],
      "schema-items": [{ type: "array", items: { type: "integer" } }, [1, 2]],
      "schema-all-of": [{ allOf: [{ type: "integer" }, { minimum: 1 }] }, 2],
      "schema-any-of": [{ anyOf: [{ type: "string" }, { type: "integer" }] }, 2],
      "schema-one-of": [{ oneOf: [{ const: 1 }, { const: 2 }] }, 2],
      "schema-not": [{ not: { type: "string" } }, 2],
      "schema-if-then": [{ if: { type: "integer" }, then: { minimum: 1 }, else: { type: "string" } }, 2],
      "schema-format-id": [{ type: "string", format: "gew-id" }, "node-1"],
      "schema-format-opaque": [{ type: "string", format: "gew-opaque-ref" }, "Z3JhcGg"],
      "schema-unique": [{ type: "array", uniqueItems: true }, [1, 2, 3]],
      "schema-contains": [{ type: "array", contains: { type: "integer" } }, [1, "x", 2]],
      "schema-unevaluated-properties": [{ type: "object", properties: { x: { type: "integer" } }, unevaluatedProperties: false }, { x: 1 }],
      "schema-unevaluated-items": [{ type: "array", prefixItems: [{ type: "integer" }], unevaluatedItems: false }, [1]],
    };
    if (scenario in schemas) schemaTrace(schemas[scenario][0], schemas[scenario][1], tracer);
    else if (scenario === "schema-ref") schemaTrace({ $ref: "urn:gew:schema:boundary-target:1.0.0" }, { x: 1 }, tracer, [], () => ({ type: "object", properties: { x: { type: "integer" } } }));
    else if (scenario === "registry-single" || scenario === "registry-ref") {
      const dialect = "https://json-schema.org/draft/2020-12/schema";
      const base = { $schema: dialect, $id: "urn:gew:schema:boundary-base:1.0.0", type: "object", properties: { schema_version: { const: "1.0.0" }, value: { type: "integer" } }, required: ["schema_version", "value"], unevaluatedProperties: false };
      const wrapper = { $schema: dialect, $id: "urn:gew:schema:boundary-wrapper:1.0.0", type: "object", properties: { schema_version: { const: "1.0.0" }, payload: { $ref: `${base.$id}#/properties/value` } }, required: ["schema_version", "payload"], unevaluatedProperties: false };
      registryTrace(scenario === "registry-single" ? [base] : [base, wrapper], tracer);
    } else {
      const geel = {
        "geel-literal": [{ op: "literal", value: true }, {}],
        "geel-path": [{ op: "path", root: "input", tokens: ["enabled"] }, { input: { enabled: true } }],
        "geel-equality": [{ op: "eq", left: { op: "literal", value: 1 }, right: { op: "literal", value: 1 } }, {}],
        "geel-membership": [{ op: "contains", container: { op: "path", root: "input", tokens: ["items"] }, value: { op: "literal", value: 2 } }, { input: { items: [1, 2, 3] } }],
        "geel-predicate": [{ op: "predicate", predicate_id: "urn:gew:predicate:string-starts-with", version: "1.0.0", args: [{ op: "literal", value: "graph" }, { op: "literal", value: "gra" }] }, {}],
        "geel-eager-error": [{ op: "all", args: [{ op: "literal", value: false }, { op: "path", root: "input", tokens: ["missing"] }] }, { input: {} }],
      };
      if (scenario in geel) geelTrace(geel[scenario][0], geel[scenario][1], tracer);
      else {
        const canonicalValues = { "canonical-integer": 1, "canonical-string": "é", "canonical-object": { b: 2, a: "x" }, "canonical-array": [1, "x", true] };
        const compareValues = { "compare-integer": [1, 1], "compare-string": ["é", "é"], "compare-object": [{ a: 1 }, { a: 2 }], "compare-array": [[1, 2], [1, 3]] };
        if (scenario in canonicalValues) canonicalTrace(canonicalValues[scenario], tracer, []);
        else if (scenario in compareValues) compareTrace(compareValues[scenario][0], compareValues[scenario][1], tracer, []);
        else if (scenario === "digest-integer" || scenario === "digest-object") semanticDigestTrace(scenario === "digest-integer" ? 1 : { a: 1, b: "x" }, "urn:gew:contract:boundary", "urn:gew:schema:boundary:1.0.0", tracer);
        else if (scenario === "result-nested") resultTrace({ schema_version: "1.0.0", status: "ok", value: { items: [1, "x"] } }, tracer);
        else if (scenario === "migration-success") migrationBoundaryTrace(tracer);
        else throw new Error("boundary-scenario");
      }
    }
  }
  return request.debug ? { events: tracer.events } : boundarySummary(tracer.events);
}

function productionTrace(request) {
  const resultRecord = { schema_version: "1.0.0", status: "ok", value: true };
  const envelope = {
    algorithm: "sha-256", body: { a: 1 }, canonicalizer: "urn:gew:canonicalizer:jcs-input:1.0.0",
    contract_type: "urn:gew:contract:trace", digest_domain: "urn:gew:digest:semantic:1.0.0",
    projection_id: "urn:gew:digest-projection:identity:1.0.0", schema_id: "urn:gew:schema:trace:1.0.0",
  };
  const repeated = (event_id, count, path = []) => Array.from({ length: count }, () => ({ event_id, count: 1, operation_path: path }));
  let events; let output;
  if (request.kind === "parse-null") { events = [...repeated("parse.input_byte", 4), { event_id: "parse.token", count: 1, operation_path: [] }]; output = "null"; }
  else if (request.kind === "parse-array") { events = [...repeated("parse.input_byte", 3), ...["parse.token", "parse.container", "parse.item", "parse.token", "parse.token"].map((event_id) => ({ event_id, count: 1, operation_path: [] }))]; output = "[1]"; }
  else if (request.kind === "schema-valid") { events = ["schema.instance_visit", "schema.keyword", "schema.keyword"].map((event_id) => ({ event_id, count: 1, operation_path: [] })); output = []; }
  else if (request.kind === "schema-format") { events = [...["schema.instance_visit", "schema.keyword", "schema.format"].map((event_id) => ({ event_id, count: 1, operation_path: [] })), ...repeated("format.scalar", 6, [0]), { event_id: "schema.keyword", count: 1, operation_path: [] }]; output = []; }
  else if (request.kind === "geel-literal") { events = [{ event_id: "geel.node", count: 1, operation_path: [] }, { event_id: "result.field", count: 3, operation_path: [0] }, { event_id: "result.node", count: measureValue(resultRecord).nodes, operation_path: [0] }, ...repeated("result.output_byte", Buffer.byteLength(canonical(resultRecord)), [0])]; output = resultRecord; }
  else if (request.kind === "canonical") { events = [{ event_id: "canonical.value", count: 1, operation_path: [] }, { event_id: "canonical.output_byte", count: 1, operation_path: [] }]; output = "1"; }
  else if (request.kind === "compare") { events = [{ event_id: "compare.base", count: 1, operation_path: [] }, { event_id: "compare.node", count: 2, operation_path: [] }, { event_id: "compare.canonical_byte", count: 2, operation_path: [] }]; output = true; }
  else if (request.kind === "digest") {
    const m = measureValue(envelope); const size = Buffer.byteLength(canonical(envelope));
    events = [{ event_id: "canonical.value", count: m.nodes, operation_path: [0] }, { event_id: "canonical.member", count: m.members, operation_path: [0] }, { event_id: "canonical.string_scalar", count: m.scalars, operation_path: [0] }, ...repeated("canonical.output_byte", size, [0]), ...repeated("digest.input_byte", size, [1])];
    output = contractDigest({ a: 1 }, "urn:gew:contract:trace", "urn:gew:digest-projection:identity:1.0.0", "urn:gew:schema:trace:1.0.0");
  } else throw new Error("trace-kind");
  const coefficients = Object.fromEntries(events.map((event) => [event.event_id, 1]));
  const result = budgetSummary({ budget: request.budget, coefficients, events });
  if (result.status === "ok") result.output = output;
  return result;
}

function resolveLocalReference(root, reference) {
  if (typeof reference !== "string" || !reference.startsWith("#")) throw new Error("wp02-ref");
  const fragment = reference.slice(1);
  if (fragment === "") return root;
  if (!fragment.startsWith("/")) throw new Error("wp02-ref");
  let current = root;
  for (const raw of fragment.slice(1).split("/")) {
    if (/~(?![01])/.test(raw)) throw new Error("wp02-ref");
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current) && /^(0|[1-9][0-9]*)$/.test(token) && Number(token) < current.length) current = current[Number(token)];
    else if (current && typeof current === "object" && Object.hasOwn(current, token)) current = current[token];
    else throw new Error("wp02-ref");
  }
  return current;
}

function tracedSchema(schema, instance, tracer, path) {
  schemaTrace(schema, instance, tracer, path, (reference) => resolveLocalReference(schema, reference));
}

function workTrace(events, coefficients, initialBalance) {
  let balance = initialBalance;
  return events.map((event, ordinal) => {
    const coefficient = coefficients[event.event_id];
    if (!Number.isSafeInteger(coefficient) || coefficient < 1) throw new Error("wp02-coefficient");
    const amount = coefficient * event.count * event.multiplier;
    if (!Number.isSafeInteger(amount) || amount > balance) throw new Error("wp02-budget");
    const record = {
      amount: String(amount), coefficient: String(coefficient), count: String(event.count),
      event_id: event.event_id, event_ordinal: String(ordinal), multiplier: String(event.multiplier),
      operation_path: event.operation_path, pre_balance: String(balance),
    };
    balance -= amount;
    record.post_balance = String(balance); record.status = "charged";
    return record;
  });
}

function wp02OperationTrace(kind, inputs) {
  const tracer = boundaryTracer();
  const graphContract = "urn:gew:contract:graph-definition";
  const graphProjection = "urn:gew:digest-projection:graph-definition:1.0.0";
  const graphInputId = "urn:gew:schema:graph-definition-digest-input:1.0.0";
  const snapshotContract = "urn:gew:contract:task-snapshot";
  const snapshotProjection = "urn:gew:digest-projection:task-snapshot:1.0.0";
  const snapshotInputId = "urn:gew:schema:task-snapshot-digest-input:1.0.0";
  if (kind === "graph_create") {
    tracedSchema(inputs.graph_input_schema, inputs.graph_candidate, tracer, tracer.child([]));
    projectedDigestTrace(inputs.graph_candidate, graphContract, graphProjection, graphInputId, tracer, tracer.child([]));
    tracedSchema(inputs.graph_source_schema, inputs.graph_record, tracer, tracer.child([]));
  } else if (kind === "graph_load") {
    tracedSchema(inputs.graph_source_schema, inputs.graph_record, tracer, tracer.child([]));
    tracedSchema(inputs.graph_input_schema, inputs.graph_candidate, tracer, tracer.child([]));
    projectedDigestTrace(inputs.graph_candidate, graphContract, graphProjection, graphInputId, tracer, tracer.child([]));
  } else if (kind === "snapshot_create") {
    tracedSchema(inputs.snapshot_input_schema, inputs.snapshot_body, tracer, tracer.child([]));
    projectedDigestTrace(inputs.snapshot_body, snapshotContract, snapshotProjection, snapshotInputId, tracer, tracer.child([]));
    tracedSchema(inputs.snapshot_source_schema, inputs.snapshot_record, tracer, tracer.child([]));
  } else if (kind === "snapshot_restore") {
    tracedSchema(inputs.snapshot_source_schema, inputs.snapshot_record, tracer, tracer.child([]));
    tracedSchema(inputs.snapshot_input_schema, inputs.snapshot_body, tracer, tracer.child([]));
    projectedDigestTrace(inputs.snapshot_body, snapshotContract, snapshotProjection, snapshotInputId, tracer, tracer.child([]));
  } else throw new Error("wp02-kind");
  return workTrace(tracer.events, inputs.coefficients, inputs.initial_balance);
}

function wp02Traces(request) {
  const kinds = ["graph_create", "graph_load", "snapshot_create", "snapshot_restore"];
  return Object.fromEntries(kinds.map((kind) => [kind, wp02OperationTrace(kind, request.inputs)]));
}

function migrateContract(request) {
  if (request.expected_schema_registry_id !== "urn:gew:schema-registry:migration:1.0.0" || request.expected_schema_registry_digest !== "sha256-jcs-v1:7886b195ddd46637995cc1aae91e6612315965bd5ccc2df8f17b19bce85954f0") return { status: "error", code: "REGISTRY" };
  const manifest = request.manifest;
  if (!manifest || Object.keys(manifest).sort().join(",") !== "registry_digest,registry_id,schema_version,transforms") return { status: "error", code: "REGISTRY" };
  const unsigned = { schema_version: manifest.schema_version, registry_id: manifest.registry_id, transforms: manifest.transforms };
  const registryDigest = contractDigest(unsigned, "urn:gew:contract:migration-registry", "urn:gew:digest-projection:migration-registry:1.0.0", "urn:gew:schema:migration-registry:1.0.0");
  if (registryDigest !== manifest.registry_digest || manifest.transforms.length !== 1) return { status: "error", code: "REGISTRY" };
  const transform = manifest.transforms[0];
  if (transform.implementation_digest !== "sha256-raw-v1:293a27413af772784f61a4383eacbabd3997ec8007209b8e3dc6506a17d02ade" || transform.capabilities.length !== 0) return { status: "error", code: "REGISTRY" };
  if (transform.source_contract_id !== request.source_contract_id || transform.target_contract_id !== request.target_contract_id) return { status: "error", code: "PATH" };
  const value = request.value;
  if (!value || value.schema_version !== "1.0.0" || Object.keys(value).some((key) => !["schema_version", "index", "value"].includes(key))) return { status: "error", code: "SOURCE" };
  const sourceDigest = contractDigest(value, request.source_contract_id, "urn:gew:digest-projection:identity:1.0.0", transform.input_schema_id);
  if (sourceDigest !== request.expected_source_digest) return { status: "error", code: "DIGEST" };
  const output = { ...value, schema_version: "1.0.1" };
  const targetDigest = contractDigest(output, request.target_contract_id, "urn:gew:digest-projection:identity:1.0.0", transform.output_schema_id);
  const provenance = {
    actor_id: request.actor_id,
    registry_digest: manifest.registry_digest,
    registry_id: manifest.registry_id,
    result: "migrated",
    schema_version: "1.0.0",
    source_contract_id: request.source_contract_id,
    source_digest: sourceDigest,
    steps: [{ implementation_digest: transform.implementation_digest, index: 0, output_digest: targetDigest, transform_id: transform.transform_id, version: transform.version }],
    target_contract_id: request.target_contract_id,
    target_digest: targetDigest,
    transaction_id: request.transaction_id,
  };
  return { status: "ok", output, output_canonical: canonical(output), provenance, provenance_canonical: canonical(provenance) };
}

function migrationPath(request) {
  const adjacency = new Map();
  request.edges.forEach((edge) => adjacency.set(edge.source, [...(adjacency.get(edge.source) ?? []), edge.target]));
  let count = 0;
  const visit = (current, seen) => {
    if (current === request.target) { count += 1; return; }
    for (const target of adjacency.get(current) ?? []) {
      if (seen.has(target)) throw new Error("cycle");
      visit(target, new Set([...seen, target]));
    }
  };
  visit(request.source, new Set([request.source]));
  return { path_count: count };
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function immutableAlias(request) {
  const shared = JSON.parse(JSON.stringify(request.shared));
  const source = { left: shared, right: shared };
  const frozen = deepFreeze(JSON.parse(JSON.stringify(source)));
  if (Array.isArray(shared)) shared.push(request.mutation); else shared.mutation = request.mutation;
  let mutationRejected = false;
  try { frozen.left.mutation = request.mutation; } catch { mutationRejected = true; }
  return {
    frozen_canonical: canonical(frozen),
    mutated_source_canonical: canonical(source),
    mutation_rejected: mutationRejected,
  };
}

function execute(request) {
  if (request.operation === "canonical") return { canonical: canonical(request.value) };
  if (request.operation === "raw_digest") return { digest: `sha256-raw-v1:${crypto.createHash("sha256").update(Buffer.from(canonical(request.value), "utf8")).digest("hex")}` };
  if (request.operation === "semantic_digest") return { digest: semanticDigest(request) };
  if (request.operation === "digest_contract") return digestContract(request);
  if (request.operation === "geel") return { value: geel(request.expression, request.roots) };
  if (request.operation === "schema") return { failures: schemaValidate(request.schema, request.instance) };
  if (request.operation === "schema_profile") return { valid: schemaProfile(request.schema) };
  if (request.operation === "strict_json") return strictJson(request.raw);
  if (request.operation === "format") return { valid: validFormat(request.format_id, request.value) };
  if (request.operation === "registry_ref") return { valid: registryReference(request.reference) };
  if (request.operation === "registry_contract") return registryContract(request);
  if (request.operation === "geel_summary") return geelSummary(request.expression, request.roots);
  if (request.operation === "budget") return budgetSummary(request);
  if (request.operation === "production_trace") return productionTrace(request);
  if (request.operation === "production_boundary") return productionBoundary(request);
  if (request.operation === "wp02_traces") return { traces: wp02Traces(request) };
  if (request.operation === "immutable") {
    const frozen = deepFreeze(JSON.parse(JSON.stringify(request.value)));
    const roundTrip = deepFreeze(JSON.parse(JSON.stringify(frozen)));
    return { canonical: canonical(frozen), round_trip_canonical: canonical(roundTrip), json_type: jsonType(request.value) };
  }
  if (request.operation === "immutable_alias") return immutableAlias(request);
  if (request.operation === "compatibility") return { compatible: (request.rows.find((row) => row.reader_id === request.reader_id)?.accepted_writer_ids ?? []).includes(request.writer_id) };
  if (request.operation === "migration") return migrateContract(request);
  if (request.operation === "migration_path") return migrationPath(request);
  throw new Error("operation");
}

const interfaceLines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of interfaceLines) {
  try { process.stdout.write(`${JSON.stringify({ status: "ok", ...execute(JSON.parse(line)) })}\n`); }
  catch (error) { process.stdout.write(`${JSON.stringify({ status: "error", code: error.message })}\n`); }
}
