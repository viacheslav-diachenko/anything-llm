process.env.NODE_ENV === "development"
  ? require("dotenv").config({ path: `.env.${process.env.NODE_ENV}` })
  : require("dotenv").config();
const JWT = require("jsonwebtoken");
const { User } = require("../../models/user");
const { jsonrepair } = require("jsonrepair");
const extract = require("extract-json-from-string");

function reqBody(request) {
  return typeof request.body === "string"
    ? JSON.parse(request.body)
    : request.body;
}

function queryParams(request) {
  return request.query;
}

function makeJWT(info = {}, expiry = "30d") {
  if (!process.env.JWT_SECRET)
    throw new Error("Cannot create JWT as JWT_SECRET is unset.");
  return JWT.sign(info, process.env.JWT_SECRET, { expiresIn: expiry });
}

// Note: Only valid for finding users in multi-user mode
// as single-user mode with password is not a "user"
async function userFromSession(request, response = null) {
  if (!!response && !!response.locals?.user) {
    return response.locals.user;
  }

  const proxyEnabled =
    process.env.MULTI_USER_MODE === "true" &&
    process.env.REVERSE_PROXY_AUTH_ENABLED === "true";
  const remoteUser = request.header("Remote-User");
  if (proxyEnabled && remoteUser) {
    const remoteGroups = (request.header("Remote-Groups") || "")
      .split(",")
      .map((g) => g.trim())
      .filter(Boolean);

    const { user, created } = await User.findOrCreate({ username: remoteUser });
    const adminGroups = (process.env.REVERSE_PROXY_AUTH_ADMIN_GROUPS || "")
      .split(",")
      .map((g) => g.trim())
      .filter(Boolean);
    const managerGroups = (process.env.REVERSE_PROXY_AUTH_MANAGER_GROUPS || "")
      .split(",")
      .map((g) => g.trim())
      .filter(Boolean);

    let role = "default";
    if (remoteGroups.some((g) => adminGroups.includes(g))) role = "admin";
    else if (remoteGroups.some((g) => managerGroups.includes(g))) role = "manager";

    if (user && user.role !== role) {
      await User._update(user.id, { role });
      user.role = role;
    }
    return user;
  }

  const auth = request.header("Authorization");
  const token = auth ? auth.split(" ")[1] : null;

  if (!token) {
    return null;
  }

  const valid = decodeJWT(token);
  if (!valid || !valid.id) {
    return null;
  }

  const user = await User.get({ id: valid.id });
  return user;
}

function decodeJWT(jwtToken) {
  try {
    return JWT.verify(jwtToken, process.env.JWT_SECRET);
  } catch {}
  return { p: null, id: null, username: null };
}

function multiUserMode(response) {
  return response?.locals?.multiUserMode;
}

function parseAuthHeader(headerValue = null, apiKey = null) {
  if (headerValue === null || apiKey === null) return {};
  if (headerValue === "Authorization")
    return { Authorization: `Bearer ${apiKey}` };
  return { [headerValue]: apiKey };
}

function safeJsonParse(jsonString, fallback = null) {
  if (jsonString === null) return fallback;

  try {
    return JSON.parse(jsonString);
  } catch {}

  if (jsonString?.startsWith("[") || jsonString?.startsWith("{")) {
    try {
      const repairedJson = jsonrepair(jsonString);
      return JSON.parse(repairedJson);
    } catch {}
  }

  try {
    return extract(jsonString)?.[0] || fallback;
  } catch {}

  return fallback;
}

function isValidUrl(urlString = "") {
  try {
    const url = new URL(urlString);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    return true;
  } catch (e) {}
  return false;
}

function toValidNumber(number = null, fallback = null) {
  if (isNaN(Number(number))) return fallback;
  return Number(number);
}

module.exports = {
  reqBody,
  multiUserMode,
  queryParams,
  makeJWT,
  decodeJWT,
  userFromSession,
  parseAuthHeader,
  safeJsonParse,
  isValidUrl,
  toValidNumber,
};
