package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.agent.burp.core.Params;
import dev.agent.burp.core.RawRequest;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;

/**
 * Deterministic edits on a {@link RawRequest} for {@code modify_and_resend_request}. Every method returns a short
 * description of what it changed (the {@code modifications_applied} list), so a differential test is reproducible
 * from the tool result alone.
 */
final class RequestEditor {
    private static final Pattern FORM_SNIFF = Pattern.compile("^[^<>\\n]+=.*$");

    private final RawRequest r;
    private boolean bodyChanged;

    RequestEditor(RawRequest r) {
        this.r = r;
    }

    /** Re-serializes the request; call after the last edit so Content-Length matches the new body. */
    String serialize() {
        if (bodyChanged && !r.hasHeader("Transfer-Encoding")) {
            long length = r.body == null ? 0L : ToolSupport.utf8Length(r.body);
            if (length == 0) {
                r.removeHeader("Content-Length");
            } else {
                r.setHeader("Content-Length", String.valueOf(length));
            }
        }
        return r.serialize();
    }

    // ---------------------------------------------------------------- headers / method / url

    String removeHeader(String name) {
        return r.removeHeader(name) ? "removed header " + name : "header " + name + " was not present";
    }

    String setHeader(String name, String value) {
        if (name == null || name.trim().isEmpty()) {
            throw new ToolException("invalid_argument", "set_headers: header name must not be empty.");
        }
        if (value == null || value.isEmpty()) {
            return removeHeader(name.trim());
        }
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new ToolException("invalid_argument",
                    "Header value of '" + name.trim() + "' contains a line break; a header cannot span lines.");
        }
        boolean existed = r.hasHeader(name);
        r.setHeader(name.trim(), value);
        return (existed ? "updated header " : "added header ") + name.trim();
    }

    String setMethod(String method) {
        String m = method.trim().toUpperCase(Locale.ROOT);
        if (m.isEmpty()) {
            throw new ToolException("invalid_argument", "method must not be empty.");
        }
        String before = r.method;
        r.method = m;
        return "method " + before + " -> " + m;
    }

    /** Retargets the request: path/query from the URL, Host header set to the URL's host (a Host swap is refused). */
    String setUrl(String url) {
        Urls.Parsed u = Urls.parse(url.trim());
        String rest = u.rest.isEmpty() ? "/" : u.rest;
        String host = u.port == Urls.defaultPort(u.scheme) ? u.host : u.host + ":" + u.port;
        boolean absoluteForm = r.target != null && r.target.contains("://");
        if (absoluteForm) {
            r.target = u.origin() + rest;
        } else {
            r.setPathAndQuery(rest);
        }
        r.setHeader("Host", host);
        return "retargeted to " + u.origin() + rest;
    }

    // ---------------------------------------------------------------- parameters

    String setParam(String name, String value, String location) {
        if (name == null || name.isBlank()) {
            throw new ToolException("invalid_argument", "set_params: 'name' must not be empty.");
        }
        switch (location) {
            case "query":
                return setQuery(name, value);
            case "cookie":
                return setCookie(name, value);
            case "json":
                return setJson(name, value);
            case "body":
                return setInBody(name, value, true);
            default:
                return setAuto(name, value);
        }
    }

    String removeParam(String name) {
        if (name == null || name.isBlank()) {
            throw new ToolException("invalid_argument", "remove_params: name must not be empty.");
        }
        List<String> done = new ArrayList<>();
        String pq = r.pathAndQuery();
        if (Params.pairExists(Params.queryOf(pq), '&', name)) {
            r.setPathAndQuery(Params.withQuery(Params.pathOf(pq), Params.removeFromPairs(Params.queryOf(pq), '&', name)));
            done.add("query");
        }
        String cookie = r.header("Cookie");
        if (cookie != null && cookieValue(cookie, name) != null) {
            String updated = Params.removeCookie(cookie, name);
            if (updated.isEmpty()) {
                r.removeHeader("Cookie");
            } else {
                r.setHeader("Cookie", updated);
            }
            done.add("cookie");
        }
        String body = r.body == null ? "" : r.body;
        String ct = r.contentType();
        if (isJson(ct, body)) {
            String updated = Params.jsonDelete(body, name);
            if (updated != null) {
                r.body = updated;
                bodyChanged = true;
                done.add("json");
            }
        }
        String delimiter = Params.multipartBoundary(r.header("Content-Type"));
        if (delimiter != null) {
            String updated = Params.removeMultipartPart(body, delimiter, name);
            if (updated != null) {
                r.body = updated;
                bodyChanged = true;
                done.add("multipart");
            }
        }
        if (isXml(ct, body)) {
            String updated = removeXml(body, name);
            if (updated != null) {
                r.body = updated;
                bodyChanged = true;
                done.add("xml");
            }
        }
        if (isForm(ct, body) && Params.pairExists(body, '&', name)) {
            r.body = Params.removeFromPairs(body, '&', name);
            bodyChanged = true;
            done.add("body");
        }
        return done.isEmpty() ? "parameter " + name + " was not present" : "removed parameter " + name + " from " + String.join(", ", done);
    }

    private String setQuery(String name, String value) {
        String pq = r.pathAndQuery();
        boolean existed = Params.pairExists(Params.queryOf(pq), '&', name);
        r.setPathAndQuery(Params.withQuery(Params.pathOf(pq), Params.setInPairs(Params.queryOf(pq), '&', name, value)));
        return (existed ? "set query param " : "added query param ") + name + "=" + Params.preview(value, 80);
    }

    private String setCookie(String name, String value) {
        String cookie = r.header("Cookie");
        boolean existed = cookie != null && cookieValue(cookie, name) != null;
        r.setHeader("Cookie", Params.setCookie(cookie, name, value));
        return (existed ? "set cookie " : "added cookie ") + name + "=" + Params.preview(value, 80);
    }

    private String setJson(String name, String value) {
        String body = r.body == null ? "" : r.body;
        String updated = Params.jsonSet(body, name, value);
        boolean existed = Params.jsonGet(Params.parseJsonOrNull(body), name) != null;
        r.body = updated;
        bodyChanged = true;
        if (r.contentType().isEmpty()) {
            r.setHeader("Content-Type", "application/json");
        }
        return (existed ? "set json " : "added json ") + name + "=" + Params.preview(value, 80);
    }

    private String setAuto(String name, String value) {
        String pq = r.pathAndQuery();
        if (Params.pairExists(Params.queryOf(pq), '&', name)) {
            return setQuery(name, value);
        }
        String cookie = r.header("Cookie");
        if (cookie != null && cookieValue(cookie, name) != null) {
            return setCookie(name, value);
        }
        String body = r.body == null ? "" : r.body;
        String ct = r.contentType();
        if (isJson(ct, body) && Params.jsonGet(Params.parseJsonOrNull(body), name) != null) {
            return setJson(name, value);
        }
        String delimiter = Params.multipartBoundary(r.header("Content-Type"));
        if (delimiter != null) {
            String updated = Params.setMultipartPart(body, delimiter, name, value);
            if (updated != null) {
                r.body = updated;
                bodyChanged = true;
                return "set multipart field " + name + "=" + Params.preview(value, 80);
            }
        }
        if (isXml(ct, body) && findXml(body, name)) {
            r.body = setXml(body, name, value);
            bodyChanged = true;
            return "set xml value " + name + "=" + Params.preview(value, 80);
        }
        if (isForm(ct, body) && Params.pairExists(body, '&', name)) {
            return setForm(name, value);
        }
        String result = setQuery(name, value);
        return result + " (not present elsewhere, so it was added to the query string)";
    }

    /** {@code body} location: form field, multipart part, JSON member or XML value, chosen by Content-Type. */
    private String setInBody(String name, String value, boolean explicitBody) {
        String body = r.body == null ? "" : r.body;
        String ct = r.contentType();
        if (isForm(ct, body)) {
            return setForm(name, value);
        }
        String delimiter = Params.multipartBoundary(r.header("Content-Type"));
        if (delimiter != null) {
            String updated = Params.setMultipartPart(body, delimiter, name, value);
            if (updated == null) {
                throw new ToolException("invalid_argument",
                        "The multipart body has no part named '" + name + "'. Use extract_parameters to list the parts.");
            }
            r.body = updated;
            bodyChanged = true;
            return "set multipart field " + name + "=" + Params.preview(value, 80);
        }
        if (isJson(ct, body)) {
            return setJson(name, value);
        }
        if (isXml(ct, body)) {
            if (!findXml(body, name)) {
                throw new ToolException("invalid_argument", "The XML body has no element or attribute named '" + name + "'.");
            }
            r.body = setXml(body, name, value);
            bodyChanged = true;
            return "set xml value " + name + "=" + Params.preview(value, 80);
        }
        throw new ToolException("invalid_argument",
                (explicitBody ? "location 'body'" : "location 'auto'") + " needs a form, multipart, JSON or XML body; this request has"
                        + (ct.isEmpty() ? " no Content-Type and an unrecognised body" : " Content-Type '" + ct + "'")
                        + ". Pass location 'query' or 'json' to add the parameter there.");
    }

    private String setForm(String name, String value) {
        String body = r.body == null ? "" : r.body;
        boolean existed = Params.pairExists(body, '&', name);
        r.body = Params.setInPairs(body, '&', name, value);
        bodyChanged = true;
        if (r.contentType().isEmpty()) {
            r.setHeader("Content-Type", "application/x-www-form-urlencoded");
        }
        return (existed ? "set body param " : "added body param ") + name + "=" + Params.preview(value, 80);
    }

    private static String cookieValue(String cookieHeader, String name) {
        for (String[] c : Params.parseCookies(cookieHeader)) {
            if (c[0].equals(name)) {
                return c[1];
            }
        }
        return null;
    }

    private static boolean isJson(String ct, String body) {
        String t = body.trim();
        return Params.isJsonContentType(ct) || ct.isEmpty() && !t.isEmpty() && (t.startsWith("{") || t.startsWith("[")) && Params.parseJsonOrNull(body) != null;
    }

    private static boolean isXml(String ct, String body) {
        String t = body.trim();
        return Params.isXmlContentType(ct) || ct.isEmpty() && !t.isEmpty() && t.startsWith("<");
    }

    private static boolean isForm(String ct, String body) {
        String t = body.trim();
        return Params.isFormContentType(ct) || ct.isEmpty() && !t.isEmpty() && FORM_SNIFF.matcher(t).matches();
    }

    // ---------------------------------------------------------------- text replacement

    /** Literal replacement of the first {@code max} occurrences ({@code <= 0}: all) in the body. */
    String replaceInBody(String find, String with, int max) {
        if (find == null || find.isEmpty()) {
            throw new ToolException("invalid_argument", "replace_in_body: 'find' must not be empty.");
        }
        String body = r.body == null ? "" : r.body;
        StringBuilder sb = new StringBuilder();
        int from = 0;
        int count = 0;
        int idx;
        while ((max <= 0 || count < max) && (idx = body.indexOf(find, from)) >= 0 && count < 100_000) {
            sb.append(body, from, idx).append(with);
            from = idx + find.length();
            count++;
        }
        if (count == 0) {
            return "replace_in_body: '" + Params.preview(find, 40) + "' not found in the body";
        }
        sb.append(body, from, body.length());
        r.body = sb.toString();
        bodyChanged = true;
        return "replaced " + count + " occurrence" + (count == 1 ? "" : "s") + " of '" + Params.preview(find, 40) + "' in the body";
    }

    String replaceInUrl(String find, String with) {
        if (find == null || find.isEmpty()) {
            throw new ToolException("invalid_argument", "replace_in_url: 'find' must not be empty.");
        }
        String pq = r.pathAndQuery();
        if (!pq.contains(find)) {
            return "replace_in_url: '" + Params.preview(find, 40) + "' not found in " + pq;
        }
        String updated = pq.replace(find, with);
        r.setPathAndQuery(updated);
        return "replace_in_url: " + Params.preview(pq, 120) + " -> " + Params.preview(updated, 120);
    }

    // ---------------------------------------------------------------- XML

    private static boolean findXml(String body, String name) {
        return xmlElement(body, name).find() || xmlAttribute(body, name).find();
    }

    private static Matcher xmlElement(String body, String name) {
        return Pattern.compile("(<" + Pattern.quote(name) + "(?:\\s[^<>]*)?>)([^<>]*)(</" + Pattern.quote(name) + "\\s*>)").matcher(body);
    }

    private static Matcher xmlAttribute(String body, String name) {
        return Pattern.compile("(\\b" + Pattern.quote(name) + "\\s*=\\s*\")([^\"]*)(\")").matcher(body);
    }

    private static String setXml(String body, String name, String value) {
        Matcher element = xmlElement(body, name);
        if (element.find()) {
            return element.replaceFirst(Matcher.quoteReplacement(element.group(1) + xmlEscape(value) + element.group(3)));
        }
        Matcher attribute = xmlAttribute(body, name);
        return attribute.replaceFirst("$1" + Matcher.quoteReplacement(xmlEscape(value)) + "$3");
    }

    private static String removeXml(String body, String name) {
        String q = Pattern.quote(name);
        String updated = body.replaceAll("<" + q + "(\\s[^<>]*)?/>\\s*", "");
        updated = updated.replaceAll("(?s)<" + q + "(\\s[^<>]*)?>.*?</" + q + "\\s*>\\s*", "");
        updated = updated.replaceAll("\\s+" + q + "\\s*=\\s*\"[^\"]*\"", "");
        return updated.equals(body) ? null : updated;
    }

    private static String xmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
