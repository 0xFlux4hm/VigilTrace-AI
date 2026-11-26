package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Params;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.json.Json;

/**
 * {@code extract_parameters}: every insertion point of one request with an "interestingness" ranking, so the agent
 * picks test targets deliberately (object ids, role fields, reflectable values) instead of fuzzing everything.
 */
public final class ExtractParametersTool implements Tool {
    private static final Pattern NUMERIC_ID = Pattern.compile("^\\d{1,20}$");
    private static final Pattern UUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern HEX_ID = Pattern.compile("^[0-9a-fA-F]{24}$");
    private static final Pattern ULID = Pattern.compile("^[0-9A-HJKMNP-TV-Z]{26}$");
    private static final Pattern URL_VALUE = Pattern.compile("^(https?:)?//\\S+$");
    private static final Pattern EMAIL = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Pattern FILE_VALUE = Pattern.compile(
            "^[\\w .\\-/\\\\:@]*\\.(pdf|docx?|xlsx?|pptx?|csv|txt|zip|tar|gz|tgz|7z|rar|jpg|jpeg|png|gif|svg|webp|ico|mp[34]|xml|json|ya?ml|html?|js|css|map|php\\d?|asp(x)?|jsp|py|rb|sh|bat|ps1|bak|old|orig|save|swp|sql|db|sqlite3?|log|conf|ini|env|toml|key|pem|crt|p12|jks)$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern ID_NAME = Pattern.compile("(^|[_\\-.])(id|uuid|guid|uid|oid|ref|no|num|nr|key|slug|handle|code)$");
    private static final Pattern FILE_NAME = Pattern.compile("file|path|doc|folder|dir|upload|attach|page|template|include|import|report|image|img|media|download|export");
    private static final Pattern ROLE_NAME = Pattern.compile(
            "role|perm|admin|priv|access|account_?type|user_?type|level|scope|entitle|plan|tier|group|rights|grant|superuser|staff|manager|owner|org|tenant|team|is_?active|enabled|verified|banned|suspend");
    private static final Pattern SESSION_NAME = Pattern.compile(
            "sess|session|sid|token|auth|jwt|csrf|xsrf|phpsessid|jsessionid|asp\\.net_sessionid|laravel_session|remember|credential|login",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STATE_CHANGING = Pattern.compile("^(POST|PUT|PATCH|DELETE)$");
    private static final Set<String> SECRET_HEADERS = Set.of("authorization", "x-api-key", "x-auth-token");
    private static final String[] LOCATION_ORDER = {"query", "body", "json", "multipart", "xml", "cookie", "header"};

    @Override
    public String name() {
        return "extract_parameters";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        Exchange ex = ctx.resolveSource(args);
        boolean includeCookies = args.bool("include_cookies", true);
        boolean includeHeaders = args.bool("include_headers", false);
        boolean deepJson = args.bool("deep_json", true);
        boolean checkReflection = args.bool("check_reflection", true);
        int max = args.integer("max", 100, 1, 1000);

        List<Params.Param> params = Params.extract(ex.requestRaw, includeCookies, includeHeaders, deepJson);
        boolean stateChanging = ex.method != null && STATE_CHANGING.matcher(ex.method.toUpperCase(Locale.ROOT)).matches();
        String body = ex.responseBody == null ? "" : ex.responseBody;

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Params.Param p : params) {
            String name = p.name == null ? "" : p.name;
            String value = p.value == null ? "" : p.value;
            String lowerName = name.toLowerCase(Locale.ROOT);
            boolean header = "header".equals(p.location);
            boolean cookie = "cookie".equals(p.location);
            boolean sessionCookie = cookie && SESSION_NAME.matcher(name).find();
            boolean secret = header && SECRET_HEADERS.contains(lowerName);

            Set<String> flags = new LinkedHashSet<>();
            boolean idLike = NUMERIC_ID.matcher(value).matches() || UUID.matcher(value).matches()
                    || HEX_ID.matcher(value).matches() || ULID.matcher(value).matches()
                    || ID_NAME.matcher(lowerName).find() && !value.isEmpty();
            boolean urlLike = URL_VALUE.matcher(value).find();
            boolean fileLike = FILE_NAME.matcher(lowerName).find() || FILE_VALUE.matcher(value).matches();
            boolean roleLike = ROLE_NAME.matcher(lowerName).find();
            boolean reflectable = checkReflection && value.length() >= 4 && !secret && !sessionCookie
                    && (body.contains(value) || body.contains(Params.urlEncode(value)));
            if (idLike) {
                flags.add("id_like");
            }
            if (urlLike) {
                flags.add("url_like");
            }
            if (fileLike) {
                flags.add("file_like");
            }
            if (roleLike) {
                flags.add("role_like");
            }
            if (reflectable) {
                flags.add("reflectable");
            }
            if (stateChanging && !"header".equals(p.location)) {
                flags.add("state_changing");
            }
            if (sessionCookie) {
                flags.add("session_cookie");
            }

            int rank = 0;
            if (roleLike) {
                rank += 4;
            }
            if (idLike || urlLike || fileLike) {
                rank += 3;
            }
            if (reflectable) {
                rank += 2;
            }
            if (stateChanging) {
                rank += 1;
            }
            if (sessionCookie || secret) {
                rank -= 5;
            }
            boolean testable = !sessionCookie && !secret;

            Map<String, Object> row = Json.obj(
                    "name", name,
                    "value_preview", previewValue(value, secret || sessionCookie),
                    "location", p.location,
                    "json_path", p.jsonPath,
                    "filename", p.filename,
                    "type_hint", typeHint(value),
                    "flags", new ArrayList<>(flags),
                    "rank", rank,
                    "testable", testable);
            rows.add(row);
        }

        rows.sort(Comparator
                .comparingInt((Map<String, Object> r) -> -(Integer) r.get("rank"))
                .thenComparingInt(r -> locationIndex((String) r.get("location")))
                .thenComparing(r -> String.valueOf(r.get("name"))));
        List<Map<String, Object>> shown = new ArrayList<>(rows.subList(0, Math.min(max, rows.size())));
        int testableCount = (int) rows.stream().filter(r -> (Boolean) r.get("testable")).count();
        String host;
        String path;
        try {
            host = Urls.parse(ex.url).host;
            path = Urls.parse(ex.url).rest;
        } catch (ToolException e) {
            host = null;
            path = null;
        }
        return Json.obj(
                "source", ToolSupport.sourceRef(args),
                "url", ex.url,
                "host", host,
                "path", path == null || path.isEmpty() ? "/" : path,
                "method", ex.method,
                "parameters", shown,
                "total", rows.size(),
                "returned", shown.size(),
                "testable", testableCount,
                "state_changing_method", stateChanging,
                "ranking", "rank = role_like 4 + id/url/file_like 3 + reflectable 2 + state_changing 1 − session/secret 5; "
                        + "swap id_like values across two test accounts for access-control tests, set role_like fields for "
                        + "mass-assignment tests, use reflectable values as proven reflections.");
    }

    /** Session cookies and credentials are never echoed in full: the agent only needs to know they exist. */
    private static String previewValue(String value, boolean mask) {
        if (value.isEmpty()) {
            return "";
        }
        if (!mask) {
            return Params.preview(value, 160);
        }
        String head = value.length() <= 6 ? "" : value.substring(0, 4);
        return head + "…(" + value.length() + " chars, redacted)";
    }

    private static String typeHint(String value) {
        if (value.isEmpty()) {
            return "empty";
        }
        if (NUMERIC_ID.matcher(value).matches()) {
            return "integer";
        }
        if (UUID.matcher(value).matches() || HEX_ID.matcher(value).matches() || ULID.matcher(value).matches()) {
            return "unique-id";
        }
        if (URL_VALUE.matcher(value).find()) {
            return "url";
        }
        if (EMAIL.matcher(value).matches()) {
            return "email";
        }
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) {
            return "boolean";
        }
        String t = value.trim();
        if (t.startsWith("{") || t.startsWith("[")) {
            return "json";
        }
        if (t.startsWith("<")) {
            return "xml";
        }
        return "string";
    }

    private static int locationIndex(String location) {
        for (int k = 0; k < LOCATION_ORDER.length; k++) {
            if (LOCATION_ORDER[k].equals(location)) {
                return k;
            }
        }
        return LOCATION_ORDER.length;
    }
}
