import com.sun.net.httpserver.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import static java.nio.charset.StandardCharsets.UTF_8;

/** SmartBank Token System - real web version. Java 8 compatible (NetBeans 8.2). Needs MySQL Connector/J on the classpath. */
public class SmartBankServer {
    static final String DB = "bank_token";
    static final String DB_USER = env("DB_USER", "root"), DB_PASS = env("DB_PASSWORD", "");
    static final String SERVER_URL = "jdbc:mysql://localhost:3306/?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true";
    static final String DB_URL = "jdbc:mysql://localhost:3306/" + DB + "?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true";
    static final Map<String, String> PREFIX = new HashMap<String, String>();
    static {
        PREFIX.put("Account Service", "A");
        PREFIX.put("Cash Service", "C");
        PREFIX.put("Loan Service", "L");
    }
    static final Map<String, Session> sessions = new ConcurrentHashMap<>();
    static final Map<String, long[]> fails = new ConcurrentHashMap<>();
    static volatile boolean queueOpen = true;
    static volatile String notice = "";
    static final SecureRandom RNG = new SecureRandom();

    static final class Session {
        private final String role, name;
        private final int id;
        Session(String role, int id, String name) { this.role = role; this.id = id; this.name = name; }
        String role() { return role; }
        int id() { return id; }
        String name() { return name; }
    }
    static class ApiError extends RuntimeException {
        final int code;
        ApiError(int code, String msg) { super(msg); this.code = code; }
    }

    static String env(String k, String d) { String v = System.getenv(k); return v == null ? d : v; }

    // ---------------------------------------------------------------- main
    public static void main(String[] args) throws Exception {
        initDb();
        int port = Integer.parseInt(env("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(env("HOST", "127.0.0.1"), port), 0);
        server.createContext("/", SmartBankServer::handle);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("SmartBank running -> http://localhost:" + port + "   (staff: admin / admin123)");
    }

    // ---------------------------------------------------------------- database
    static Connection db() throws SQLException { return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS); }

    static void initDb() throws SQLException {
        try (Connection c = DriverManager.getConnection(SERVER_URL, DB_USER, DB_PASS); Statement st = c.createStatement()) {
            st.executeUpdate("CREATE DATABASE IF NOT EXISTS " + DB);
        }
        try (Connection c = db(); Statement st = c.createStatement()) {
            st.executeUpdate("CREATE TABLE IF NOT EXISTS customers (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100) NOT NULL, phone VARCHAR(20) NOT NULL, email VARCHAR(150) UNIQUE NOT NULL, password_hash VARCHAR(128) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(128) NOT NULL)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS counters (id INT PRIMARY KEY AUTO_INCREMENT, counter_name VARCHAR(50) NOT NULL, service VARCHAR(50) NOT NULL, status VARCHAR(20) NOT NULL)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS tokens (id INT PRIMARY KEY AUTO_INCREMENT, token_number VARCHAR(20) UNIQUE NOT NULL, customer_id INT NOT NULL, service VARCHAR(50) NOT NULL, priority VARCHAR(20) NOT NULL, status VARCHAR(20) NOT NULL, waiting_time INT DEFAULT 0, counter_id INT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, called_at TIMESTAMP NULL, completed_at TIMESTAMP NULL, FOREIGN KEY(customer_id) REFERENCES customers(id), FOREIGN KEY(counter_id) REFERENCES counters(id))");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS feedback (token_id INT PRIMARY KEY, rating INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS audit_log (id INT PRIMARY KEY AUTO_INCREMENT, actor VARCHAR(60), action VARCHAR(200), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
            if (num(c, "SELECT COUNT(*) FROM users") == 0)
                exec(c, "INSERT INTO users (username,password_hash) VALUES (?,?)", "admin", newHash("admin123"));
            if (num(c, "SELECT COUNT(*) FROM counters") == 0) {
                exec(c, "INSERT INTO counters (counter_name,service,status) VALUES (?,?,'AVAILABLE')", "Counter 1", "Account Service");
                exec(c, "INSERT INTO counters (counter_name,service,status) VALUES (?,?,'AVAILABLE')", "Counter 2", "Cash Service");
                exec(c, "INSERT INTO counters (counter_name,service,status) VALUES (?,?,'AVAILABLE')", "Counter 3", "Loan Service");
            }
        }
    }

    static final String AVG_SVC = "SELECT GREATEST(2,COALESCE(ROUND(AVG(TIMESTAMPDIFF(MINUTE,called_at,completed_at))),5)) FROM (SELECT called_at,completed_at FROM tokens WHERE status='COMPLETED' ORDER BY id DESC LIMIT 50) z";

    static void audit(String who, String what) {
        try { exec("INSERT INTO audit_log (actor,action) VALUES (?,?)", who, what); } catch (SQLException e) { /* never block the request */ }
    }

    static void exportCsv(HttpExchange ex) throws Exception {
        need(session(ex), "staff");
        StringBuilder sb = new StringBuilder("Token,Customer,Phone,Service,Queue,Status,Taken\n");
        try (Connection c = db(); Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT t.token_number,c.name,c.phone,t.service,t.priority,t.status,t.created_at FROM tokens t JOIN customers c ON t.customer_id=c.id ORDER BY t.id DESC")) {
            while (rs.next()) {
                for (int i = 1; i <= 7; i++) {
                    String v = String.valueOf(rs.getString(i));
                    if (v.matches("^[=+@-].*")) v = "'" + v;   // block spreadsheet formula injection
                    sb.append('"').append(v.replace("\"", "\"\"")).append(i < 7 ? "\"," : "\"\n");
                }
            }
        }
        ex.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"smartbank-tokens.csv\"");
        send(ex, 200, "text/csv; charset=utf-8", sb.toString().getBytes(UTF_8));
    }

    static void bind(PreparedStatement ps, Object[] a) throws SQLException { for (int i = 0; i < a.length; i++) ps.setObject(i + 1, a[i]); }

    static int exec(Connection c, String sql, Object... a) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) { bind(ps, a); return ps.executeUpdate(); }
    }
    static int exec(String sql, Object... a) throws SQLException { try (Connection c = db()) { return exec(c, sql, a); } }

    static int num(Connection c, String sql, Object... a) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, a);
            try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getInt(1) : 0; }
        }
    }

    static String[] row(Connection c, String sql, Object... a) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, a);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                String[] r = new String[rs.getMetaData().getColumnCount()];
                for (int i = 0; i < r.length; i++) r[i] = rs.getString(i + 1);
                return r;
            }
        }
    }
    static String[] row(String sql, Object... a) throws SQLException { try (Connection c = db()) { return row(c, sql, a); } }

    static String rows(String sql, Object... a) throws SQLException {
        try (Connection c = db(); PreparedStatement ps = c.prepareStatement(sql)) {
            bind(ps, a);
            try (ResultSet rs = ps.executeQuery()) {
                ResultSetMetaData md = rs.getMetaData();
                StringBuilder sb = new StringBuilder("[");
                boolean first = true;
                while (rs.next()) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('{');
                    for (int i = 1; i <= md.getColumnCount(); i++) {
                        if (i > 1) sb.append(',');
                        Object v = rs.getObject(i);
                        sb.append(q(md.getColumnLabel(i))).append(':')
                          .append(v == null ? "null" : v instanceof Number ? v.toString() : q(v.toString()));
                    }
                    sb.append('}');
                }
                return sb.append(']').toString();
            }
        }
    }

    // ---------------------------------------------------------------- security helpers
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    static String pbkdf2(String pw, String salt) {
        try {
            return hex(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(new PBEKeySpec(pw.toCharArray(), salt.getBytes(UTF_8), 65000, 256)).getEncoded());
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static String newHash(String pw) { byte[] s = new byte[16]; RNG.nextBytes(s); String salt = hex(s); return salt + ":" + pbkdf2(pw, salt); }

    /** Supports new salted PBKDF2 hashes and legacy plain SHA-256 hashes from the Swing version. */
    static boolean verify(String pw, String stored) {
        try {
            if (stored.contains(":")) {
                String[] p = stored.split(":");
                return MessageDigest.isEqual(pbkdf2(pw, p[0]).getBytes(UTF_8), p[1].getBytes(UTF_8));
            }
            return MessageDigest.isEqual(hex(MessageDigest.getInstance("SHA-256").digest(pw.getBytes(UTF_8))).getBytes(UTF_8), stored.getBytes(UTF_8));
        } catch (Exception e) { return false; }
    }

    static void lockCheck(String k) {
        long[] f = fails.get(k);
        if (f == null) return;
        if (System.currentTimeMillis() - f[1] >= 300000) { fails.remove(k); return; }
        if (f[0] >= 5) throw new ApiError(429, "Too many failed attempts. Try again in 5 minutes.");
    }
    static void fail(String k) {
        fails.compute(k, (x, v) -> { if (v == null) return new long[]{1, System.currentTimeMillis()}; v[0]++; v[1] = System.currentTimeMillis(); return v; });
    }

    // ---------------------------------------------------------------- http plumbing
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c < 32) b.append(' ');
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("X-Content-Type-Options", "nosniff");
        h.set("X-Frame-Options", "DENY");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'");
        h.set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        ex.close();
    }
    static void json(HttpExchange ex, int code, String body) throws IOException { send(ex, code, "application/json; charset=utf-8", body.getBytes(UTF_8)); }

    static void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        try {
            if (path.equals("/api/export")) exportCsv(ex);
            else if (path.startsWith("/api/")) json(ex, 200, route(ex, ex.getRequestMethod() + " " + path.substring(5)));
            else serveStatic(ex, path);
        } catch (ApiError e) {
            json(ex, e.code, "{\"error\":" + q(e.getMessage()) + "}");
        } catch (Exception e) {
            e.printStackTrace();
            json(ex, 500, "{\"error\":\"Server error. Check that MySQL is running.\"}");
        }
    }

    static void serveStatic(HttpExchange ex, String path) throws IOException {
        if (path.equals("/") || path.equals("/index.html")) send(ex, 200, "text/html; charset=utf-8", INDEX_HTML.getBytes(UTF_8));
        else if (path.equals("/style.css")) send(ex, 200, "text/css; charset=utf-8", STYLE_CSS.getBytes(UTF_8));
        else if (path.equals("/app.js")) send(ex, 200, "text/javascript; charset=utf-8", APP_JS.getBytes(UTF_8));
        else send(ex, 404, "text/plain", "Not found".getBytes(UTF_8));
    }

    static void parse(String s, Map<String, String> m) {
        for (String kv : s.split("&")) {
            if (kv.isEmpty()) continue;
            int i = kv.indexOf('=');
            try {
                m.put(URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), "UTF-8"), i < 0 ? "" : URLDecoder.decode(kv.substring(i + 1), "UTF-8"));
            } catch (UnsupportedEncodingException e) { throw new RuntimeException(e); }
        }
    }

    static Session session(HttpExchange ex) {
        String ck = ex.getRequestHeaders().getFirst("Cookie");
        if (ck == null) return null;
        for (String p : ck.split(";")) {
            p = p.trim();
            if (p.startsWith("sid=")) return sessions.get(p.substring(4));
        }
        return null;
    }
    static Session need(Session s, String role) {
        if (s == null) throw new ApiError(401, "Please sign in first.");
        if (!s.role().equals(role)) throw new ApiError(403, "Not allowed for your account.");
        return s;
    }

    // ---------------------------------------------------------------- API routes
    static String route(HttpExchange ex, String key) throws Exception {
        Map<String, String> f = new HashMap<>();
        String rq = ex.getRequestURI().getRawQuery();
        if (rq != null) parse(rq, f);
        if (ex.getRequestMethod().equals("POST")) {
            if (!"smartbank".equals(ex.getRequestHeaders().getFirst("X-Requested-With"))) throw new ApiError(403, "Bad request origin.");
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = ex.getRequestBody().read(buf)) > 0 && bo.size() < 65536) bo.write(buf, 0, n);
            parse(new String(bo.toByteArray(), UTF_8), f);
        }
        Session s = session(ex);

        switch (key) {
            // ---- public
            case "GET me":
                return s == null ? "{\"role\":null}" : "{\"role\":" + q(s.role()) + ",\"name\":" + q(s.name()) + "}";

            case "GET display":
                return "{\"notice\":" + q(notice) + ",\"open\":" + queueOpen + ",\"calling\":" + rows("SELECT t.token_number token, co.counter_name counter, t.status, t.service FROM tokens t JOIN counters co ON t.counter_id=co.id WHERE t.status IN ('CALLED','SERVING') ORDER BY t.called_at DESC LIMIT 8")
                     + ",\"waiting\":" + rows("SELECT service, COUNT(*) n FROM tokens WHERE status='WAITING' GROUP BY service") + "}";

            case "POST register": {
                String name = f.getOrDefault("name", "").trim(), phone = f.getOrDefault("phone", "").trim(),
                       email = f.getOrDefault("email", "").trim().toLowerCase(), pw = f.getOrDefault("password", "");
                if (name.isEmpty() || name.length() > 100) throw new ApiError(400, "Enter your full name.");
                if (!phone.matches("[0-9]{10}")) throw new ApiError(400, "Phone must be 10 digits.");
                if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) throw new ApiError(400, "Enter a valid email.");
                if (pw.length() < 8) throw new ApiError(400, "Password needs at least 8 characters.");
                try { exec("INSERT INTO customers (name,phone,email,password_hash) VALUES (?,?,?,?)", name, phone, email, newHash(pw)); }
                catch (SQLIntegrityConstraintViolationException e) { throw new ApiError(409, "That email is already registered. Sign in instead."); }
                return "{\"ok\":true}";
            }

            case "POST login": {
                String role = f.getOrDefault("role", "customer"), id = f.getOrDefault("id", "").trim(), pw = f.getOrDefault("password", "");
                String lk = ex.getRemoteAddress().getAddress().getHostAddress() + "|" + id.toLowerCase();
                lockCheck(lk);
                Session ns = null;
                if (role.equals("staff")) {
                    String[] r = row("SELECT id,password_hash,username FROM users WHERE username=?", id);
                    if (r != null && verify(pw, r[1])) ns = new Session("staff", Integer.parseInt(r[0]), r[2]);
                } else {
                    String[] r = row("SELECT id,password_hash,name FROM customers WHERE email=?", id.toLowerCase());
                    if (r != null && verify(pw, r[1])) ns = new Session("customer", Integer.parseInt(r[0]), r[2]);
                }
                if (ns == null) { fail(lk); throw new ApiError(401, "Wrong email/username or password."); }
                fails.remove(lk);
                if (role.equals("staff")) audit(ns.name(), "Signed in");
                byte[] b = new byte[24]; RNG.nextBytes(b);
                String sid = hex(b);
                sessions.put(sid, ns);
                ex.getResponseHeaders().add("Set-Cookie", "sid=" + sid + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800");
                return "{\"role\":" + q(ns.role()) + ",\"name\":" + q(ns.name()) + "}";
            }

            case "POST logout": {
                String ck = ex.getRequestHeaders().getFirst("Cookie");
                if (ck != null) for (String p : ck.split(";")) if (p.trim().startsWith("sid=")) sessions.remove(p.trim().substring(4));
                ex.getResponseHeaders().add("Set-Cookie", "sid=; Path=/; Max-Age=0");
                return "{\"ok\":true}";
            }

            // ---- customer
            case "POST token": {
                need(s, "customer");
                if (!queueOpen) throw new ApiError(423, "Token issue is paused right now. Please ask at the counter.");
                String svc = f.getOrDefault("service", ""), pri = "Priority".equals(f.get("priority")) ? "Priority" : "Normal";
                String prefix = PREFIX.get(svc);
                if (prefix == null) throw new ApiError(400, "Choose a service.");
                try (Connection c = db()) {
                    c.setAutoCommit(false);
                    if (num(c, "SELECT COUNT(*) FROM tokens WHERE customer_id=? AND service=? AND status IN ('WAITING','CALLED','SERVING')", s.id(), svc) > 0)
                        throw new ApiError(409, "You already have an active token for " + svc + ".");
                    int ahead = num(c, "SELECT COUNT(*) FROM tokens WHERE service=? AND status='WAITING'" + (pri.equals("Priority") ? " AND priority='Priority'" : ""), svc);
                    int id;
                    try (PreparedStatement ps = c.prepareStatement("INSERT INTO tokens (token_number,customer_id,service,priority,status,waiting_time) VALUES (?,?,?,?,'WAITING',?)", Statement.RETURN_GENERATED_KEYS)) {
                        ps.setString(1, "T" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
                        ps.setInt(2, s.id()); ps.setString(3, svc); ps.setString(4, pri); ps.setInt(5, ahead * num(c, AVG_SVC));
                        ps.executeUpdate();
                        try (ResultSet k = ps.getGeneratedKeys()) { k.next(); id = k.getInt(1); }
                    }
                    String tok = prefix + String.format("%03d", id);
                    exec(c, "UPDATE tokens SET token_number=? WHERE id=?", tok, id);
                    c.commit();
                    return "{\"token\":" + q(tok) + ",\"position\":" + (ahead + 1) + ",\"wait\":" + (ahead * num(c, AVG_SVC)) + "}";
                }
            }

            case "GET my-tokens":
                need(s, "customer");
                return rows("SELECT t.id, t.token_number token, t.service, t.priority, t.status, co.counter_name counter, t.created_at created, "
                        + "(SELECT COUNT(*) FROM tokens x WHERE x.service=t.service AND x.status='WAITING' AND ((x.priority='Priority' AND t.priority<>'Priority') OR (x.priority=t.priority AND x.id<t.id)))+1 pos, (SELECT rating FROM feedback f WHERE f.token_id=t.id) rating, (" + AVG_SVC + ") avgmin "
                        + "FROM tokens t LEFT JOIN counters co ON t.counter_id=co.id WHERE t.customer_id=? ORDER BY t.id DESC LIMIT 50", s.id());

            case "POST cancel":
                need(s, "customer");
                if (exec("UPDATE tokens SET status='CANCELLED' WHERE id=? AND customer_id=? AND status='WAITING'", f.get("id"), s.id()) == 0)
                    throw new ApiError(409, "Only waiting tokens can be cancelled.");
                return "{\"ok\":true}";

            // ---- staff
            case "GET stats":
                need(s, "staff");
                return rows("SELECT COALESCE(SUM(status='WAITING'),0) waiting, COALESCE(SUM(status='CALLED'),0) called, COALESCE(SUM(status='SERVING'),0) serving, "
                        + "COALESCE(SUM(status='COMPLETED'),0) completed, COALESCE(SUM(status IN ('SKIPPED','CANCELLED')),0) dropped, "
                        + "COALESCE(ROUND(AVG(TIMESTAMPDIFF(MINUTE,created_at,called_at)),1),0) avgwait FROM tokens WHERE DATE(created_at)=CURDATE()");

            case "GET queue":
                need(s, "staff");
                return rows("SELECT t.id, t.token_number token, c.name customer, c.phone, t.service, t.priority, t.status, COALESCE(co.counter_name,'-') counter, t.created_at created "
                        + "FROM tokens t JOIN customers c ON t.customer_id=c.id LEFT JOIN counters co ON t.counter_id=co.id "
                        + "WHERE t.status IN ('WAITING','CALLED','SERVING') ORDER BY (t.status='WAITING'), (t.priority='Priority') DESC, t.id");

            case "POST call": {
                need(s, "staff");
                try (Connection c = db()) {
                    c.setAutoCommit(false);
                    int cid = Integer.parseInt(f.getOrDefault("counterId", "0"));
                    String[] co = row(c, "SELECT service,status FROM counters WHERE id=? FOR UPDATE", cid);
                    if (co == null || !co[1].equals("AVAILABLE")) throw new ApiError(409, "That counter is not available.");
                    String[] t = row(c, "SELECT id,token_number FROM tokens WHERE status='WAITING' AND service=? ORDER BY (priority='Priority') DESC, id LIMIT 1 FOR UPDATE", co[0]);
                    if (t == null) throw new ApiError(404, "Nobody is waiting for " + co[0] + ".");
                    exec(c, "UPDATE tokens SET status='CALLED',counter_id=?,called_at=NOW() WHERE id=?", cid, t[0]);
                    exec(c, "UPDATE counters SET status='BUSY' WHERE id=?", cid);
                    c.commit();
                    audit(s.name(), "Called " + t[1] + " to counter " + cid);
                    return "{\"token\":" + q(t[1]) + "}";
                }
            }

            case "POST status": {
                need(s, "staff");
                String ns = f.getOrDefault("status", "");
                String[] t = row("SELECT status,counter_id FROM tokens WHERE id=?", f.get("id"));
                if (t == null) throw new ApiError(404, "Token not found.");
                boolean ok = (t[0].equals("CALLED") && (ns.equals("SERVING") || ns.equals("SKIPPED")))
                          || (t[0].equals("SERVING") && ns.equals("COMPLETED"))
                          || (t[0].equals("WAITING") && ns.equals("SKIPPED"));
                if (!ok) throw new ApiError(409, "Can't move a " + t[0].toLowerCase() + " token to " + ns.toLowerCase() + ".");
                exec(ns.equals("COMPLETED") ? "UPDATE tokens SET status=?,completed_at=NOW() WHERE id=?" : "UPDATE tokens SET status=? WHERE id=?", ns, f.get("id"));
                audit(s.name(), "Token " + f.get("id") + " marked " + ns.toLowerCase());
                if ((ns.equals("COMPLETED") || ns.equals("SKIPPED")) && t[1] != null)
                    exec("UPDATE counters SET status='AVAILABLE' WHERE id=? AND status='BUSY'", t[1]);
                return "{\"ok\":true}";
            }

            case "GET history": {
                need(s, "staff");
                String k = f.getOrDefault("q", "").trim();
                String base = "SELECT t.token_number token, c.name customer, c.phone, t.service, t.priority, t.status, t.waiting_time wait, t.created_at created FROM tokens t JOIN customers c ON t.customer_id=c.id ";
                return k.isEmpty() ? rows(base + "ORDER BY t.id DESC LIMIT 300")
                        : rows(base + "WHERE t.token_number LIKE ? OR c.name LIKE ? OR c.phone LIKE ? ORDER BY t.id DESC LIMIT 300", "%" + k + "%", "%" + k + "%", "%" + k + "%");
            }

            case "GET counters":
                need(s, "staff");
                return rows("SELECT id, counter_name name, service, status FROM counters ORDER BY id");

            case "POST counter":
                need(s, "staff");
                if (!Arrays.asList("AVAILABLE", "OFFLINE").contains(f.get("status"))) throw new ApiError(400, "Bad status.");
                if (exec("UPDATE counters SET status=? WHERE id=? AND status<>'BUSY'", f.get("status"), f.get("id")) == 0)
                    throw new ApiError(409, "A busy counter can't be changed. Finish its token first.");
                audit(s.name(), "Counter " + f.get("id") + " set " + f.get("status"));
                return "{\"ok\":true}";

            case "POST add-counter": {
                need(s, "staff");
                String n = f.getOrDefault("name", "").trim();
                if (n.isEmpty() || n.length() > 50 || !PREFIX.containsKey(f.get("service"))) throw new ApiError(400, "Enter a name and pick a service.");
                exec("INSERT INTO counters (counter_name,service,status) VALUES (?,?,'AVAILABLE')", n, f.get("service"));
                return "{\"ok\":true}";
            }

            case "POST rate": {
                need(s, "customer");
                int r = Integer.parseInt(f.getOrDefault("rating", "0"));
                if (r < 1 || r > 5) throw new ApiError(400, "Pick 1 to 5 stars.");
                if (row("SELECT id FROM tokens WHERE id=? AND customer_id=? AND status='COMPLETED'", f.get("id"), s.id()) == null)
                    throw new ApiError(409, "You can rate completed tokens only.");
                try { exec("INSERT INTO feedback (token_id,rating) VALUES (?,?)", f.get("id"), r); }
                catch (SQLIntegrityConstraintViolationException e) { throw new ApiError(409, "You already rated this token."); }
                return "{\"ok\":true}";
            }

            case "POST password": {
                if (s == null) throw new ApiError(401, "Please sign in first.");
                String nw = f.getOrDefault("password", "");
                if (nw.length() < 8) throw new ApiError(400, "New password needs at least 8 characters.");
                String tbl = s.role().equals("staff") ? "users" : "customers";
                String[] r = row("SELECT password_hash FROM " + tbl + " WHERE id=?", s.id());
                if (r == null || !verify(f.getOrDefault("current", ""), r[0])) throw new ApiError(401, "Current password is wrong.");
                exec("UPDATE " + tbl + " SET password_hash=? WHERE id=?", newHash(nw), s.id());
                if (s.role().equals("staff")) audit(s.name(), "Changed own password");
                return "{\"ok\":true}";
            }

            case "POST add-staff": {
                need(s, "staff");
                String u = f.getOrDefault("username", "").trim(), pw = f.getOrDefault("password", "");
                if (!u.matches("[A-Za-z0-9_.-]{3,50}")) throw new ApiError(400, "Username: 3-50 letters, numbers, . _ -");
                if (pw.length() < 8) throw new ApiError(400, "Password needs at least 8 characters.");
                try { exec("INSERT INTO users (username,password_hash) VALUES (?,?)", u, newHash(pw)); }
                catch (SQLIntegrityConstraintViolationException e) { throw new ApiError(409, "That username already exists."); }
                audit(s.name(), "Created staff account " + u);
                return "{\"ok\":true}";
            }

            case "GET insights":
                need(s, "staff");
                return "{\"services\":" + rows("SELECT service, COUNT(*) total, COALESCE(SUM(status='COMPLETED'),0) done, COALESCE(ROUND(AVG(TIMESTAMPDIFF(MINUTE,created_at,called_at)),1),0) avgwait FROM tokens WHERE DATE(created_at)=CURDATE() GROUP BY service")
                     + ",\"hours\":" + rows("SELECT HOUR(created_at) h, COUNT(*) n FROM tokens WHERE DATE(created_at)=CURDATE() GROUP BY HOUR(created_at) ORDER BY h")
                     + ",\"days\":" + rows("SELECT DATE(created_at) d, COUNT(*) n FROM tokens WHERE created_at >= CURDATE() - INTERVAL 6 DAY GROUP BY DATE(created_at) ORDER BY d")
                     + ",\"svc\":" + rows("SELECT COALESCE(ROUND(AVG(TIMESTAMPDIFF(MINUTE,called_at,completed_at)),1),0) m FROM tokens WHERE status='COMPLETED'")
                     + ",\"rating\":" + rows("SELECT COALESCE(ROUND(AVG(rating),1),0) score, COUNT(*) n FROM feedback") + "}";

            case "GET audit":
                need(s, "staff");
                return rows("SELECT actor, action, created_at created FROM audit_log ORDER BY id DESC LIMIT 100");

            case "GET notice":
                return "{\"notice\":" + q(notice) + ",\"open\":" + queueOpen + "}";

            case "POST admin-settings": {
                need(s, "staff");
                String nt = f.getOrDefault("notice", "").trim();
                if (nt.length() > 200) nt = nt.substring(0, 200);
                notice = nt;
                queueOpen = !"0".equals(f.get("open"));
                audit(s.name(), (queueOpen ? "Resumed" : "Paused") + " token issue; notice " + (nt.isEmpty() ? "cleared" : "updated"));
                return "{\"ok\":true}";
            }

            default:
                throw new ApiError(404, "Unknown endpoint.");
        }
    }

    // ---------------------------------------------------------------- embedded web files
    static final String INDEX_HTML =
        "<!doctype html>\n" +
        "<html lang=\"en\">\n" +
        "<head>\n" +
        "<meta charset=\"utf-8\">\n" +
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
        "<title>SmartBank - Skip the line</title>\n" +
        "<link rel=\"stylesheet\" href=\"/style.css\">\n" +
        "</head>\n" +
        "<body>\n" +
        "<div id=\"app\"></div>\n" +
        "<script src=\"/app.js\"></script>\n" +
        "</body>\n" +
        "</html>\n" +
        "";

    static final String STYLE_CSS =
        ":root{--bg:#f5f7fa;--ink:#0f2038;--card:#fff;--line:#e2e7ee;--mute:#66758a;--hot:#1a56db;--hot-d:#1445b3;--ok:#0e8a5f;\n" +
        "--font:\"Segoe UI\",\"Helvetica Neue\",Arial,sans-serif}\n" +
        "*{box-sizing:border-box}\n" +
        "body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 var(--font)}\n" +
        "h1,h2,h3{margin:0;line-height:1.15;letter-spacing:-.02em;font-weight:700}\n" +
        "h1{font-size:clamp(2.4rem,6vw,4.2rem);font-weight:800;letter-spacing:-.035em}\n" +
        "h2{font-size:1.35rem}\n" +
        "h3{font-size:1.05rem}\n" +
        "a{color:inherit}\n" +
        ":focus-visible{outline:3px solid #9db8f5;outline-offset:2px}\n" +
        ".wrap{max-width:1160px;margin:0 auto;padding:0 24px}\n" +
        "header.top{background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}\n" +
        "header.top .wrap{display:flex;align-items:center;gap:20px;height:60px}\n" +
        ".brand{font-weight:800;font-size:1.15rem;letter-spacing:-.02em;text-decoration:none;color:var(--hot)}\n" +
        ".grow{flex:1}\n" +
        ".who{color:var(--mute);font-size:.88rem;text-decoration:none}\n" +
        "nav.tabs{display:flex;gap:2px;margin-left:12px;overflow-x:auto}\n" +
        "nav.tabs button{background:none;border:0;color:var(--mute);font:inherit;font-weight:600;padding:19px 12px 17px;cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}\n" +
        "nav.tabs button:hover{color:var(--ink)}\n" +
        "nav.tabs button.on{color:var(--hot);border-color:var(--hot)}\n" +
        ".btn{display:inline-block;background:var(--hot);color:#fff;border:0;border-radius:8px;font:inherit;font-weight:600;padding:10px 20px;cursor:pointer;text-decoration:none;transition:background .15s}\n" +
        ".btn:hover{background:var(--hot-d)}\n" +
        ".btn.alt{background:var(--ink)}\n" +
        ".btn.ghost{background:#fff;color:var(--ink);box-shadow:inset 0 0 0 1px var(--line)}\n" +
        ".btn.ghost:hover{background:var(--bg)}\n" +
        ".btn.ok{background:var(--ok)}\n" +
        ".btn.sm{padding:6px 12px;font-size:.85rem}\n" +
        ".row{display:flex;flex-wrap:wrap;gap:12px;align-items:center}\n" +
        ".hero{padding:clamp(48px,9vw,110px) 0 72px}\n" +
        ".hero p{max-width:32rem;font-size:1.15rem;color:var(--mute);margin:22px 0 32px}\n" +
        ".card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:26px}\n" +
        ".auth{max-width:420px;margin:56px auto}\n" +
        ".auth h2{margin-bottom:8px}\n" +
        "label{display:block;font-weight:600;font-size:.85rem;margin:16px 0 6px}\n" +
        "input,select{width:100%;font:inherit;padding:10px 12px;border:1px solid #cdd5df;border-radius:8px;background:#fff;color:var(--ink)}\n" +
        "input:focus,select:focus{border-color:var(--hot);outline:3px solid #dbe6fd}\n" +
        ".auth .btn{width:100%;margin-top:24px}\n" +
        ".auth .sub{margin-top:18px;color:var(--mute)}\n" +
        ".radios{display:flex;gap:10px}\n" +
        ".radios label{flex:1;margin:0;border:1px solid #cdd5df;border-radius:8px;padding:10px 12px;cursor:pointer;font-weight:600}\n" +
        ".radios input{width:auto;margin-right:8px}\n" +
        ".radios label:has(input:checked){border-color:var(--hot);background:#eef3fe}\n" +
        ".grid2{display:grid;grid-template-columns:5fr 7fr;gap:24px;margin:32px 0}\n" +
        ".two{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin:24px 0}\n" +
        "@media(max-width:820px){.grid2,.two{grid-template-columns:1fr}}\n" +
        ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin:28px 0 20px}\n" +
        ".stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}\n" +
        ".stat b{display:block;font-size:2rem;font-weight:800;letter-spacing:-.03em;line-height:1.1}\n" +
        ".stat span{color:var(--mute);font-size:.85rem}\n" +
        ".ticket{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:14px;background:#fff}\n" +
        ".ticket.call{background:var(--hot);color:#fff;border-color:var(--hot)}\n" +
        ".ticket .num{font-size:3rem;font-weight:800;letter-spacing:-.04em;line-height:1.05}\n" +
        ".ticket .meta{display:flex;justify-content:space-between;align-items:end;gap:12px}\n" +
        ".badge{display:inline-block;font-weight:600;font-size:.78rem;padding:2px 10px;border-radius:99px;background:var(--line);text-transform:capitalize}\n" +
        ".WAITING{background:#fff1cc;color:#7a5200}.CALLED{background:var(--hot);color:#fff}.SERVING{background:#dbe8ff;color:#12378a}.COMPLETED{background:#d4f3e5;color:#075c3f}.SKIPPED,.CANCELLED{background:#e8ebef;color:var(--mute)}\n" +
        ".AVAILABLE{background:#d4f3e5;color:#075c3f}.BUSY{background:#fff1cc;color:#7a5200}.OFFLINE{background:#e8ebef;color:var(--mute)}\n" +
        "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:12px;overflow:hidden}\n" +
        "th{text-align:left;font-size:.8rem;font-weight:600;color:var(--mute);padding:10px 14px;background:#fafbfc;border-bottom:1px solid var(--line)}\n" +
        "td{padding:11px 14px;border-bottom:1px solid #eef1f5}\n" +
        "tr:last-child td{border-bottom:0}\n" +
        "tr:hover td{background:#f7f9fc}\n" +
        "tr[data-act=pick]{cursor:pointer}\n" +
        "tr.sel td{background:#e4edff}\n" +
        ".tblwrap{overflow-x:auto;border-radius:12px}\n" +
        ".bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0}\n" +
        ".bar select{width:auto;min-width:230px}\n" +
        ".chips{display:flex;gap:8px;flex-wrap:wrap}\n" +
        ".chip{border:1px solid var(--line);background:#fff;border-radius:99px;padding:5px 14px;font:inherit;font-size:.85rem;font-weight:600;cursor:pointer;color:var(--mute)}\n" +
        ".chip.on{background:var(--ink);color:#fff;border-color:var(--ink)}\n" +
        ".notice{background:#eef3fe;border:1px solid #c9d9fb;color:#12378a;border-radius:10px;padding:12px 16px;margin-bottom:16px}\n" +
        ".empty{padding:26px;color:var(--mute);text-align:center}\n" +
        ".toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--ink);color:#fff;padding:11px 20px;border-radius:8px;font-weight:600;z-index:9;box-shadow:0 8px 24px rgba(15,32,56,.25)}\n" +
        ".toast.bad{background:#c62828}\n" +
        "main{padding-bottom:56px}\n" +
        ".card h3{margin-bottom:12px}\n" +
        ".hbars{display:flex;align-items:end;gap:10px;height:170px;padding-top:8px}\n" +
        ".hbars div{flex:1;display:flex;flex-direction:column;justify-content:end;align-items:center;height:100%;font-size:.78rem;color:var(--mute)}\n" +
        ".hbars i{display:block;width:100%;max-width:36px;background:var(--hot);border-radius:4px 4px 0 0;min-height:3px}\n" +
        ".hbars b{color:var(--ink)}\n" +
        ".star{background:none;border:0;color:#d99a00;font-size:1.25rem;cursor:pointer;padding:0 1px}\n" +
        ".star:hover{transform:scale(1.2)}\n" +
        ".foot{color:var(--mute);font-size:.82rem;padding:24px;border-top:1px solid var(--line)}\n" +
        "body.board{background:#0f2038;color:#fff}\n" +
        ".board .wrap{max-width:1400px}\n" +
        ".board h1{font-size:clamp(2rem,5vw,3.2rem);margin:32px 0}\n" +
        ".board .brand{color:#fff}\n" +
        ".board .notice{background:#1c3358;border-color:#2c4b7c;color:#dbe8ff;font-size:1.2rem}\n" +
        ".calls{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px}\n" +
        ".calls div{background:#17294a;border-radius:14px;padding:24px}\n" +
        ".calls .n{font-size:clamp(4rem,10vw,6.5rem);font-weight:800;letter-spacing:-.04em;line-height:1}\n" +
        ".calls .n.hot{color:#7fb0ff}\n" +
        ".calls small{color:#9fb0c8;font-size:1.1rem}\n" +
        ".queue-sum{display:flex;gap:32px;flex-wrap:wrap;margin:32px 0;color:#9fb0c8;font-size:1.1rem}\n" +
        ".queue-sum b{color:#fff;font-size:1.7rem}\n" +
        "@media(prefers-reduced-motion:no-preference){.ticket.call{animation:pulse 1.6s ease-in-out 3}}\n" +
        "@keyframes pulse{50%{transform:scale(1.015)}}\n" +
        "";

    static final String APP_JS =
        "const app = document.getElementById('app');\n" +
        "const SERVICES = ['Account Service', 'Cash Service', 'Loan Service'];\n" +
        "let qf = '', me = null, timer = null, staffTab = 'queue', selected = null, counterPick = '', prevStatus = {}, sound = false, lastCalled = '';\n" +
        "\n" +
        "const esc = s => String(s ?? '').replace(/[&<>\"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));\n" +
        "const when = s => s ? String(s).replace('T', ' ').slice(0, 16) : '-';\n" +
        "const badge = s => `<span class=\"badge ${esc(s)}\">${esc(s.toLowerCase())}</span>`;\n" +
        "\n" +
        "async function api(path, data) {\n" +
        "  const o = { credentials: 'same-origin' };\n" +
        "  if (data) {\n" +
        "    o.method = 'POST';\n" +
        "    o.headers = { 'X-Requested-With': 'smartbank' };\n" +
        "    o.body = new URLSearchParams(data);\n" +
        "  }\n" +
        "  const r = await fetch('/api/' + path, o);\n" +
        "  const j = await r.json().catch(() => ({}));\n" +
        "  if (!r.ok) throw new Error(j.error || 'Something went wrong.');\n" +
        "  return j;\n" +
        "}\n" +
        "function toast(m, bad) {\n" +
        "  const t = document.createElement('div');\n" +
        "  t.className = 'toast' + (bad ? ' bad' : '');\n" +
        "  t.textContent = m;\n" +
        "  document.body.append(t);\n" +
        "  setTimeout(() => t.remove(), 3500);\n" +
        "}\n" +
        "const safe = fn => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };\n" +
        "function poll(fn, ms) { fn(); timer = setInterval(fn, ms); }\n" +
        "\n" +
        "// ---------------------------------------------------------------- routing\n" +
        "async function boot() { try { me = await api('me'); } catch { me = { role: null }; } route(); }\n" +
        "function route() {\n" +
        "  clearInterval(timer);\n" +
        "  document.body.className = '';\n" +
        "  const h = location.hash.slice(1);\n" +
        "  if (h === 'board') return board();\n" +
        "  if (me && me.role) return me.role === 'staff' ? staff() : customer();\n" +
        "  if (['staff', 'customer', 'register'].includes(h)) return auth(h);\n" +
        "  landing();\n" +
        "}\n" +
        "addEventListener('hashchange', route);\n" +
        "\n" +
        "function shell(inner, nav = '') {\n" +
        "  const user = me && me.role\n" +
        "    ? `<span class=\"who\">${esc(me.name)}</span><button class=\"btn ghost sm\" data-act=\"logout\">Sign out</button>` : '';\n" +
        "  app.innerHTML = `<header class=\"top\"><div class=\"wrap\"><a class=\"brand\" href=\"#\">SmartBank</a>${nav}<span class=\"grow\"></span>\n" +
        "    <a class=\"who\" href=\"#board\">Live board</a>${user}</div></header><main class=\"wrap\">${inner}</main><footer class=\"foot wrap\">SmartBank Token System. Sessions are secured and staff actions are logged.</footer>`;\n" +
        "}\n" +
        "\n" +
        "// ---------------------------------------------------------------- landing + auth\n" +
        "function landing() {\n" +
        "  shell(`<section class=\"hero\"><h1>Skip the line.<br>Keep the service.</h1>\n" +
        "    <p>Take a token from your phone, watch your turn move up, and walk to the counter when it's called.</p>\n" +
        "    <div class=\"row\"><a class=\"btn\" href=\"#customer\">Get a token</a><a class=\"btn alt\" href=\"#staff\">Staff sign in</a>\n" +
        "    <a class=\"btn ghost\" href=\"#register\">Create account</a></div></section>`);\n" +
        "}\n" +
        "\n" +
        "function auth(mode) {\n" +
        "  const f = {\n" +
        "    customer: ['Customer sign in', 'Email', 'email', 'Sign in'],\n" +
        "    staff: ['Staff sign in', 'Username', 'text', 'Sign in'],\n" +
        "  }[mode];\n" +
        "  const body = mode === 'register'\n" +
        "    ? `<h2>Create your account</h2>\n" +
        "       <label for=\"name\">Full name</label><input id=\"name\" name=\"name\" autocomplete=\"name\" required>\n" +
        "       <label for=\"phone\">Phone (10 digits)</label><input id=\"phone\" name=\"phone\" inputmode=\"numeric\" maxlength=\"10\" required>\n" +
        "       <label for=\"email\">Email</label><input id=\"email\" name=\"email\" type=\"email\" autocomplete=\"email\" required>\n" +
        "       <label for=\"password\">Password (8+ characters)</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"new-password\" minlength=\"8\" required>\n" +
        "       <button class=\"btn\">Create account</button><p class=\"sub\">Have an account? <a href=\"#customer\">Sign in</a></p>`\n" +
        "    : `<h2>${f[0]}</h2>\n" +
        "       <label for=\"id\">${f[1]}</label><input id=\"id\" name=\"id\" type=\"${f[2]}\" autocomplete=\"username\" required>\n" +
        "       <label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>\n" +
        "       <button class=\"btn\">${f[3]}</button>\n" +
        "       <p class=\"sub\">${mode === 'customer' ? 'New here? <a href=\"#register\">Create an account</a>' : 'Customer? <a href=\"#customer\">Sign in here</a>'}</p>`;\n" +
        "  shell(`<form class=\"card auth\" id=\"authForm\">${body}</form>`);\n" +
        "  document.getElementById('authForm').onsubmit = safe(async e => {\n" +
        "    e.preventDefault();\n" +
        "    const d = Object.fromEntries(new FormData(e.target));\n" +
        "    if (mode === 'register') {\n" +
        "      await api('register', d);\n" +
        "      toast('Account created. Sign in to continue.');\n" +
        "      location.hash = 'customer';\n" +
        "    } else {\n" +
        "      me = await api('login', { ...d, role: mode });\n" +
        "      location.hash = '';\n" +
        "      route();\n" +
        "    }\n" +
        "  });\n" +
        "}\n" +
        "\n" +
        "const banner = n => (n.notice || !n.open) ? `<div class=\"notice\">${n.open ? '' : '<b>Token issue is paused.</b> '}${esc(n.notice)}</div>` : '';\n" +
        "const trend = days => { const m = Math.max(1, ...days.map(x => x.n)); return days.length ? `<div class=\"hbars\">${days.map(x => `<div><b>${x.n}</b><i style=\"height:${x.n / m * 100}%\"></i><span>${x.d.slice(5)}</span></div>`).join('')}</div>` : '<p class=\"empty\">No data yet.</p>'; };\n" +
        "const rating = t => t.status !== 'COMPLETED' ? '-' : t.rating ? '&#9733;'.repeat(t.rating)\n" +
        "  : [1, 2, 3, 4, 5].map(n => `<button class=\"star\" data-act=\"rate\" data-id=\"${t.id}\" data-r=\"${n}\" aria-label=\"Rate ${n} of 5\">&#9734;</button>`).join('');\n" +
        "const pwCard = () => `<form class=\"card\" id=\"pwForm\" style=\"max-width:440px;margin-bottom:24px\"><h3>Change password</h3>\n" +
        "  <label for=\"cur\">Current password</label><input id=\"cur\" name=\"current\" type=\"password\" autocomplete=\"current-password\" required>\n" +
        "  <label for=\"npw\">New password (8+ characters)</label><input id=\"npw\" name=\"password\" type=\"password\" autocomplete=\"new-password\" minlength=\"8\" required>\n" +
        "  <button class=\"btn\" style=\"margin-top:18px\">Update password</button></form>`;\n" +
        "function bindPw() {\n" +
        "  const f = document.getElementById('pwForm');\n" +
        "  if (f) f.onsubmit = safe(async e => { e.preventDefault(); await api('password', Object.fromEntries(new FormData(f))); f.reset(); toast('Password updated.'); });\n" +
        "}\n" +
        "\n" +
        "// ---------------------------------------------------------------- customer\n" +
        "function customer() {\n" +
        "  shell(`<div class=\"grid2\"><form class=\"card\" id=\"tokForm\"><h2>Get a token</h2>\n" +
        "    <label for=\"service\">Service</label><select id=\"service\" name=\"service\">${SERVICES.map(s => `<option>${s}</option>`).join('')}</select>\n" +
        "    <label>Queue</label><div class=\"radios\"><label><input type=\"radio\" name=\"priority\" value=\"Normal\" checked>Normal</label>\n" +
        "    <label><input type=\"radio\" name=\"priority\" value=\"Priority\">Priority</label></div>\n" +
        "    <p style=\"color:var(--mute);font-size:.9rem\">Priority is for seniors, pregnant customers and customers with disabilities.</p>\n" +
        "    <button class=\"btn\" style=\"width:100%\">Take token</button></form>\n" +
        "    <section><h2 style=\"margin-bottom:16px\">Your tokens</h2><div id=\"mine\"></div></section></div>${pwCard()}`);\n" +
        "  document.getElementById('tokForm').onsubmit = safe(async e => {\n" +
        "    e.preventDefault();\n" +
        "    const r = await api('token', Object.fromEntries(new FormData(e.target)));\n" +
        "    toast(`Token ${r.token}. ${r.position === 1 ? \"You're next.\" : r.position - 1 + ' ahead of you.'}`);\n" +
        "    loadMine();\n" +
        "  });\n" +
        "  bindPw();\n" +
        "  poll(loadMine, 5000);\n" +
        "}\n" +
        "\n" +
        "const loadMine = safe(async () => {\n" +
        "  const [list, nt] = await Promise.all([api('my-tokens'), api('notice')]), el = document.getElementById('mine');\n" +
        "  if (!el) return;\n" +
        "  list.forEach(t => {\n" +
        "    if (prevStatus[t.id] && prevStatus[t.id] !== 'CALLED' && t.status === 'CALLED') toast(`${t.token} is called. Go to ${t.counter}.`);\n" +
        "    prevStatus[t.id] = t.status;\n" +
        "  });\n" +
        "  const active = list.filter(t => ['WAITING', 'CALLED', 'SERVING'].includes(t.status)), past = list.filter(t => !active.includes(t));\n" +
        "  el.innerHTML = banner(nt) + (active.length ? active.map(t => `<div class=\"ticket ${t.status === 'CALLED' ? 'call' : ''}\"><div class=\"meta\"><div>\n" +
        "      <div>${esc(t.service)}${t.priority === 'Priority' ? ' (priority)' : ''}</div><div class=\"num\">${esc(t.token)}</div></div>\n" +
        "      <div style=\"text-align:right\">${t.status === 'WAITING' ? `<b>${t.pos === 1 ? 'You are next' : t.pos - 1 + ' ahead of you'}</b><br>about ${(t.pos - 1) * (t.avgmin || 5)} min`\n" +
        "        : `<b>${t.status === 'CALLED' ? 'Go to ' + esc(t.counter) + ' now' : 'Being served at ' + esc(t.counter)}</b>`}\n" +
        "      ${t.status === 'WAITING' ? `<br><button class=\"btn sm alt\" style=\"margin-top:8px\" data-act=\"cancel\" data-id=\"${t.id}\">Cancel token</button>` : ''}</div></div></div>`).join('')\n" +
        "    : `<div class=\"card empty\">No active token. Take one to join the queue.</div>`)\n" +
        "    + (past.length ? `<h3 style=\"margin:28px 0 12px\">History</h3><div class=\"tblwrap\"><table><tr><th>Token</th><th>Service</th><th>Status</th><th>Taken</th><th>Your rating</th></tr>${\n" +
        "      past.map(t => `<tr><td>${esc(t.token)}</td><td>${esc(t.service)}</td><td>${badge(t.status)}</td><td>${when(t.created)}</td><td>${rating(t)}</td></tr>`).join('')}</table></div>` : '');\n" +
        "});\n" +
        "\n" +
        "// ---------------------------------------------------------------- staff\n" +
        "function staff() {\n" +
        "  const tabs = [['queue', 'Queue'], ['insights', 'Insights'], ['history', 'History'], ['counters', 'Counters'], ['audit', 'Activity'], ['settings', 'Settings']];\n" +
        "  shell(`<div id=\"body\"></div>`,\n" +
        "    `<nav class=\"tabs\">${tabs.map(([k, l]) => `<button data-act=\"tab\" data-tab=\"${k}\" class=\"${k === staffTab ? 'on' : ''}\">${l}</button>`).join('')}</nav>`);\n" +
        "  poll(renderStaff, 4000);\n" +
        "}\n" +
        "\n" +
        "const renderStaff = safe(async () => {\n" +
        "  const el = document.getElementById('body');\n" +
        "  if (!el) return;\n" +
        "  if (staffTab === 'queue') {\n" +
        "    const [st, qu, co] = await Promise.all([api('stats'), api('queue'), api('counters')]);\n" +
        "    const s = st[0], free = co.filter(c => c.status === 'AVAILABLE'), fq = qu.filter(t => !qf || t.service === qf);\n" +
        "    if (!free.some(c => String(c.id) === counterPick)) counterPick = free[0] ? String(free[0].id) : '';\n" +
        "    el.innerHTML = `<div class=\"stats\">${[['Waiting', s.waiting], ['Called', s.called], ['Serving', s.serving], ['Done today', s.completed], ['Dropped', s.dropped], ['Avg wait (min)', s.avgwait]]\n" +
        "      .map(([l, v]) => `<div class=\"stat\"><b>${v}</b><span>${l}</span></div>`).join('')}</div>\n" +
        "      <div class=\"bar\"><select id=\"cpick\" aria-label=\"Counter\">${free.length ? free.map(c => `<option value=\"${c.id}\" ${String(c.id) === counterPick ? 'selected' : ''}>${esc(c.name)} - ${esc(c.service)}</option>`).join('') : '<option value=\"\">No free counter</option>'}</select>\n" +
        "      <button class=\"btn\" data-act=\"call\">Call next</button>\n" +
        "      <span class=\"grow\"></span>\n" +
        "      <button class=\"btn alt sm\" data-act=\"status\" data-s=\"SERVING\">Start serving</button>\n" +
        "      <button class=\"btn ok sm\" data-act=\"status\" data-s=\"COMPLETED\">Complete</button>\n" +
        "      <button class=\"btn ghost sm\" data-act=\"status\" data-s=\"SKIPPED\">Skip</button></div>\n" +
        "      <div class=\"chips\" style=\"margin-bottom:14px\">${[''].concat(SERVICES).map(v => `<button class=\"chip ${v === qf ? 'on' : ''}\" data-act=\"filter\" data-s=\"${v}\">${v ? v.replace(' Service', '') : 'All services'}</button>`).join('')}</div>\n" +
        "      <div class=\"tblwrap\"><table><tr><th>Token</th><th>Customer</th><th>Phone</th><th>Service</th><th>Queue</th><th>Status</th><th>Counter</th><th>Taken</th></tr>${\n" +
        "      fq.length ? fq.map(t => `<tr data-act=\"pick\" data-id=\"${t.id}\" class=\"${String(t.id) === selected ? 'sel' : ''}\"><td><b>${esc(t.token)}</b></td><td>${esc(t.customer)}</td><td>${esc(t.phone)}</td><td>${esc(t.service)}</td><td>${esc(t.priority)}</td><td>${badge(t.status)}</td><td>${esc(t.counter)}</td><td>${when(t.created)}</td></tr>`).join('')\n" +
        "        : '<tr><td colspan=\"8\" class=\"empty\">Queue is empty.</td></tr>'}</table></div>\n" +
        "      <p style=\"color:var(--mute)\">Select a row, then choose an action.</p>`;\n" +
        "    document.getElementById('cpick').onchange = e => counterPick = e.target.value;\n" +
        "  } else if (staffTab === 'counters') {\n" +
        "    const co = await api('counters');\n" +
        "    el.innerHTML = `<h2 style=\"margin:32px 0 16px\">Counters</h2><div class=\"tblwrap\"><table><tr><th>Name</th><th>Service</th><th>Status</th><th></th></tr>${\n" +
        "      co.map(c => `<tr><td>${esc(c.name)}</td><td>${esc(c.service)}</td><td>${badge(c.status)}</td><td>${\n" +
        "        c.status === 'OFFLINE' ? `<button class=\"btn sm ok\" data-act=\"counter\" data-id=\"${c.id}\" data-s=\"AVAILABLE\">Open</button>`\n" +
        "        : c.status === 'AVAILABLE' ? `<button class=\"btn sm ghost\" data-act=\"counter\" data-id=\"${c.id}\" data-s=\"OFFLINE\">Close</button>` : ''}</td></tr>`).join('')}</table></div>\n" +
        "      <form class=\"bar\" id=\"addc\"><input name=\"name\" placeholder=\"Counter name\" style=\"width:200px\" required>\n" +
        "      <select name=\"service\" style=\"width:auto\">${SERVICES.map(s => `<option>${s}</option>`).join('')}</select><button class=\"btn\">Add counter</button></form>`;\n" +
        "    document.getElementById('addc').onsubmit = safe(async e => { e.preventDefault(); await api('add-counter', Object.fromEntries(new FormData(e.target))); renderStaff(); });\n" +
        "  } else if (staffTab === 'insights') {\n" +
        "    const d = await api('insights'), max = Math.max(1, ...d.hours.map(h => h.n)), rt = d.rating[0];\n" +
        "    el.innerHTML = `<div class=\"stats\"><div class=\"stat\"><b>${rt.score}/5</b><span>Satisfaction from ${rt.n} ratings</span></div><div class=\"stat\"><b>${d.svc[0].m}</b><span>Avg service time (min)</span></div></div>\n" +
        "      <div class=\"two\"><div class=\"card\"><h3>Tokens per hour today</h3>${d.hours.length ? `<div class=\"hbars\">${d.hours.map(h => `<div><b>${h.n}</b><i style=\"height:${h.n / max * 100}%\"></i><span>${h.h}:00</span></div>`).join('')}</div>` : '<p class=\"empty\">No tokens yet today.</p>'}</div>\n" +
        "      <div class=\"card\"><h3>By service today</h3><table><tr><th>Service</th><th>Tokens</th><th>Done</th><th>Avg wait</th></tr>${d.services.map(v => `<tr><td>${esc(v.service)}</td><td>${v.total}</td><td>${v.done}</td><td>${v.avgwait} min</td></tr>`).join('') || '<tr><td colspan=\"4\" class=\"empty\">No data yet.</td></tr>'}</table></div></div><div class=\"card\" style=\"margin-bottom:24px\"><h3>Last 7 days</h3>${trend(d.days)}</div>`;\n" +
        "  } else if (staffTab === 'audit') {\n" +
        "    const a = await api('audit');\n" +
        "    el.innerHTML = `<h2 style=\"margin:32px 0 16px\">Staff activity</h2><div class=\"tblwrap\"><table><tr><th>Time</th><th>Staff</th><th>Action</th></tr>${a.map(x => `<tr><td>${when(x.created)}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td></tr>`).join('') || '<tr><td colspan=\"3\" class=\"empty\">Nothing logged yet.</td></tr>'}</table></div>`;\n" +
        "  } else if (staffTab === 'settings') {\n" +
        "    if (document.getElementById('pwForm')) return;\n" +
        "    const nt = await api('notice');\n" +
        "    el.innerHTML = `<form class=\"card\" id=\"ctlForm\" style=\"margin-top:32px\"><h3>Queue controls</h3><label for=\"nm\">Notice for customers and the lobby board</label><input id=\"nm\" name=\"notice\" maxlength=\"200\" value=\"${esc(nt.notice)}\" placeholder=\"Example: Loan desk closes at 3 pm\"><label for=\"op\">New tokens</label><select id=\"op\" name=\"open\"><option value=\"1\" ${nt.open ? 'selected' : ''}>Accepting tokens</option><option value=\"0\" ${nt.open ? '' : 'selected'}>Paused</option></select><button class=\"btn\" style=\"margin-top:18px\">Save controls</button></form><div class=\"two\">${pwCard()}<form class=\"card\" id=\"stForm\"><h3>Add a staff account</h3>\n" +
        "      <label for=\"su\">Username</label><input id=\"su\" name=\"username\" required><label for=\"sp\">Password (8+ characters)</label><input id=\"sp\" name=\"password\" type=\"password\" minlength=\"8\" autocomplete=\"new-password\" required>\n" +
        "      <button class=\"btn\" style=\"margin-top:18px\">Create staff account</button></form></div>\n" +
        "      <p><a class=\"btn alt\" href=\"/api/export\">Download all tokens (CSV)</a></p>`;\n" +
        "    bindPw();\n" +
        "    document.getElementById('ctlForm').onsubmit = safe(async e => { e.preventDefault(); await api('admin-settings', Object.fromEntries(new FormData(e.target))); toast('Controls saved.'); });\n" +
        "    document.getElementById('stForm').onsubmit = safe(async e => { e.preventDefault(); await api('add-staff', Object.fromEntries(new FormData(e.target))); e.target.reset(); toast('Staff account created.'); });\n" +
        "  } else if (!document.getElementById('hq')) {\n" +
        "    el.innerHTML = `<h2 style=\"margin:32px 0 16px\">Token history</h2><div class=\"bar\"><input id=\"hq\" placeholder=\"Search token, name or phone\" style=\"max-width:340px\"></div><div id=\"hres\"></div>`;\n" +
        "    let t; document.getElementById('hq').oninput = () => { clearTimeout(t); t = setTimeout(loadHistory, 250); };\n" +
        "    loadHistory();\n" +
        "  }\n" +
        "});\n" +
        "\n" +
        "const loadHistory = safe(async () => {\n" +
        "  const r = await api('history?q=' + encodeURIComponent(document.getElementById('hq').value));\n" +
        "  document.getElementById('hres').innerHTML = `<div class=\"tblwrap\"><table><tr><th>Token</th><th>Customer</th><th>Phone</th><th>Service</th><th>Queue</th><th>Status</th><th>Est. wait</th><th>Taken</th></tr>${\n" +
        "    r.length ? r.map(t => `<tr><td><b>${esc(t.token)}</b></td><td>${esc(t.customer)}</td><td>${esc(t.phone)}</td><td>${esc(t.service)}</td><td>${esc(t.priority)}</td><td>${badge(t.status)}</td><td>${t.wait} min</td><td>${when(t.created)}</td></tr>`).join('')\n" +
        "      : '<tr><td colspan=\"8\" class=\"empty\">No tokens match.</td></tr>'}</table></div>`;\n" +
        "});\n" +
        "\n" +
        "// ---------------------------------------------------------------- public live board\n" +
        "function board() {\n" +
        "  document.body.className = 'board';\n" +
        "  app.innerHTML = `<div class=\"wrap\"><div class=\"row\" style=\"padding-top:20px\"><a class=\"brand\" href=\"#\">SmartBank</a><span class=\"grow\"></span>\n" +
        "    <button class=\"btn ghost sm\" data-act=\"sound\">Sound off</button></div><h1>Now calling</h1><div id=\"nb\"></div><div class=\"calls\" id=\"calls\"></div><div class=\"queue-sum\" id=\"sum\"></div></div>`;\n" +
        "  poll(safe(async () => {\n" +
        "    const d = await api('display'), el = document.getElementById('calls');\n" +
        "    if (!el) return;\n" +
        "    document.getElementById('nb').innerHTML = banner(d);\n" +
        "    el.innerHTML = d.calling.length ? d.calling.map(c => `<div><div class=\"n ${c.status === 'CALLED' ? 'hot' : ''}\">${esc(c.token)}</div><small>${esc(c.counter)}${c.status === 'SERVING' ? ' - serving' : ''}</small></div>`).join('')\n" +
        "      : '<div><small>No tokens being called.</small></div>';\n" +
        "    document.getElementById('sum').innerHTML = d.waiting.map(w => `<span><b>${w.n}</b> waiting for ${esc(w.service)}</span>`).join('') || '<span>No one waiting.</span>';\n" +
        "    const first = d.calling.find(c => c.status === 'CALLED'), id = first ? first.token + first.counter : '';\n" +
        "    if (sound && id && id !== lastCalled) speechSynthesis.speak(new SpeechSynthesisUtterance(`Token ${first.token.split('').join(' ')}, please go to ${first.counter}`));\n" +
        "    lastCalled = id || lastCalled;\n" +
        "  }), 3000);\n" +
        "}\n" +
        "\n" +
        "// ---------------------------------------------------------------- click actions\n" +
        "const acts = {\n" +
        "  logout: safe(async () => { await api('logout', {}); me = { role: null }; selected = null; location.hash = ''; route(); }),\n" +
        "  tab: b => { staffTab = b.dataset.tab; staff(); },\n" +
        "  pick: b => { selected = b.dataset.id; renderStaff(); },\n" +
        "  call: safe(async () => {\n" +
        "    const r = await api('call', { counterId: counterPick });\n" +
        "    toast(`Calling ${r.token}`); renderStaff();\n" +
        "  }),\n" +
        "  status: safe(async b => {\n" +
        "    if (!selected) throw new Error('Select a token in the table first.');\n" +
        "    await api('status', { id: selected, status: b.dataset.s });\n" +
        "    if (b.dataset.s !== 'SERVING') selected = null;\n" +
        "    renderStaff();\n" +
        "  }),\n" +
        "  counter: safe(async b => { await api('counter', { id: b.dataset.id, status: b.dataset.s }); renderStaff(); }),\n" +
        "  rate: safe(async b => { await api('rate', { id: b.dataset.id, rating: b.dataset.r }); toast('Thanks for your feedback.'); loadMine(); }),\n" +
        "  filter: b => { qf = b.dataset.s; renderStaff(); },\n" +
        "  cancel: safe(async b => { await api('cancel', { id: b.dataset.id }); toast('Token cancelled.'); loadMine(); }),\n" +
        "  sound: b => { sound = !sound; b.textContent = sound ? 'Sound on' : 'Sound off'; if (sound) speechSynthesis.speak(new SpeechSynthesisUtterance('Sound on')); },\n" +
        "};\n" +
        "document.addEventListener('click', e => {\n" +
        "  const b = e.target.closest('[data-act]');\n" +
        "  if (b && acts[b.dataset.act]) acts[b.dataset.act](b);\n" +
        "});\n" +
        "\n" +
        "boot();\n" +
        "";

}