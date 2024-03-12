package com.sdat.Master;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sdat.Common.Encryption;
import com.sdat.Common.GeneralFunctions;
import com.sdat.Common.JWT;

import jakarta.servlet.http.HttpServletRequest;

import org.mindrot.jbcrypt.BCrypt;

@Service
public class UserService {

    @Autowired
    JdbcTemplate jdbc;

    // public Map<String, Object> login(Map<String, Object> request, ObjectNode
    // payload) throws Exception {
    // String mobile_no_email = (String) request.get("mobile_no_email");
    // String pwd = (String) request.get("password");
    // // Check if the payload is null or if the 'key' is missing or empty
    // if (payload == null || !payload.has("key") ||
    // payload.get("secret_key").asText().isEmpty()) {
    // throw new RuntimeException("Secret key is missing or empty in the payload");
    // }
    // // Extract the secret key from the payload
    // String secretKey = payload.get("secret_key").asText();
    // // Instantiate Encryption class
    // // Decrypt the username using the extracted secret key
    // mobile_no_email = Encryption.decrypt(mobile_no_email, secretKey);
    // System.out.println("Decrypted username: " + mobile_no_email);
    // // Execute SQL query to retrieve user information based on the provided
    // username
    // // and pwd
    // String sql = "SELECT *,COALESCE(lockout_on, '1978-02-28'::TIMESTAMPTZ) +
    // INTERVAL '10 MINUTES' > CURRENT_TIMESTAMP AS is_lockedout FROM mas.users
    // WHERE email = ?";
    // List<Map<String, Object>> rows = jdbc.queryForList(sql, mobile_no_email);
    // String message = null;
    // // Check if rows are returned and handle appropriately
    // if (rows != null && !rows.isEmpty()) {
    // // User found, further validation can be performed here
    // Map<String, Object> ret_data = rows.get(0);
    // String psw = ret_data.get("password").toString();
    // // Generate a salt
    // // String salt = BCrypt.gensalt();
    // // Hash the password with the generated salt
    // // String hashedPassword = BCrypt.hashpw(psw, salt);
    // System.out.println(psw);
    // boolean isLockedOut = (boolean) ret_data.get("is_lockedout");
    // if (isLockedOut) {
    // throw new RuntimeException("Lockout");
    // }
    // Integer user_id = (int) ret_data.get("id");
    // if (BCrypt.checkpw(pwd, psw)) {
    // System.out.println("True");
    // Map<String, Object> reg_cuss = getUsers(request ,payload);
    // } else {
    // Integer failure_attempt = (int) ret_data.get("failure_attempt");
    // if (failure_attempt != null && failure_attempt < 4) {
    // String sqlUpdate = "UPDATE mas.users " +
    // "SET failure_attempt = COALESCE(failure_attempt, 0) + 1 " +
    // "WHERE id = ? " +
    // "RETURNING failure_attempt";
    // List<Map<String, Object>> f_rows = jdbc.queryForList(sqlUpdate, user_id);
    // Integer db_failure_attempt = null;
    // if(f_rows != null && f_rows.size() > 0){
    // db_failure_attempt = (int) f_rows.get(0).get("failure_attempt");
    // }
    // String ip_address = payload.get("ipaddress").asText();
    // String user_agent = payload.get("useragent").asText();
    // String referer = (payload.get("referer").asText() != null) ?
    // payload.get("referer").asText() : "";
    // // $process_id = getmypid();
    // String url = payload.get("url").asText();
    // String username = mobile_no_email;
    // System.out.println(db_failure_attempt + " " + ip_address + " " + user_agent +
    // " " + referer + " " + url + " " + username);
    // message = String.format("Mobile No. / eMail ID / Password Invalid. Attempt
    // %d/5.", failure_attempt + 1);
    // } else {
    // String sqlUpdate = "UPDATE mas.users " +
    // "SET failure_attempt = COALESCE(failure_attempt, 0) + 1 " +
    // "WHERE id = ? " +
    // "RETURNING failure_attempt";
    // List<Map<String, Object>> f_rows = jdbc.queryForList(sqlUpdate, user_id);
    // }
    // }
    // } else {
    // throw new RuntimeException("Mobile No. / eMail ID / Password Invalid");
    // }
    // Map<String, Object> retObj = new HashMap<>();
    // retObj.put("rows", rows);
    // retObj.put("message", message);
    // return retObj;
    // }

    public Map<String, Object> login(@RequestBody Map<String, Object> request, Map<String, Object> payload)
            throws Exception {
        Map<String, Object> retObj = new HashMap<>();
        ;
        String message = null;
        try {
            String mobile_no_email = (String) request.get("mobile_no_email");
            String pwd = (String) request.get("pwd");

            if (!payload.containsKey("secret_key")) {
                throw new Exception("Token is not valid / Expired.");
            }
            String secretKey = (String) payload.get("secret_key");

            mobile_no_email = Encryption.decrypt(mobile_no_email, secretKey);
            pwd = Encryption.decrypt(pwd, secretKey);

            String sql = "SELECT *, COALESCE(lockout_on, '1978-02-28'::TIMESTAMPTZ) + INTERVAL '10 MINUTES' > CURRENT_TIMESTAMP AS is_lockedout FROM mas.users WHERE email = ?";
            List<Map<String, Object>> rows = jdbc.queryForList(sql, mobile_no_email);

            if (rows != null && !rows.isEmpty()) {
                Map<String, Object> ret_data = rows.get(0);
                String psw = ret_data.get("password").toString();
                boolean isLockedOut = (boolean) ret_data.get("is_lockedout");
                Integer user_id = (int) ret_data.get("id");

                if (isLockedOut) {
                    throw new RuntimeException("Lockout");
                }
                // Generate a salt
                String salt = BCrypt.gensalt();
                // Hash the password with the generated salt
                String hashedPassword = BCrypt.hashpw(pwd, salt);
                System.out.println(pwd + " " + hashedPassword);
                if (BCrypt.checkpw(pwd, psw)) {
                    System.out.println("Sign in");
                    List<Map<String, Object>> reg_cusList = (List<Map<String, Object>>) getUsers(request, payload)
                            .get("rows");
                    retObj = (reg_cusList != null) ? reg_cusList.get(0) : null;
                    String ip_address = (String) payload.get("ipaddress");
                    String session_token = new GeneralFunctions().generateSecretKey();
                    String sqlUpdate = "UPDATE mas.users " +
                            "SET last_login = CURRENT_TIMESTAMP, " +
                            "session_token = ?, " +
                            "failure_attempt = 0, " +
                            "lockout_on = NULL, " +
                            "ip_address = ? " +
                            "WHERE id = ? RETURNING id";
                    jdbc.queryForList(sqlUpdate, session_token, ip_address, user_id);
                    // String user_agent = payload.get("useragent").asText();
                    // String referer = (payload.get("referer").asText() != null) ?
                    // payload.get("referer").asText() : "";
                    // String url = payload.get("url").asText();
                    // String username = mobile_no_email;
                    payload.put("id", user_id);
                    payload.put("session_token", session_token);
                    message = String.format("User authenticated");
                    String token = new JWT().generateToken(payload);
                    System.out.print(token);
                    retObj.put("message", message);
                    retObj.put("token", token);
                } else {
                    Integer failure_attempt = (int) ret_data.get("failure_attempt");
                    if (failure_attempt != null && failure_attempt < 4) {
                        String sqlUpdate = "UPDATE mas.users " +
                                "SET failure_attempt = COALESCE(failure_attempt, 0) + 1 " +
                                "WHERE id = ? " +
                                "RETURNING failure_attempt";
                        List<Map<String, Object>> f_rows = jdbc.queryForList(sqlUpdate, user_id);
                        Integer db_failure_attempt = null;
                        if (f_rows != null && f_rows.size() > 0) {
                            db_failure_attempt = (int) f_rows.get(0).get("failure_attempt");
                        }

                        message = String.format("Mobile No. / eMail ID / Password Invalid. Attempt %d/5.",
                                failure_attempt + 1);
                        throw new RuntimeException(message);
                    } else {
                        String sqlUpdate = "UPDATE mas.users " +
                                "SET failure_attempt = COALESCE(failure_attempt, 0) + 1 " +
                                "WHERE id = ? " +
                                "RETURNING failure_attempt";
                        List<Map<String, Object>> f_rows = jdbc.queryForList(sqlUpdate, user_id);
                    }
                }
            } else {
                throw new RuntimeException("Mobile No. / eMail ID / Password Invalid");
            }

        } catch (Exception e) {
            retObj.put("message", e.getMessage());
        }
        return retObj;
    }
    // Add other user-related methods here

    public Map<String, Object> getUsers(@RequestBody Map<String, Object> filter, Map<String, Object> payload) {
        Map<String, Object> retObj = new HashMap<>();
        Integer limit = (Integer) filter.getOrDefault("limit", 1);
        Integer offset = ((limit != null) ? limit : 1) * (Integer) filter.getOrDefault("offset", 0);

        System.out.println("get Users");
        String whereClause = "";
        MapSqlParameterSource params = new MapSqlParameterSource();
        String param = " ";
        params.addValue("limit", limit);
        params.addValue("offset", offset);
        param += ", " + limit;
        param += ", " + offset;
        // System.out.println("params: " + params);

        if (filter.containsKey("id") && filter.get("id") != null) {
            Integer id = (Integer) filter.get("id");
            params.addValue("id", id);
            param += ", " + id;
            whereClause += " AND a.id = :id";
        }

        if (filter.containsKey("client_id") && filter.get("client_id") != null) {
            Integer clientId = (Integer) filter.get("client_id");
            params.addValue("client_id", clientId);
            param += ", " + clientId;
            whereClause += " AND a.client_id = :client_id";
        }

        if (filter.containsKey("search_text") && filter.get("search_text") != null) {
            String searchText = "%" + filter.get("search_text") + "%";
            params.addValue("search_text", searchText);
            param += ", " + searchText;
            whereClause += " AND (UPPER(a.name) like UPPER(:search_text) OR UPPER(a.mobile_no) like UPPER(:search_text) OR (a.email IS NOT NULL AND UPPER(a.email) like UPPER(:search_text)))";
        }

        if (!(filter.containsKey("include_inactive") && (Boolean) filter.get("include_inactive"))) {
            whereClause += " AND a.is_active = true";
        }

        try {

            List<Object> paramValues = new ArrayList<>();
            for (Map.Entry<String, Object> entry : params.getValues().entrySet()) {
                String paramName = entry.getKey();
                Object paramValue = entry.getValue();
                paramValues.add(entry.getValue());
                param += ", " + paramValue;
            }
            Object[] paramsArray = paramValues.toArray();
            // Remove the leading comma and space
            param = param.isEmpty() ? "" : param.substring(2);
            // Get total rows
            String countSql = "SELECT COUNT(*) AS cnt, ? AS limit, ? AS offset FROM mas.users AS a WHERE true"
                    + whereClause;
            Map<String, Object> countRow = jdbc.queryForList(countSql, limit, offset).get(0);
            Long totRows = countRow.containsKey("cnt") ? (Long) countRow.get("cnt") : 0;
            retObj.put("tot_rows", totRows);
            // System.out.println(countSql + " " + params);
            // Get actual data

            String sql = "SELECT a.id, a.email, a.mobile_no, a.is_active, a.last_login, (true) AS is_del, a.client_id, a.name, a.designation_code, a.sdo_id, "
                    +
                    "a.district_id, b.is_show_payment, b.is_show_occupancy, b.is_show_licence, b.ref_designation_code "
                    +
                    "FROM mas.users AS a " +
                    "INNER JOIN mas.designations AS b ON (b.code = a.designation_code) " +
                    "WHERE true " + whereClause + " " +
                    "ORDER BY a.mobile_no " +
                    "LIMIT ? OFFSET ?";
            // System.out.println("params: " + paramsArray);
            List<Map<String, Object>> rows = jdbc.queryForList(sql, paramsArray);

            // Encrypt fields and convert types
            for (Map<String, Object> r : rows) {
                String secretKey = (String) payload.get("secret_key");
                if (r.containsKey("id") && r.get("id") != null) {
                    // Encrypt the id field using the secret key
                    String encryptedId = Encryption.encrypt((String) r.get("id").toString(), secretKey);
                    // Replace the original id with the encrypted id
                    r.put("id", encryptedId);
                }
                // Encrypt designation_code field
                if (r.containsKey("designation_code") && r.get("designation_code") != null) {
                    String encryptedDesignationCode = Encryption.encrypt((String) r.get("designation_code"), secretKey);
                    // Replace the original designation_code with the encrypted designation_code
                    r.put("designation_code", encryptedDesignationCode);
                }
                // Convert other fields as needed
                r.put("client_id", r.get("client_id") != null ? (Integer) r.get("client_id") : null);
                r.put("district_id", r.get("district_id") != null ? (Integer) r.get("district_id") : null);
                r.put("sdo_id", r.get("sdo_id") != null ? r.get("sdo_id").toString() : null);
                r.put("is_active", (Boolean) r.get("is_active"));
                r.put("is_del", (Boolean) r.get("is_del"));
                r.put("is_show_payment", (Boolean) r.get("is_show_payment"));
                r.put("is_show_occupancy", (Boolean) r.get("is_show_occupancy"));
                r.put("is_show_licence", (Boolean) r.get("is_show_licence"));
            }
            // System.out.println(rows);
            retObj.put("rows", rows);
        } catch (Exception e) {
            retObj.put("rows", null);
            retObj.put("tot_rows", 0);
            // retObj.put("message", e.getMessage());
            System.out.println(e.getMessage());
        }

        return retObj;
    }

    public void checkUserSessionToken(Map<String, Object> data) throws Exception {

        try {
            if (data.containsKey("id") && data.containsKey("session_token")) {
                Integer id = (Integer) data.get("id");
                Integer sessionToken = (Integer) data.get("sessionToken");

                String sql = "SELECT id, designation_code FROM mas.users WHERE id = ? AND COALESCE(session_token, '') = ?";
                Object[] params = { id, sessionToken };
                Map<String, Object> user = jdbc.queryForMap(sql, params);
                if (user == null) {
                    throw new Exception(
                            "Your current session terminated, since you created a new session with new login.");
                }
            } else {
                throw new Exception("Token is not valid / Expired.");
            }
        } catch (Exception e) {
            throw new Exception("An error occurred while checking the session token.");
        }
    }

}
