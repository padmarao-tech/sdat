package com.sdat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sdat.Common.Encryption;
import com.sdat.Common.GeneralFunctions;
import com.sdat.Common.JWT;
import com.sdat.Master.UserService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest; // Importing HttpServletRequest

@RestController
@RequestMapping("api/")
public class DataController {

    @Autowired
    private JWT jwt;

    @Autowired
    private UserService user;

    @Autowired
    private GeneralFunctions gn;

    @PostMapping("/dataService")
    public ResponseEntity<Object> process(@RequestBody Map<String, Object> requestBody, HttpServletRequest request)
            throws Exception {
        Map<String, Object> payload = null;
        Set<String> keySet = requestBody.keySet();
        // Convert the key set to a list
        List<String> keys = new ArrayList<>(keySet);
        String newToken = null;
        // Check if the list of keys is not empty
        if (!keys.isEmpty()) {
            // Get the first key
            String firstKey = keys.get(0);
            try {
                System.out.println("requestBody :" + requestBody.keySet());
                // Validate the token and get the payload
                // System.out.println("request :" + request);
                payload = jwt.validateToken(request.getHeader("Authorization"));
                System.out.println("payload :" + payload);

                if (payload.containsKey("id") && (int) payload.get("id") > 0) {
                    // Check if the 'logout' query parameter is present and true
                    if (firstKey != "logout") {
                        // TODO: Check if user is already logged in
                        // If necessary, access payload values using payload.get("key")
                        // For example: String userType = (String) payload.get("user_type");

                        // Generate a new token
                        newToken = jwt.generateToken(payload);
                        user.checkUserSessionToken(payload);
                        // Set the new token in the response header
                    }
                } else {
                    // Throw an exception if 'id' claim is missing or invalid
                    throw new RuntimeException("Authentication data tampered.");
                }
                return AfterLoginFunctions(firstKey, requestBody, payload, newToken);
            } catch (Exception e) {
                HttpHeaders headers = new HttpHeaders();
                switch (firstKey) {
                    case "generateSecretKey":
                        String secretKey = gn.generateSecretKey();
                        ObjectNode secret = new ObjectMapper().createObjectNode();
                        secret.put("secret_key", secretKey);

                        // Create a new payload map including the existing claims from the previous
                        // token, if any
                        Map<String, Object> newPayload = payload != null ? new HashMap<>(payload) : new HashMap<>();
                        newPayload.put("secret_key", secretKey);

                        // Generate a new token with the updated payload
                        newToken = jwt.generateToken(newPayload);

                        headers.add("X-TOKEN", newToken);
                        return new ResponseEntity<>(secret.get("secret_key"), headers, HttpStatus.OK);
                    case "login":
                        Map<String, Object> retObj = null;
                        // System.out.println("payload: "+payload);

                        retObj = user.login(requestBody, payload);
                        if (retObj != null && retObj.containsKey("id")) {
                            String id = Encryption.decrypt((String) retObj.get("id"),
                                    (String) payload.get("secret_key"));
                            payload.put("id", Integer.parseInt(id));
                            newToken = jwt.generateToken(payload);
                            headers.add("X-TOKEN", newToken);
                        }

                        return new ResponseEntity<>(retObj, headers, HttpStatus.OK);

                    default:
                        System.out.println(e);
                        return new ResponseEntity<>(" 401 Unauthorized" ,HttpStatus.UNAUTHORIZED);
                }

            }
        }
        return null;
    }

    public ResponseEntity<Object> AfterLoginFunctions(String firstKey, @RequestBody Map<String, Object> requestBody,
            Map<String, Object> payload, String token) throws Exception {
        switch (firstKey) {
            case "login":
                Map<String, Object> retObj = null;
                // System.out.println("payload: "+payload);
                if (payload != null) {
                    retObj = user.login(requestBody, payload);
                } else {
                    throw new RuntimeException("Payload is null please check.");
                }
                return new ResponseEntity<>(retObj, HttpStatus.OK);
            default:
                return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
