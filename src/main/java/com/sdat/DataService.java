package com.sdat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sdat.Common.GeneralFunctions;
import com.sdat.Common.JWT;
import com.sdat.Master.UserService;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;

@Service
public class DataService {

	@Autowired
	private JWT jwt;

	@Autowired
	private GeneralFunctions gn;

	@Autowired
	private UserService user;

	public ResponseEntity<Object> processRequest(Map<String, Object> requestBody) throws Exception {
		Map<String, Object> payload = null;
		try {
			System.out.println("requestBody :" + requestBody.keySet());
			// Validate the token and get the payload
			payload = jwt.validateToken(getAuthorizationHeader());
			System.out.println("payload :" + payload);
			// Create a map of predicates and corresponding actions
			Map<Predicate<Map<String, Object>>, Supplier<ResponseEntity<Object>>> actionMap = createActionMap(payload,
					requestBody);

			// Iterate over the map and execute the action associated with the first true
			// predicate
			for (Map.Entry<Predicate<Map<String, Object>>, Supplier<ResponseEntity<Object>>> entry : actionMap
					.entrySet()) {
				if (entry.getKey().test(payload)) {
					return entry.getValue().get();
				}
			}

			// If no predicate matches, return Unauthorized
			return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
		} catch (Exception e) {
			Set<String> keySet = requestBody.keySet();

			// Convert the key set to a list
			List<String> keys = new ArrayList<>(keySet);

			// Check if the list of keys is not empty
			if (!keys.isEmpty()) {
				// Get the first key
				String firstKey = keys.get(0);
				switch (firstKey) {
					case "generateSecretKey":
						String secretKey = gn.generateSecretKey();
						ObjectNode secret = new ObjectMapper().createObjectNode();
						secret.put("key", secretKey);
						Map<String, Object> newPayload = payload != null ? payload : Map.of();
						newPayload.put("secret_key", secretKey);
						String newToken = jwt.generateToken(newPayload);
						HttpHeaders headers = new HttpHeaders();
						headers.add("X-TOKEN", newToken);
						return new ResponseEntity<>(secret.get("key"), HttpStatus.OK);

					case "login":
						Map<String, Object> retObj = null;
						retObj = user.login(requestBody, payload);
						return new ResponseEntity<>(retObj, HttpStatus.OK);
					default:
						break;
				}
			}
			// Handle exceptions
			System.out.println(e);
			return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	// Helper method to extract authorization header from the request
	private String getAuthorizationHeader() {
		// Get the current HTTP request attributes using RequestContextHolder
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder
				.getRequestAttributes();
		if (requestAttributes != null) {
			// Get the HttpServletRequest object from the request attributes
			HttpServletRequest request = requestAttributes.getRequest();
			// Get the Authorization header from the request
			return request.getHeader("Authorization");
		}
		return null;
	}

	private Map<Predicate<Map<String, Object>>, Supplier<ResponseEntity<Object>>> createActionMap(
			Map<String, Object> payload, Map<String, Object> requestBody) {
		Map<Predicate<Map<String, Object>>, Supplier<ResponseEntity<Object>>> actionMap = new LinkedHashMap<>();

		// Add predicates and corresponding actions to the map
		actionMap.put(
				// Predicate for validating the payload and request body
				(p) -> p.containsKey("id") && (int) p.get("id") > 0 &&
						!(requestBody.containsKey("logout")
								&& Boolean.parseBoolean(requestBody.get("logout").toString())),

				// Supplier for the action associated with the predicate
				() -> {
					try {
						// Handle action: Generate new token
						if (!payload.containsKey("user_type")) {
							throw new Exception("Authentication data tampered.");
						}
						String newToken = jwt.generateToken(payload);
						HttpHeaders headers = new HttpHeaders();
						headers.add("X-TOKEN", newToken);
						return new ResponseEntity<>(headers, HttpStatus.OK);
					} catch (Exception e) {
						// Handle exceptions
						return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
					}
				});

		actionMap.put(
				// Predicate for checking if generateSecretKey is present in the request body
				(p) -> requestBody.containsKey("generateSecretKey")
						&& Boolean.parseBoolean(requestBody.get("generateSecretKey").toString()),

				// Supplier for the action associated with the predicate
				() -> {
					try {
						// Handle action: Generate secret key
						String secretKey = gn.generateSecretKey();
						Map<String, Object> newPayload = payload != null ? payload : Map.of();
						newPayload.put("secret_key", secretKey);
						String newToken = jwt.generateToken(newPayload);
						HttpHeaders headers = new HttpHeaders();
						headers.add("X-TOKEN", newToken);
						return new ResponseEntity<>(secretKey, HttpStatus.OK);
					} catch (Exception e) {
						// Handle exceptions
						return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
					}
				});

		actionMap.put(
				// Predicate for checking if login is present in the request body
				(p) -> requestBody.containsKey("login") && Boolean.parseBoolean(requestBody.get("login").toString()),

				// Supplier for the action associated with the predicate
				() -> {
					// Handle action: Perform login
					// Assuming request body contains login details
					// Perform login operation and generate response
					Map<String, Object> retObj = null;
					try {
						retObj = user.login(requestBody, payload);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					return new ResponseEntity<>(retObj, HttpStatus.OK);
				});

		return actionMap;
	}
}

// *******************************************************************
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpHeaders;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.stereotype.Service;
// import org.springframework.web.bind.annotation.RequestBody;
// import java.util.Map;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.sdat.Common.GeneralFunctions;
// import com.sdat.Common.JWT;

// @Service
// public class DataService {

// @Autowired
// private JWT jwt;

// @Autowired
// private GeneralFunctions gn;

// public ResponseEntity<Object> processRequest(@RequestBody Map<String, Object>
// requestBody) {
// try {
// Map<String, Object> payload = jwt.validateToken(getAuthorizationHeader());
// switch (true) {
// case (payload.containsKey("id") && (int) payload.get("id") > 0):
// if (!(requestBody.containsKey("logout") &&
// Boolean.parseBoolean(requestBody.get("logout").toString()))) {
// if (!payload.containsKey("user_type")) {
// throw new Exception("Authentication data tampered.");
// }
// String newToken = jwt.generateToken(payload);
// HttpHeaders headers = new HttpHeaders();
// headers.add("X-TOKEN", newToken);
// return new ResponseEntity<>(headers, HttpStatus.OK);
// }
// break;
// default:
// throw new Exception("Authentication data tampered.");
// }
// } catch (Exception e) {
// try {
// switch (true) {
// case (requestBody.containsKey("generateSecretKey") &&
// Boolean.parseBoolean(requestBody.get("generateSecretKey").toString())):
// String secretKey = gn.generateSecretKey();
// Map<String, Object> newPayload = payload != null ? payload : Map.of();
// newPayload.put("secret_key", secretKey);
// String newToken = jwt.generateToken(newPayload);
// HttpHeaders headers = new HttpHeaders();
// headers.add("X-TOKEN", newToken);
// return new ResponseEntity<>(secretKey, headers, HttpStatus.OK);
// case (requestBody.containsKey("login") &&
// Boolean.parseBoolean(requestBody.get("login").toString())):
// // Handle login request
// // Assuming request body contains login details
// // Perform login operation and generate response
// return new ResponseEntity<>(HttpStatus.OK);
// default:
// return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
// }
// } catch (Exception ex) {
// // Handle further exceptions
// return new ResponseEntity<>(ex.getMessage(),
// HttpStatus.INTERNAL_SERVER_ERROR);
// }
// }
// return new ResponseEntity<>(HttpStatus.OK);
// }

// // Helper method to extract authorization header from the request
// private String getAuthorizationHeader() {
// // Logic to extract Authorization header from request, if needed
// return "";
// }
// }

// ************************************************************
// import java.sql.SQLException;
// import java.util.List;
// import java.util.Map;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.autoconfigure.SpringBootApplication;
// import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;

// import com.fasterxml.jackson.databind.JsonNode;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.fasterxml.jackson.databind.node.ObjectNode;
// import com.sdat.Common.gn;
// import com.sdat.Common.JWT;
// import com.sdat.Master.*;
// import com.sdat.Master.Models.Student;

// import jakarta.servlet.http.HttpServletRequest;

// @SpringBootApplication
// @RestController
// @RequestMapping("api/")
// public class DataService {

// @Autowired
// StudentService Student;
// @Autowired
// UserService User;
// @Autowired
// JWT jwt;
// private ObjectNode payload = new ObjectMapper().createObjectNode(); //
// Initialize payload

// @GetMapping("/generateToken")
// public String generateToken() throws SQLException {
// return jwt.generateToken(16);
// }

// @GetMapping("/generateSecretKey")
// public JsonNode generateSecretKey(HttpServletRequest request) throws
// SQLException {
// String secret_key = new GeneralFunctions().generateSecretKey(16);
// payload.put("key", secret_key);
// payload.put("useragent", request.getHeader("User-Agent"));
// payload.put("referer", request.getHeader("Referer"));
// payload.put("url", request.getRequestURI());
// payload.put("ipaddress", new GeneralFunctions().getIPAddress(request));
// // System.out.println(payload.get("key"));
// return payload.get("key");
// }

// @GetMapping("/getIPAddress")
// public JsonNode getIPAddress(HttpServletRequest request) throws SQLException
// {
// String ipaddress = new GeneralFunctions().getIPAddress(request);
// ObjectNode ip = new ObjectMapper().createObjectNode();
// ip.put("ip", ipaddress);
// return ip.get("ip");
// }

// @PostMapping("/login")
// public Map<String, Object> login(@RequestBody Map<String, Object>
// requestData) throws Exception {
// // System.out.println(requestData);
// return User.login(requestData, payload);
// }

// @PostMapping("/getStudents")
// public List<Student> getStudents(@RequestBody Map<String, Object>
// requestData) throws SQLException {
// return Student.getStudents(requestData);
// }

// @PostMapping("/saveStudent")
// public Map<String, Object> saveStudent(@RequestBody Map<String, Object>
// requestData) throws SQLException {
// return Student.saveStudent(requestData);
// }

// @PostMapping("/deleteStudent")
// public Map<String, Object> deleteStudent(@RequestBody Integer requestData)
// throws SQLException {
// return Student.deleteStudent(requestData);
// }

// }
