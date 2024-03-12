package com.sdat.Master;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import com.sdat.Master.Models.Student;

@RestController
@Service
public class StudentService {

    @Autowired  
    JdbcTemplate jdbc;

    public List<Student> getStudents(Map<String, Object> requestData) throws SQLException {
        String sql = "SELECT * FROM customer";
        return jdbc.query(sql, (res, rowNum) -> 
            new Student(res.getInt("id"), res.getString("name"), res.getString("email"), res.getInt("age")));
    }

    public Map<String, Object> saveStudent(Map<String, Object> requestData) throws SQLException {
        String name = (String) requestData.get("name");
        int age = (int) requestData.get("age");
        String email = (String) requestData.get("email");
        Integer id = (Integer) requestData.get("id");

        int rowsAffected;
        if (id == null || id == 0) {
            String sql = "INSERT INTO customer (name, age, email) VALUES (?, ?, ?)";
            rowsAffected = jdbc.update(sql, name, age, email);

            // Get the ID of the inserted student
            long generatedId = jdbc.queryForObject("SELECT lastval()", Long.class);

            // Construct the response message
            String message;
            if (rowsAffected > 0) {
                message = "Student saved successfully.";
            } else {
                message = "Failed to insert student.";
            }

            // Prepare the response data
            Map<String, Object> response = new HashMap<>();
            response.put("message", message);
            response.put("id", generatedId);
            return response;
        } else {
            String sql = "UPDATE customer SET name = ?, age =?, email = ? WHERE id = ?";
            rowsAffected = jdbc.update(sql, name, age, email, id);

            // Construct the response message
            String message;
            if (rowsAffected > 0) {
                message = "Student update successfully.";
            } else {
                message = "Failed to update student with ID: " + id + ". Student not found.";
            }

            // Prepare the response data
            Map<String, Object> response = new HashMap<>();
            response.put("message", message);
            response.put("id", id);
            return response;
        }
    }

    public Map<String, Object> deleteStudent(int id) {
        String sql = "DELETE FROM customer WHERE id = ?";
        int rowsAffected = jdbc.update(sql, id);

        // Construct the response message
        String message;
        if (rowsAffected > 0) {
            message = "Student deleted successfully.";
        } else {
            message = "Failed to delete student with ID: " + id + ". Student not found.";
        }

        // Prepare the response data
        Map<String, Object> response = new HashMap<>();
        response.put("message", message);
        return response;
    }

}
