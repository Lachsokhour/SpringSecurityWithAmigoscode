package com.springsecurity.controller;

import com.springsecurity.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Sokhour"),
            new Student(2,"Soklay"),
            new Student(3,"Chanthei")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Student "+studentId + " does not exists"));
    }
}
