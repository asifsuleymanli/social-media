package com.social.media.controller;

import com.social.media.dto.LoginRequest;
import com.social.media.dto.LoginResponse;
import com.social.media.model.User;
import com.social.media.service.UserService;
import com.social.media.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {
        if (userService.existsByUsername(user.getUsername())) {
            return ResponseEntity.badRequest().body("Bu username artıq mövcuddur.");
        }
        if (userService.existsByEmail(user.getEmail())) {
            return ResponseEntity.badRequest().body("Bu email artıq mövcuddur.");
        }
        if (user.getPassword().length() < 8) {
            return ResponseEntity.badRequest().body("Şifrə minimum 8 simvol olmalıdır.");
        }
        User savedUser = userService.saveUser(user);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest request) {
        Optional<User> userOpt = userService.authenticate(request.getUsername(), request.getPassword());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("İstifadəçi adı və ya şifrə yanlışdır.");
        }
        String token = jwtUtil.generateToken(userOpt.get().getUsername());
        return ResponseEntity.ok(new LoginResponse(token));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");

        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token etibarsızdır");
        }

        String username = jwtUtil.extractUsername(token);

        Optional<User> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("İstifadəçi tapılmadı");
        }

        return ResponseEntity.ok(userOpt.get());
    }
}

