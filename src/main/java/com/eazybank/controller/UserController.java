package com.eazybank.controller;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.eazybank.dto.LoginRequestDTO;
import com.eazybank.dto.LoginResponseDTO;
import com.eazybank.model.Customer;
import com.eazybank.repository.CustomerRepository;
import com.eazybank.utils.ApplicationConstants;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class UserController {

	private final CustomerRepository customerRepository;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final Environment env;

	@PostMapping("/register")
	public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
		try {
			String hashPwd = passwordEncoder.encode(customer.getPwd());
			customer.setPwd(hashPwd);
			customer.setCreateDt(new Date(System.currentTimeMillis()));
			Customer savedCustomer = customerRepository.save(customer);

			if (savedCustomer.getId() > 0) {
				return ResponseEntity.status(HttpStatus.CREATED).body("Given user details are successfully registered");
			} else {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User registration failed");
			}
		} catch (Exception ex) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("An exception occurred: " + ex.getMessage());
		}
	}

	@GetMapping("/user")
	public Customer getUserDetailsAfterLogin(Authentication authentication) {
		Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
		return optionalCustomer.orElse(null);
	}

	@PostMapping("/apiLogin")
	public ResponseEntity<LoginResponseDTO> apiLogin(@RequestBody LoginRequestDTO login) {
		String jwt = "";
		Authentication auth = UsernamePasswordAuthenticationToken.unauthenticated(login.username(), login.password());
		Authentication authRes = authenticationManager.authenticate(auth);
		if (null != authRes && authRes.isAuthenticated()) {
			if (null != env) {
				String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
						ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
				SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
				jwt = Jwts.builder().issuer("Eazy Bank").subject("Jwt Token").claim("username", auth.getName())
						.claim("authorities",
								authRes.getAuthorities().stream().map(GrantedAuthority::getAuthority)
										.collect(Collectors.joining(",")))
						.issuedAt(new Date()).expiration(new Date(new Date().getTime() + 30000000)).signWith(key)
						.compact();
			}
		}
		return ResponseEntity.status(HttpStatus.OK).header(ApplicationConstants.JWT_HEADER, jwt)
				.body(new LoginResponseDTO(HttpStatus.OK.getReasonPhrase(), jwt));

	}
}
