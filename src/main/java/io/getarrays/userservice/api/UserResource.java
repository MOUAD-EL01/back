package io.getarrays.userservice.api;
import java.io.*;
import java.nio.file.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.core.Context;
import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.filter.CustomAuthorizationFilter;
import io.getarrays.userservice.service.UserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tomcat.jni.File;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.annotation.Resource;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;

/**
 * @author Get Arrays (https://www.getarrays.io/)
 * @version 1.0
 * @since 7/10/2021
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class UserResource {
//    private static final String[] IMAGE_PNG_VALUE = null;
	private final UserService userService;
    @Value("${spring.mail.host}")
    private String smtpHost;
    @Value("${spring.mail.port}")
    private String port;
    
    @Value("${storage.url}")
    private String s_url;
    public static String generateRandomPassword(int len)
    {
        // ASCII range – alphanumeric (0-9, a-z, A-Z)
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
 
        SecureRandom random = new SecureRandom();
 
        // each iteration of the loop randomly chooses a character from the given
        // ASCII range and appends it to the `StringBuilder` instance
        return IntStream.range(0, len)
                .map(i -> random.nextInt(chars.length()))
                .mapToObj(randomIndex -> String.valueOf(chars.charAt(randomIndex)))
                .collect(Collectors.joining());
    }
    
    
    public void sendEmail(String usname,String UsEmail,String Pass) throws MessagingException,
    UnsupportedEncodingException {
Properties mailProps = new Properties();

mailProps.put("mail.smtp.host", smtpHost);
mailProps.put("mail.smtp.port", port);
mailProps.put("mail.smtp.auth", true);
mailProps.put("mail.smtp.socketFactory.port", port); 
mailProps.put("mail.smtp.socketFactory.fallback", "false");
mailProps.put("mail.smtp.starttls.enable", "true");

Session mailSession = Session.getInstance(mailProps, new Authenticator() {

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication("elattarmouad1@gmail.com", "Kratos01");
    }

});

   MimeMessage message = new MimeMessage(mailSession);
     message.setFrom(new InternetAddress("elattarmouad1@gmail.com"));
     String email =UsEmail ;
     InternetAddress dests = new InternetAddress(email.trim().toLowerCase());
     message.setRecipient(Message.RecipientType.TO, dests);
     message.setSubject("PasswordAndUsername", "UTF-8");
     Multipart mp = new MimeMultipart();
     MimeBodyPart mbp = new MimeBodyPart();
     mbp.setContent("hi your username=>"+"  "+usname+"  "+"and password=>"+"  "+Pass+""+".", "text/html;charset=utf-8");
     mp.addBodyPart(mbp);
     message.setContent(mp);
     message.setSentDate(new java.util.Date());

     Transport.send(message);
}
    @GetMapping("/users")
    public ResponseEntity<List<User>>getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }
    @GetMapping("/user/{username}")
    public ResponseEntity<User>getUser(@PathVariable String username) {
        return ResponseEntity.ok().body(userService.getUser(username));
    }
    @PostMapping("/user/save/{role}")
    public void saveUser( @RequestBody User user,@PathVariable String role) throws MessagingException, IOException {
    	sendEmail(user.getUsername(),user.getEmail(),user.getPassword());
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        user.setPassword(generateRandomPassword( 7));
        sendEmail(user.getUsername(),user.getEmail(),user.getPassword()); 
        userService.saveUser(user);     
        userService.addRoleToUser(user.getUsername(),role);
     
        
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?>addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }
    
    
    @PutMapping("/new_user/{id}")
    public void replaceEmployee(@RequestBody User UpdateUs, @PathVariable Long id){ 
    	
       userService.UpdateUser(id, UpdateUs);
      }
       
    
    

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);
                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            }catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                //response.sendError(FORBIDDEN.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", exception.getMessage());
                response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }
        } else {
            throw new RuntimeException("Refresh token is missing");
        }
    }
    
    
//    @GetMapping("/upload/{id}")
//    	public @ResponseBody String getImageWithMediaType(@PathVariable Long id) throws IOException {
//         	User us=userService.getUserById(id);
//    	//	File file=new File(us.getImagePath());
//    		Path p=Paths.get(us.getImagePath());
//    		return new String(Base64.getEncoder().encode(Files.readAllBytes(p)));
//    		
//    	}
    @GetMapping(path="/upload/{id}",produces={MediaType.IMAGE_JPEG_VALUE})
	public  byte[] getImageWithMediaType(@PathVariable Long id) throws IOException {
     	User us=userService.getUserById(id);
     	log.debug(us.getImagePath());
	//	File file=new File(us.getImagePath());
		Path p=Paths.get(us.getImagePath());
		return Files.readAllBytes(p) ;
	}
    
    
    @DeleteMapping("/delete/{id}")
    public void deleteUser(@PathVariable Long id) 
    {
    	userService.RemoveUser(id);
    }
    @GetMapping("/users_roles/{id}")
    public Collection<Role> getall(@PathVariable Long  id) 
    {
    	User us=userService.getUserById(id);
    	return us.getRoles();
    }
 
    
    
    @PostMapping("/user/saveImage/{id}")
    public void saveUserimage( @PathVariable Long id, @RequestParam("image") MultipartFile multipartFile) throws MessagingException, IOException {
    	 
    	
        String fileName = StringUtils.cleanPath(multipartFile.getOriginalFilename());
       User user=userService.getUserById(id);  
        user.setImage(fileName);
        log.debug(multipartFile.getOriginalFilename()) ;
        String uploadDir = s_url +"/image";
        saveFile(uploadDir, fileName, multipartFile,user);
        userService.updateuserb(id, user);
        log.debug(fileName);
        System.out.println(uploadDir);
    }
   
    public  void saveFile(String uploadDir, String fileName,
            MultipartFile multipartFile,User us) throws IOException {
        Path uploadPath = Paths.get(uploadDir);
         
        if (!Files.exists(uploadPath)) {
        	System.out.println("not found");
            Files.createDirectories(uploadPath);
        }
         
        try (InputStream inputStream = multipartFile.getInputStream()) {
        	String extension = FilenameUtils.getExtension(multipartFile.getOriginalFilename());
            Path filePath = uploadPath.resolve(us.getId()+"."+extension);
            us.setImagePath(filePath.toString());
            Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ioe) {        
            throw new IOException("Could not save image file: " + fileName, ioe);
        } 
       
    }
}

@Data
class RoleToUserForm {
    private String username;
    private String roleName;
}
