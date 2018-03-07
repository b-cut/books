package com.aidanwhiteley.books.service;

import static com.aidanwhiteley.books.domain.User.AuthenticationProvider.FACEBOOK;
import static com.aidanwhiteley.books.domain.User.AuthenticationProvider.GOOGLE;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;

import com.aidanwhiteley.books.domain.User;
import com.aidanwhiteley.books.repository.UserRepository;
import com.aidanwhiteley.books.util.Oauth2AuthenticationUtils;

@Service
public class UserService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserService.class);

    @Value("${books.users.default.admin.email}")
    private String defaultAdminEmail;

    private final UserRepository userRepository;

    private final Oauth2AuthenticationUtils authUtils;

    @Autowired
    public UserService(UserRepository userRepository, Oauth2AuthenticationUtils oauth2AuthenticationUtils) {
        this.userRepository = userRepository;
        this.authUtils = oauth2AuthenticationUtils;
    }

    public User createOrUpdateUser(OAuth2Authentication authentication) {

        Map<String, Object> userDetails = authUtils.getUserDetails(authentication);
        User.AuthenticationProvider provider = authUtils.getAuthenticationProvider(authentication);
        Optional<User> user = authUtils.getUserIfExists(authentication);
        return user.map(user1 -> updateUser(userDetails, user1, provider)).orElseGet(() -> createUser(userDetails, provider));
    }

    private User createUser(Map<String, Object> userDetails, User.AuthenticationProvider provider) {

        User user;
        LocalDateTime now = LocalDateTime.now();

        switch (provider) {
            case GOOGLE: {
                user = User.builder().authenticationServiceId((String) userDetails.get("id")).
                        firstName((String) userDetails.get("given_name")).
                        lastName((String) userDetails.get("family_name")).
                        fullName((String) userDetails.get("name")).
                        link((String) userDetails.get("link")).
                        picture((String) userDetails.get("picture")).
                        email((String) userDetails.get("email")).
                        lastLogon(now).
                        firstLogon(now).
                        authProvider(GOOGLE).
                        build();

                user = setDefaultAdminUser(user);
                user.addRole(User.Role.ROLE_USER);
                break;
            }
            case FACEBOOK: {

                user = User.builder().authenticationServiceId((String) userDetails.get("id")).
                        firstName((String) userDetails.get("first_name")).
                        lastName((String) userDetails.get("last_name")).
                        fullName((String) userDetails.get("name")).
                        link((String) userDetails.get("link")).
                        email((String) userDetails.get("email")).
                        lastLogon(LocalDateTime.now()).
                        firstLogon(LocalDateTime.now()).
                        authProvider(FACEBOOK).
                        build();
                user = setDefaultAdminUser(user);
                user.addRole(User.Role.ROLE_USER);

                String url = extractFaceBookPictureUrl(userDetails);
                if (url != null) {
                    user.setPicture(url);
                }

                break;
            }
            default: {
                LOGGER.error("Unexpected oauth user type {}", provider);
                throw new IllegalArgumentException("Unexpected oauth type: " + provider);
            }
        }

        userRepository.insert(user);
        LOGGER.info("User created in repository: {}", user);
        return user;
    }

    private User updateUser(Map<String, Object> userDetails, User user, User.AuthenticationProvider provider) {

        switch (provider) {
            case GOOGLE: {
                user.setFirstName((String) userDetails.get("given_name"));
                user.setLastName((String) userDetails.get("family_name"));
                user.setFullName((String) userDetails.get("name"));
                user.setLink((String) userDetails.get("link"));
                user.setPicture((String) userDetails.get("picture"));
                user.setEmail((String) userDetails.get("email"));
                user.setLastLogon(LocalDateTime.now());
                break;
            }
            case FACEBOOK: {
                user.setFirstName((String) userDetails.get("first_name"));
                user.setLastName((String) userDetails.get("last_name"));
                user.setFullName((String) userDetails.get("name"));
                user.setLink((String) userDetails.get("link"));
                String url = extractFaceBookPictureUrl(userDetails);
                if (url != null) {
                    user.setPicture(url);
                }
                user.setEmail((String) userDetails.get("email"));
                user.setLastLogon(LocalDateTime.now());
                break;
            }
            default: {
                LOGGER.error("Unexpected oauth user type {}", provider);
                throw new IllegalArgumentException("Unexpected oauth type: " + provider);
            }
        }

        userRepository.save(user);
        LOGGER.info("User updated in repository: {}", user);
        return user;
    }

    private User setDefaultAdminUser(User user) {
        if (defaultAdminEmail != null && defaultAdminEmail.equals(user.getEmail())) {
            user.addRole(User.Role.ROLE_EDITOR);
            user.addRole(User.Role.ROLE_ADMIN);
        }

        return user;
    }

    private String extractFaceBookPictureUrl(Map<String, Object> userDetails) {
        if (userDetails.get("picture") != null && userDetails.get("picture") instanceof LinkedHashMap) {
            @SuppressWarnings("unchecked")
            LinkedHashMap<String, Object> picture = (LinkedHashMap<String, Object>) userDetails.get("picture");
            if (picture.get("data") != null && picture.get("data") instanceof LinkedHashMap) {
                @SuppressWarnings("unchecked")
                LinkedHashMap<String, Object> data = (LinkedHashMap<String, Object>) picture.get("data");
                return (String) data.get("url");
            }
        }
        return null;
    }
}
