package com.aidanwhiteley.books.controller;

import com.aidanwhiteley.books.controller.jwt.JwtUtils;
import com.aidanwhiteley.books.domain.Book;
import com.aidanwhiteley.books.domain.User;
import com.aidanwhiteley.books.util.IntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static com.aidanwhiteley.books.controller.RestApiExceptionHandler.MESSAGE_ILLEGAL_ARGUMENT;
import static com.aidanwhiteley.books.controller.RestApiExceptionHandler.MESSAGE_NOT_FOUND;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@AutoConfigureMockMvc
public class RestApiExceptionHandlerTest extends IntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Test
    public void testExceptionHandlerForResourceNotFound() throws Exception {
        RequestBuilder requestBuilder = getGetRequestBuilder("/api/books/987654321");
        mockMvc.perform(requestBuilder)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code", is(NOT_FOUND.value())))
                .andExpect(jsonPath("$.message", containsString(MESSAGE_NOT_FOUND)));
    }

    @Test
    public void testExceptionHandlerIllegalArguments() throws Exception {
        RequestBuilder requestBuilder = getGetRequestBuilder("/api/books/?rating=wibble");
        mockMvc.perform(requestBuilder)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code", is(BAD_REQUEST.value())))
                .andExpect(jsonPath("$.message", containsString(MESSAGE_ILLEGAL_ARGUMENT)));
    }

    @Test
    public void testExceptionHandlerForNoPermissions() throws Exception {
        Book book = new Book();
        RequestBuilder requestBuilder = getPostRequestBuilder("/secure/api/books", book);
        mockMvc.perform(requestBuilder)
                .andExpect(status().isForbidden());
    }
//
//    @Test
//    public void testExceptionHandlerForRejectingHtml() throws Exception {
//
//
//        Book book = BookRepositoryTest.createTestBook();
//        //book.setTitle("<b>Html is not allowed</b>");
//        RequestBuilder requestBuilder = getPostRequestBuilder("/secure/api/books", book);
//
//        mockMvc.perform(requestBuilder)
//                .andExpect(status().isUnsupportedMediaType());
//    }

    private RequestBuilder getGetRequestBuilder(String url) {
        return MockMvcRequestBuilders
                .get(url)
                .accept(MediaType.APPLICATION_JSON);
    }

    @SuppressWarnings("SameParameterValue")
    private RequestBuilder getPostRequestBuilder(String url, Book book) {
        User user = BookControllerTestUtils.getTestUser();
        String token = jwtUtils.createTokenForUser(user);
        String xsrfToken = BookControllerTestUtils.getXsrfToken(testRestTemplate);

        HttpEntity<Book> entity = BookControllerTestUtils.getBookHttpEntity(book, token, xsrfToken);

        return MockMvcRequestBuilders
                .post(url)
                .content("{\"title\":\"The Travelling Hornplayer\",\"foundOnGoogle\":true,\"googleBookId\":\"pbFgLK91crUC\",\"author\":\"xzczx\",\"genre\":\"zcxzx\",\"summary\":\"xzcxzczxc\",\"rating\":4,\"createdDateTime\":\"2018-08-12T17:28:25.435Z\"}")
                .headers(entity.getHeaders())
                .accept(MediaType.APPLICATION_JSON);
    }

}
