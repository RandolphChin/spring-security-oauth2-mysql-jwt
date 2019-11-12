package cn.randy.controller;

import lombok.extern.slf4j.Slf4j;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;

@Controller
@Slf4j
public class CallBackClientOne {

    @RequestMapping("/clientOne/redirect")
    public String getToken(@RequestParam String code){
        log.info("receive code from authorization server code => {} ",code);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", encodeClient());
        MultiValueMap<String, String> params= new LinkedMultiValueMap<>();
        params.add("grant_type","authorization_code");
        params.add("code",code);
        params.add("client_id","clientOne");
        params.add("client_secret","clientOne");
        params.add("redirect_uri","http://localhost:8081/clientOne/redirect");
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = new RestTemplate().exchange("http://localhost:8000/oauth/token", HttpMethod.POST, requestEntity, String.class);
        String token = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        String access_token="";
        try{
        Map map = objectMapper.readValue(token, Map.class);
        access_token = map.get("access_token").toString();
        log.info("receive code from authorization server token => {} ",token);
            log.info("access_token is => {} " +access_token);

    } catch (IOException e) {
        e.printStackTrace();
    }
        return token;
    }

    private String encodeClient() {
        return "Basic " + Base64.getEncoder().encodeToString("clientOne:clientOne".getBytes());
    }

}
