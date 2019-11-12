package generatePwd;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CryptClientPwd {
    public static void main(String[] args) {
        System.out.println( new BCryptPasswordEncoder().encode("clientOne"));
    }
}
