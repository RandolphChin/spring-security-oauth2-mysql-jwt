import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Created by v054 on 2019/11/4.
 */
public class BCryptTest {
    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("clientOne"));
        System.out.println(new BCryptPasswordEncoder().encode("clientTwo"));
    }
}
