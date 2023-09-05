package space.crickets.authorize;

import io.jsonwebtoken.JwtParser;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import space.crickets.authorize.aop.AuthorizeAdvice;

@Configuration
@EnableAspectJAutoProxy // Needed to get @Authorize and our other annotations to work
@Import({
        AuthorizeAdvice.class,
        JwtParser.class
})
public class AppConfig {
}
