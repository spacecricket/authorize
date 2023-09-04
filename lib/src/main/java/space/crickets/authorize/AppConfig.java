package space.crickets.authorize;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import space.crickets.authorize.internals.AuthorizeAnnotationAdvice;
import space.crickets.authorize.internals.ClaimsParser;

@Configuration
@EnableAspectJAutoProxy // Needed to get @Authorize and our other annotations to work
@Import({
        AuthorizeAnnotationAdvice.class,
        ClaimsParser.class
})
public class AppConfig {
}
