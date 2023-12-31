package space.crickets.authorize;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.util.Assert;
import space.crickets.authorize.aop.AuthorizeAdvice;
import space.crickets.authorize.signing.AuthorizeSigningKeyResolver;

@Configuration
@EnableAspectJAutoProxy // Needed to get @Authorize and our other annotations to work
@Import({
        AuthorizeAdvice.class,
        AuthorizeSigningKeyResolver.class
})
public class AppConfig implements ApplicationContextAware {
    private ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Bean(name = "jwksUrl")
    public String jwksUrl() {
        String jwksUrl = applicationContext.getEnvironment().getProperty("jwks-url");
        Assert.notNull(jwksUrl, "Environment property 'jwks-url' was not provided.");
        return jwksUrl;
    }

    @Bean
    public JwtParser jwtParser(AuthorizeSigningKeyResolver authorizeSigningKeyResolver) {
        return Jwts.parserBuilder()
                .setSigningKeyResolver(authorizeSigningKeyResolver)
                .build();
    }
}
