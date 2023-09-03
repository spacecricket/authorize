# authorize
A Java library that provides intuitive annotation-based authorization capabilities to 
Spring Boot controller methods.

Your controller methods look like this:

```java
@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @GetMapping("/{name}")
    public String getGreetingByName(@PathVariable String name) {
        // do something
        return "Hello " + name;
    }
}
```
But you want to secure your endpoints with Oauth2. A popular way to do this is to have the caller provide a token by a header param called "Authorization".
```
curl -H 'Authorization: Bearer <JWT>' https://yourdomain.com/api/hello/Jatin
```
And on the server side, consider this approach: https://developer.okta.com/blog/2019/06/20/spring-preauthorize

That Okta library will allow you to secure your endpoints via code like:
```java
@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @PreAuthorize("hasAuthority('greeting.read')")
    @GetMapping("/{name}")
    public String getGreetingByName(@PathVariable String name) {
        // do something
        return "Hello " + name;
    }
}
```
So if the JWT doesn't list the `greeting.read` scope, the caller will receive a `403 - Forbidden` response.

I like the approach of putting the authorization concern right by the controller method being secured.
If finer control is needed per endpoint, this approach is much nicer than the standard Spring boot approach of using 
`HttpSecurity` in the `SecurityConfig` class (see that Okta blog post linked above).

But what if we want even more fine-grained authorization capabilities to guard our endpoints? 
That's what this library provides.

## More fine-grained annotation-based authorization

### Example 1 - Simple scope-based authorization guard
Allow the GET if the JWT has either the `greeting.read` or `greeting.write` scope. 
```java
@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName(
            @PathVariable String name, 
            @RequestHeader @Jwt String authorization
    ) {
        // do something
        return "Hello " + name;
    }
}
```

### Example 2 - Simple validation of claims
Allow the GET if the JWT has either the `greeting.read` or `greeting.write` scope.
But also require the JWT's claim `name` to match the path param `name`.
I.e. the service will only say hello to you if you are ${name}!
```java
@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName(
            @PathVariable @MatchClaim("full-name") String name,
            @RequestHeader @Jwt String authorization
    ) {
        // do something
        return "Hello " + name;
    }
}
```

### Example 3 - Custom claim validation
Allow the GET if the JWT has either the `greeting.read` or `greeting.write` scope.
But also require the JWT's claim `name` to match the path param `name`.
Also, check that you're above 13 years old!
I.e. the service will only say hello to you if you are ${name} and >13 years old!
```java
@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName(
            @PathVariable @MatchClaim("full-name") String name,
            @BindClaim("user_age") Integer age,
            @RequestHeader @Jwt String authorization
    ) {
        if (age < 13) {
            throw new ForbiddenException("User is only " + age + "!");
        }

        // do something
        return "Hello " + name;
    }
}
```

# Callouts
* This library needs to make outbound HTTP calls to the oauth provider to get updated public keys. There are concurrency concerns here.
* Spring AOP is used to get these new annotations to work.
* Probably the most important one - this is a hobby project!

# Setup
... TODO