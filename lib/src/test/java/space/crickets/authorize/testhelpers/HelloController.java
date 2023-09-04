package space.crickets.authorize.testhelpers;

import space.crickets.authorize.Authorize;
import space.crickets.authorize.BindClaim;
import space.crickets.authorize.Jwt;
import space.crickets.authorize.MatchClaim;
import space.crickets.authorize.exceptions.ForbiddenException;
import space.crickets.authorize.testhelpers.fakeannotations.GetMapping;
import space.crickets.authorize.testhelpers.fakeannotations.PathVariable;
import space.crickets.authorize.testhelpers.fakeannotations.RequestHeader;
import space.crickets.authorize.testhelpers.fakeannotations.RequestMapping;
import space.crickets.authorize.testhelpers.fakeannotations.RestController;

@RestController
@RequestMapping("/api/hello")
public class HelloController {
    @Authorize
    @GetMapping("/one/{name}")
    public String getGreetingByName_checkNoScope(
            @PathVariable String name,
            @RequestHeader @Jwt String authorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/one/{name}")
    public String getGreetingByName_checkScopes(
            @PathVariable String name,
            @RequestHeader @Jwt String authorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/two/{name}")
    public String getGreetingByName_checkScopesAndMatchName(
            @PathVariable @MatchClaim("full-name") String name,
            @RequestHeader @Jwt String authorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/three/{name}")
    public String getGreetingByName_checkScopesAndMatchNameAndCheckAge(
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
