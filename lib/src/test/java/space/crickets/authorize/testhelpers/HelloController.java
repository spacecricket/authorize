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
    @GetMapping("/{name}")
    public String getGreetingByName_checkNoScope(
            @PathVariable String name,
            @RequestHeader @Jwt String ignoredAuthorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName_checkScopes(
            @PathVariable String name,
            @RequestHeader @Jwt String ignoredAuthorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName_matchNameAndAge(
            @PathVariable @MatchClaim("full-name") String name,
            @RequestHeader @MatchClaim("age") Integer ignoredAge,
            @RequestHeader @Jwt String ignoredAuthorization
    ) {
        // do something
        return "Hello " + name;
    }

    @Authorize(scopes = {"greeting.read", "greeting.write"})
    @GetMapping("/{name}")
    public String getGreetingByName_bindAndCheckAge(
            @PathVariable @MatchClaim("full-name") String name,
            @BindClaim("age") Integer age,
            @RequestHeader @Jwt String ignoredAuthorization
    ) {
        assert age != null; // The @BindClaim should overwrite whatever is passed in.

        if (age < 13) {
            throw new ForbiddenException("User is only " + age + "!");
        }

        // do something
        return "Hello " + name;
    }
}
