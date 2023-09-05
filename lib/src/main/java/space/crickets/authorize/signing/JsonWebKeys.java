package space.crickets.authorize.signing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public record JsonWebKeys (List<JsonWebKey> keys) {
    public JsonWebKeys() {
        this(new ArrayList<>());
    }

    public JsonWebKeys(JsonWebKey... keys) {
        this(Arrays.asList(keys));
    }
}
