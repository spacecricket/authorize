package space.crickets.authorize.signing;

import java.time.Duration;
import java.time.Instant;

/**
 * This only exists to be able to mock time concerns in unit tests.
 */
public class RotationClock {

    public static boolean hasBeenLongEnoughSinceLastRotation(Instant rotatedAt) {
        return Duration.between(rotatedAt, Instant.now()).toMinutes() >= 5L;
    }
}
