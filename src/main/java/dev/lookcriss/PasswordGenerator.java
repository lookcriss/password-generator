package dev.lookcriss;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Class responsible for generating a random password
 * <br/>
 * {@link #generatePassword() the main function} responsible for creating the random password
 *
 * @author lookcriss
 * @since 0.0.1
 */
public class PasswordGenerator {
    @SuppressWarnings(value = { "unused" })
    private static final Logger LOGGER = Logger.getLogger(PasswordGenerator.class.getSimpleName());

    private static final char[] LOWERCASE_CHARACTERS    = new char[] {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    private static final char[] UPPERCASE_CHARACTERS    = new char[] {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
    private static final char[] DIGIT_CHARACTERS        = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    private static final char[] SPECIAL_CHARACTERS      = new char[] {' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'};
    private static final char[][] ALLOWED_CHARACTERS    = new char[][] { PasswordGenerator.LOWERCASE_CHARACTERS, PasswordGenerator.UPPERCASE_CHARACTERS, PasswordGenerator.DIGIT_CHARACTERS, PasswordGenerator.SPECIAL_CHARACTERS};

    private static final int MAX_LENGTH = 8;

    public PasswordGenerator() {}

    /**
     * Generates a random password using {@code SecureRandom} to generate random characters from predefined array of characters.
     * <p>In case the random generated password does not match the model of a modern password:
     * <ul>
     *     <li>a lowercase character</li>
     *     <li>an uppercase character</li>
     *     <li>a digit character</li>
     *     <li>a special character</li>
     * </ul>
     * the password, will go in a new iteration {@link #regeneratePassword(StringBuilder)} to recreate the password having,
     * at least one of character mentioned above!</p>
     * @return A password in {@code String} format
     *
     * @since 0.0.1
     */
    public static String generatePassword() {
        final SecureRandom secureRandom = new SecureRandom();
        final PasswordGenerator passwordGenerator = new PasswordGenerator();

        final StringBuilder passwordBuilder = new StringBuilder();
        for (int i = 0; i < PasswordGenerator.MAX_LENGTH; ++i) {
            final char[] randomSetCharacters = PasswordGenerator.ALLOWED_CHARACTERS[secureRandom.nextInt(PasswordGenerator.ALLOWED_CHARACTERS.length)];
            final char randomCharacter = randomSetCharacters[secureRandom.nextInt(randomSetCharacters.length)];

            passwordBuilder.append(randomCharacter);
        }

        passwordGenerator.regeneratePassword(passwordBuilder);

        return new String(passwordBuilder);
    }

    public final char[] getLowercaseCharacters() {
        return PasswordGenerator.LOWERCASE_CHARACTERS;
    }

    public final char[] getUppercaseCharacters() {
        return PasswordGenerator.UPPERCASE_CHARACTERS;
    }

    public final char[] getDigitCharacters() {
        return PasswordGenerator.DIGIT_CHARACTERS;
    }

    public final char[] getSpecialCharacters() {
        return PasswordGenerator.SPECIAL_CHARACTERS;
    }

    public final char[][] getAllowedCharacters() {
        return PasswordGenerator.ALLOWED_CHARACTERS;
    }

    /**
     * <p>Takes the randomly generated password, and checks the compliance of it!</p>
     * <p>Not having at least one character mentioned in {@link #generatePassword()}, it will recreate it,
     * by assuring the missing character from a set is added, to make it compliant!</p>
     *
     * @param passwordBuilder Password in {@code StringBuilder} format
     *
     * @since 0.0.1
     *
     * @see #maxCharactersOccurrencesIndexes(int[]...)
     * @see #containsCharacter(StringBuilder, char[])
     */
    protected void regeneratePassword(final StringBuilder passwordBuilder) {
        final SecureRandom secureRandom = new SecureRandom();
        final int[] maxOccurrencesCharacterSet = this.maxCharactersOccurrencesIndexes(this.lowercaseCharactersIndexes(passwordBuilder),
                this.uppercaseCharactersIndexes(passwordBuilder), this.digitCharactersIndexes(passwordBuilder), this.specialCharactersIndexes(passwordBuilder));
        final char[] passwordCharacterArray = new String(passwordBuilder).toCharArray();

        if (!containsLowercaseCharacter(passwordBuilder)) {
            passwordCharacterArray[secureRandom.nextInt(maxOccurrencesCharacterSet.length)] = PasswordGenerator.LOWERCASE_CHARACTERS[secureRandom.nextInt(PasswordGenerator.LOWERCASE_CHARACTERS.length)];
            passwordBuilder.replace(0, passwordBuilder.length(), new String(passwordCharacterArray));
            regeneratePassword(passwordBuilder);
        }
        if (!containsUppercaseCharacter(passwordBuilder)) {
            passwordCharacterArray[secureRandom.nextInt(maxOccurrencesCharacterSet.length)] = PasswordGenerator.UPPERCASE_CHARACTERS[secureRandom.nextInt(PasswordGenerator.UPPERCASE_CHARACTERS.length)];
            passwordBuilder.replace(0, passwordBuilder.length(), new String(passwordCharacterArray));
            regeneratePassword(passwordBuilder);
        }
        if (!containsDigitCharacter(passwordBuilder)) {
            passwordCharacterArray[secureRandom.nextInt(maxOccurrencesCharacterSet.length)] = PasswordGenerator.DIGIT_CHARACTERS[secureRandom.nextInt(PasswordGenerator.DIGIT_CHARACTERS.length)];
            passwordBuilder.replace(0, passwordBuilder.length(), new String(passwordCharacterArray));
            regeneratePassword(passwordBuilder);
        }
        if (!containsSpecialCharacter(passwordBuilder)) {
            passwordCharacterArray[secureRandom.nextInt(maxOccurrencesCharacterSet.length)] = PasswordGenerator.SPECIAL_CHARACTERS[secureRandom.nextInt(PasswordGenerator.SPECIAL_CHARACTERS.length)];
            passwordBuilder.replace(0, passwordBuilder.length(), new String(passwordCharacterArray));
            regeneratePassword(passwordBuilder);
        }
    }

    protected boolean containsLowercaseCharacter(final StringBuilder passwordBuilder) {
        return this.containsCharacter(passwordBuilder, PasswordGenerator.LOWERCASE_CHARACTERS);
    }

    protected boolean containsUppercaseCharacter(final StringBuilder passwordBuilder) {
        return this.containsCharacter(passwordBuilder, PasswordGenerator.UPPERCASE_CHARACTERS);
    }

    protected boolean containsDigitCharacter(final StringBuilder passwordBuilder) {
        return this.containsCharacter(passwordBuilder, PasswordGenerator.DIGIT_CHARACTERS);
    }

    protected boolean containsSpecialCharacter(final StringBuilder passwordBuilder) {
        return this.containsCharacter(passwordBuilder, PasswordGenerator.SPECIAL_CHARACTERS);
    }

    protected boolean containsCharacter(final StringBuilder passwordBuilder, final char[] characters) {
        final char[] passwordCharacterArray = new String(passwordBuilder).toCharArray();
        for (final char passwordCharacter : passwordCharacterArray)
            if (Arrays.binarySearch(characters, passwordCharacter) >= 0) return true;
        return false;
    }

    protected int[] lowercaseCharactersIndexes(final StringBuilder passwordBuilder) {
        return this.charactersOccurrencesIndexes(passwordBuilder, PasswordGenerator.LOWERCASE_CHARACTERS);
    }

    protected int[] uppercaseCharactersIndexes(final StringBuilder passwordBuilder) {
        return this.charactersOccurrencesIndexes(passwordBuilder, PasswordGenerator.UPPERCASE_CHARACTERS);
    }

    protected int[] digitCharactersIndexes(final StringBuilder passwordBuilder) {
        return this.charactersOccurrencesIndexes(passwordBuilder, PasswordGenerator.DIGIT_CHARACTERS);
    }

    protected int[] specialCharactersIndexes(final StringBuilder passwordBuilder) {
        return this.charactersOccurrencesIndexes(passwordBuilder, PasswordGenerator.SPECIAL_CHARACTERS);
    }

    protected int[] charactersOccurrencesIndexes(final StringBuilder passwordBuilder, final char[] characters) {
        final char[] passwordCharacterArray = new String(passwordBuilder).toCharArray();
        final int[] tempCharacterIndexes = new int[passwordCharacterArray.length];

        int j = 0;
        for (int i = 0; i < passwordCharacterArray.length; ++i) {
            if (Arrays.binarySearch(characters, passwordCharacterArray[i]) >= 0) { tempCharacterIndexes[j] = i; ++j; }
        }

        final int[] characterIndexes = new int[j];
        System.arraycopy(tempCharacterIndexes, 0, characterIndexes, 0, j);

        return characterIndexes;
    }

    protected int[] maxCharactersOccurrencesIndexes(final int[]...characterIndexes) {
        if (characterIndexes == null) return null;

        int maxLength = -1;
        for (final int[] setIndexes : characterIndexes) maxLength = Math.max(maxLength, setIndexes.length);

        for (final int[] setIndexes : characterIndexes)
            if (maxLength == setIndexes.length)
                return setIndexes;

        return null;
    }
}
