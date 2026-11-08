package com.fbztec.hush.dto;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// null is valid (= no passphrase); otherwise it must fit bcrypt and be typable in a password field
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = BcryptPassphrase.Validator.class)
public @interface BcryptPassphrase {
    String message() default "must be at most 72 bytes, without line breaks";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<BcryptPassphrase, String> {
        @Override
        public boolean isValid(String passphrase, ConstraintValidatorContext context) {
            // a password input drops CR/LF: such a passphrase could never be typed back
            return passphrase == null || (CreateSecretRequest.fitsBcrypt(passphrase)
                    && passphrase.indexOf('\n') < 0 && passphrase.indexOf('\r') < 0);
        }
    }
}
