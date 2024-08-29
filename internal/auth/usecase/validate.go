package usecase

import (
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslations "github.com/go-playground/validator/v10/translations/en"
)

var (
	validate *validator.Validate
	trans    ut.Translator
)

func init() {
	validate = validator.New(validator.WithRequiredStructEnabled())

	english := en.New()
	uni := ut.New(english, english)
	trans, _ = uni.GetTranslator("en")
	if err := enTranslations.RegisterDefaultTranslations(validate, trans); err != nil {
		panic(err)
	}
}

func validatorErrorText(err error) string {
	if err == nil {
		return ""
	}
	validatorErrs := err.(validator.ValidationErrors)
	if len(validatorErrs) == 0 {
		return ""
	}

	sb := strings.Builder{}
	sb.WriteString("Validation input data errors: ")
	sb.WriteString(validatorErrs[0].Translate(trans))
	for _, e := range validatorErrs[1:] {
		sb.WriteString("; ")
		sb.WriteString(e.Translate(trans))
	}

	return sb.String()
}
